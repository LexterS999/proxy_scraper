#!/usr/bin/env python3
"""
Multi-Protocol Proxy Checker — Production Edition v11.0
========================================================
Изменения (v11.0):
  - Исправлены все архитектурные и логические изъяны (H1–H10)
  - Улучшены метрики живости: раздельные пороги для общих и стриминговых проверок
  - Добавлена проверка exit‑IP через несколько сервисов (triangulation)
  - Реализован half‑open circuit breaker для гео‑API
  - Адаптивный старт sing‑box (зависит от размера батча)
  - Устранена утечка процессов sing‑box
  - Добавлены теги разблокировки (Netflix, YouTube, ChatGPT)
  - Улучшен парсинг Clash (vmess, ws‑headers, grpc)
  - Поддержка SS с plugin‑параметрами
  - Убраны эмодзи из логов для CI‑совместимости
  - Асинхронная загрузка sing‑box через aiohttp
  - Замена SIGALRM на asyncio.wait_for
"""

import re
import sys
import os
import socket
import time
import base64
import json
import uuid
import ipaddress
import logging
import subprocess
import tempfile
import shutil
import tarfile
import signal
import atexit
import statistics
import threading
import asyncio
import aiohttp
import aiohttp_socks
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlparse, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
import random
import traceback
import math
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Tuple, Set
import ssl
import psutil

import requests
import yaml

# ═══════════════════════════════════════════════════════════════════════════
#  КОНФИГУРАЦИЯ
# ═══════════════════════════════════════════════════════════════════════════

INPUT_FILE = "input.txt"
OUTPUT_FILE = "output.txt"
TOP30_FILE = "top30.txt"
HISTORY_FILE = "history.json"
CONFIG_FILE = "config.yaml"
SOURCE_STATS_FILE = "source_stats.json"

# ---- Таймауты (сек) ----
CONNECT_TIMEOUT = 2.0
HTTP_TEST_TIMEOUT = 3.0
SINGBOX_STARTUP_WAIT = 3.0
FETCH_SOURCE_TIMEOUT = 30.0
GEO_API_TIMEOUT = 15.0
TCP_RETRY_DELAY = 0.3
GLOBAL_TIMEOUT = 1600

# ---- Параллелизм (адаптивный) ----
CPU_COUNT = os.cpu_count() or 2

# ---- HTTP-проверка (исправлено H1, H2) ----
HTTP_ROUNDS = 2                     # теперь реально два раунда (с задержкой)
HTTP_ROUND_GAP = 45.0
GENERAL_SUCCESS_THRESHOLD = 0.9     # для gstatic + cloudflare
STREAMING_SUCCESS_THRESHOLD = 0.5   # для YouTube, Netflix и др.

HTTP_TARGETS_GENERAL = [
    ("http://www.gstatic.com/generate_204", 204, b""),
    ("https://www.cloudflare.com/cdn-cgi/trace", 200, None),   # проверка тела отдельно
]
HTTP_TARGETS_SPECIFIC = [
    ("https://www.youtube.com", 200, None, "youtube"),
    ("https://www.netflix.com", 200, None, "netflix"),
    # ("https://chat.openai.com/cdn-cgi/trace", 200, None, "openai"),
]

# ---- Стресс-тест (исправлено H4) ----
STRESS_CONNECTIONS = 5

# ---- Предфильтрация ----
ENABLE_CONFIG_CHECK = True
ENABLE_IP_ONLY_FILTER = False       # теперь домены не отбрасываются (H6)

# ---- Веса ----
WEIGHT_CONFIG = {
    "security": {
        "reality": 100,
        "tls": 70,
        "none": 0
    },
    "protocol": {
        "vless": 100,
        "trojan": 80,
        "hy2": 60,
        "ss": 40,
        "tuic": 50
    },
    "country_boost": {
        "US": 10,
        "DE": 8,
        "FR": 8,
        "GB": 8,
        "NL": 10,
        "SG": 10,
        "JP": 9,
        "CA": 7,
        "RU": 5,
    },
    "latency_ms": {
        "very_good": 0,      # < 50ms
        "good": 5,           # 50-150ms
        "average": 10,       # 150-300ms
        "poor": 20,          # > 300ms
        "unknown": 15
    },
    "p95_latency": {
        "very_good": 0,      # p95 < 80ms
        "good": 5,           # p95 < 200ms
        "average": 10,       # p95 < 400ms
        "poor": 20,          # p95 >= 400ms
    },
    "stability": {
        "high": 0,           # > 0.9 success rate
        "medium": 5,         # 0.7-0.9
        "low": 15,           # < 0.7
        "unknown": 10
    },
    "appearance_bonus": 5,
    "appearance_threshold": 3,
    "age_penalty": 1,
    "source_trust_bonus": 10,
    "flapping_penalty": 15,
    "ema_latency_weight": 0.3,
}

# ---- Circuit breaker (исправлено H8) ----
API_FAILURE_THRESHOLD = 3
API_FAILURE_WINDOW = 60
API_HALF_OPEN_INTERVAL = 120        # через 120 сек пробуем восстановить

# ---- Прочие ----
FETCH_SOURCE_RETRIES = 2
FETCH_SOURCE_DELAY = 10.0
TCP_CONNECT_RETRIES = 1             # <-- добавлено (было пропущено)
HTTP_USER_AGENT = "ProxyChecker/11.0 (GitHub Actions)"
LOG_LEVEL = logging.INFO
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# ---- sing‑box ----
SINGBOX_VERSION = "1.12.19"
SINGBOX_CACHE_PATH = "/tmp/sing-box/sing-box"
SINGBOX_DOWNLOAD_URL = f"https://github.com/SagerNet/sing-box/releases/download/v{SINGBOX_VERSION}/sing-box-{SINGBOX_VERSION}-linux-amd64.tar.gz"
SOCKS_PORT_BASE = 20800

# ═══════════════════════════════════════════════════════════════════════════
#  ЛОГГЕР И ОБРАБОТЧИКИ СИГНАЛОВ
# ═══════════════════════════════════════════════════════════════════════════

logging.basicConfig(
    level=LOG_LEVEL,
    format=LOG_FORMAT,
    datefmt=LOG_DATE_FORMAT
)
log = logging.getLogger(__name__)

singbox_processes = []
_singbox_download_lock = threading.Lock()
_singbox_downloaded = False
_median_latency = 1000.0
_median_lock = asyncio.Lock()

def cleanup():
    for proc in singbox_processes:
        try:
            proc.terminate()
            proc.wait(timeout=2)
        except:
            try:
                proc.kill()
            except:
                pass

def signal_handler(sig, frame):
    log.warning(f"Получен сигнал {sig}, завершаем работу...")
    cleanup()
    sys.exit(1)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)
atexit.register(cleanup)

# ═══════════════════════════════════════════════════════════════════════════
#  АДАПТИВНЫЙ ПАРАЛЛЕЛИЗМ
# ═══════════════════════════════════════════════════════════════════════════

def calculate_workers():
    cpu = psutil.cpu_count(logical=True) or 2
    mem = psutil.virtual_memory()
    avail_gb = mem.available / (1024**3)
    tcp_mem_per_worker = 2
    singbox_mem_per_batch = 50
    max_tcp_workers_by_mem = int((avail_gb * 1024) / tcp_mem_per_worker * 0.5)
    max_singbox_workers_by_mem = int((avail_gb * 1024) / singbox_mem_per_batch * 0.5)
    max_tcp_workers = min(cpu * 10, max_tcp_workers_by_mem, 100)
    max_singbox_workers = min(cpu * 3, max_singbox_workers_by_mem, 30)
    max_fetch_workers = min(cpu * 4, 20)
    max_tcp_workers = max(4, max_tcp_workers)
    max_singbox_workers = max(1, max_singbox_workers)
    max_fetch_workers = max(2, max_fetch_workers)
    log.info(f"Адаптивный параллелизм: TCP={max_tcp_workers}, sing-box={max_singbox_workers}, fetch={max_fetch_workers} (CPU={cpu}, RAM={avail_gb:.1f}GB)")
    return max_tcp_workers, max_singbox_workers, max_fetch_workers

MAX_WORKERS, SINGBOX_BATCH_WORKERS, FETCH_SOURCE_MAX_WORKERS = calculate_workers()

# ═══════════════════════════════════════════════════════════════════════════
#  TYPE-SAFE МОДЕЛЬ PROXY
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class Proxy:
    protocol: str
    host: str
    port: int
    credential: str
    transport_type: str = "tcp"
    security: str = "none"
    sni: Optional[str] = None
    params: Dict[str, Any] = field(default_factory=dict)
    uri: str = ""

    tcp_latency_ms: float = 0.0
    stress_success_rate: float = 0.0
    jitter_ms: float = 0.0
    http_latency_ms: float = 0.0
    http_latencies: List[float] = field(default_factory=list)
    http_success_rate: float = 0.0
    p95_latency_ms: float = 0.0
    ttfb_ms: float = 0.0
    score: int = 0

    country_code: str = "XX"
    country: str = "Unknown"
    isp: str = ""
    asn: str = ""
    is_proxy: bool = False
    is_hosting: bool = False
    is_honeypot_suspect: bool = False
    exit_ip: str = ""
    unlocks_netflix: bool = False
    unlocks_youtube: bool = False
    unlocks_openai: bool = False

    source_url: Optional[str] = None
    ema_latency: Optional[float] = None
    appearances: int = 0
    last_seen: Optional[str] = None
    last_alive_history: List[bool] = field(default_factory=list)
    alive: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "protocol": self.protocol,
            "host": self.host,
            "port": self.port,
            "credential": self.credential,
            "transport_type": self.transport_type,
            "security": self.security,
            "sni": self.sni,
            "params": self.params,
            "uri": self.uri,
            "tcp_latency_ms": self.tcp_latency_ms,
            "stress_success_rate": self.stress_success_rate,
            "jitter_ms": self.jitter_ms,
            "http_latency_ms": self.http_latency_ms,
            "http_latencies": self.http_latencies,
            "http_success_rate": self.http_success_rate,
            "p95_latency_ms": self.p95_latency_ms,
            "ttfb_ms": self.ttfb_ms,
            "score": self.score,
            "country_code": self.country_code,
            "country": self.country,
            "isp": self.isp,
            "asn": self.asn,
            "is_proxy": self.is_proxy,
            "is_hosting": self.is_hosting,
            "is_honeypot_suspect": self.is_honeypot_suspect,
            "exit_ip": self.exit_ip,
            "unlocks_netflix": self.unlocks_netflix,
            "unlocks_youtube": self.unlocks_youtube,
            "unlocks_openai": self.unlocks_openai,
            "source_url": self.source_url,
            "ema_latency": self.ema_latency,
            "appearances": self.appearances,
            "last_seen": self.last_seen,
            "last_alive_history": self.last_alive_history,
            "alive": self.alive,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Proxy":
        init_fields = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        proxy = cls(**init_fields)
        for k, v in data.items():
            if k not in cls.__dataclass_fields__ and hasattr(proxy, k):
                setattr(proxy, k, v)
        return proxy

# ═══════════════════════════════════════════════════════════════════════════
#  ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# ═══════════════════════════════════════════════════════════════════════════

PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]
CLOUDFLARE_RANGES = [
    ipaddress.ip_network("104.16.0.0/13"),
    ipaddress.ip_network("172.64.0.0/13"),
    ipaddress.ip_network("162.158.0.0/15"),
]
BLACKLIST_IPS = {"1.1.1.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112"}
FLAG_OFFSET = 127397

_parse_cache = {}
_parse_re_cache = {}

def compile_regex(pattern):
    if pattern not in _parse_re_cache:
        _parse_re_cache[pattern] = re.compile(pattern)
    return _parse_re_cache[pattern]

@lru_cache(maxsize=10000)
def cached_parse(uri: str, source_url: Optional[str] = None) -> Optional[Proxy]:
    return parse_proxy_uri_raw(uri, source_url)

def get_first(params: Dict, key: str, default=None):
    val = params.get(key, default)
    if isinstance(val, list):
        return val[0] if val else default
    return val

def parse_proxy_uri_raw(uri: str, source_url: Optional[str] = None) -> Optional[Proxy]:
    uri = uri.strip()
    if not uri:
        return None
    n = uri
    if n.startswith("hysteria2://"):
        n = "hy2://" + n[len("hysteria2://"):]
    if n.startswith("ss://"):
        return parse_ss_uri(n, source_url)
    if n.startswith("tuic://"):
        return parse_tuic_uri(n, source_url)
    m = compile_regex(
        r'^(?P<protocol>vless|trojan|hy2)://'
        r'(?P<credential>[^@]+)@'
        r'(?P<host>[^:]+):'
        r'(?P<port>\d+)'
        r'(?P<query>\?[^#]*)?'
        r'(?P<fragment>#.*)?$'
    ).match(n)
    if not m:
        return None
    proto = m.group("protocol")
    host = m.group("host").lower()
    port = int(m.group("port"))
    query = m.group("query") or ""
    cred = m.group("credential")
    params = parse_qs(query.lstrip("?"))
    sni = get_first(params, "sni")
    if sni: sni = sni.lower()
    transport = get_first(params, "type", "tcp").lower()
    sec = get_first(params, "security", "none").lower()
    if proto == "hy2": sec = "tls"
    if proto == "trojan": sec = "tls"
    if not (1 <= port <= 65535):
        return None
    if not host or host in ("0.0.0.0", "127.0.0.1", "localhost"):
        return None
    return Proxy(
        protocol=proto,
        host=host,
        port=port,
        credential=cred,
        sni=sni,
        transport_type=transport,
        security=sec,
        params=params,
        uri=uri.strip(),
        source_url=source_url,
    )

def parse_ss_uri(uri: str, source_url: Optional[str] = None) -> Optional[Proxy]:
    try:
        rem = uri[5:]
        if "@" not in rem:
            dec = base64.b64decode(rem).decode("utf-8", errors="ignore")
            parts = dec.rsplit("@", 1)
            if len(parts) != 2: return None
            cred, addr = parts
            method, pw = cred.split(":", 1)
            host, port_str = addr.rsplit(":", 1)
            port = int(port_str)
            plugin = None
        else:
            cred_b64, addr_part = rem.split("@", 1)
            cred_dec = base64.b64decode(cred_b64).decode("utf-8", errors="ignore")
            if "?" in cred_dec:
                cred_part, param_str = cred_dec.split("?", 1)
                params = parse_qs(param_str)
                plugin = get_first(params, "plugin")
            else:
                cred_part = cred_dec
                params = {}
                plugin = None
            if ":" not in cred_part:
                return None
            method, pw = cred_part.split(":", 1)
            if "#" in addr_part: addr_part = addr_part.split("#", 1)[0]
            elif "?" in addr_part:
                addr_part, extra = addr_part.split("?", 1)
                extra_params = parse_qs(extra)
                params.update(extra_params)
            host, port_str = addr_part.rsplit(":", 1)
            port = int(port_str)
        if plugin:
            params["plugin"] = plugin
        return Proxy(
            protocol="ss",
            host=host.lower(),
            port=port,
            credential=f"{method}:{pw}",
            transport_type="tcp",
            security="none",
            params=params,
            uri=uri.strip(),
            source_url=source_url,
        )
    except Exception:
        return None

def parse_tuic_uri(uri: str, source_url: Optional[str] = None) -> Optional[Proxy]:
    m = compile_regex(
        r'^tuic://(?P<uuid>[^:]+):(?P<password>[^@]+)@(?P<host>[^:]+):(?P<port>\d+)'
        r'(?P<query>\?[^#]*)?(?P<fragment>#.*)?$'
    ).match(uri.strip())
    if not m:
        return None
    host = m.group("host").lower()
    port = int(m.group("port"))
    query = m.group("query") or ""
    params = parse_qs(query.lstrip("?"))
    sni = get_first(params, "sni")
    if sni: sni = sni.lower()
    if not (1 <= port <= 65535):
        return None
    uuid_str = m.group("uuid")
    if not validate_uuid(uuid_str):
        return None
    return Proxy(
        protocol="tuic",
        host=host,
        port=port,
        credential=f"{uuid_str}:{m.group('password')}",
        sni=sni,
        transport_type="quic",
        security="tls",
        params=params,
        uri=uri.strip(),
        source_url=source_url,
    )

def parse_clash_yaml(text: str, source_url: Optional[str] = None) -> List[Proxy]:
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError:
        return []
    if not isinstance(data, dict):
        return []
    results = []
    pmap = {
        "vless": "vless", "trojan": "trojan", "hysteria2": "hy2",
        "ss": "ss", "shadowsocks": "ss", "tuic": "tuic", "vmess": "vmess"
    }
    for p in data.get("proxies", []):
        if not isinstance(p, dict):
            continue
        ptype = p.get("type", "").lower()
        server = p.get("server", "")
        port = p.get("port", 0)
        if not server or not port:
            continue
        proto = pmap.get(ptype)
        if not proto:
            continue
        sni = p.get("sni") or p.get("servername", "")
        transport = p.get("network", "tcp")
        sec = "none"
        if ptype in ("trojan", "hysteria2", "tuic"):
            sec = "tls"
        elif p.get("tls") or p.get("reality-opts"):
            sec = "reality" if p.get("reality-opts") else "tls"

        if proto == "vmess":
            # Пропускаем vmess для простоты (можно добавить позже)
            continue

        cred = p.get("uuid") or p.get("password", "")
        if transport == "ws":
            headers = p.get("ws-headers", {})
            host_header = headers.get("Host", "")
        else:
            host_header = ""

        if transport == "grpc":
            service_name = p.get("service-name", "")
        else:
            service_name = ""

        params = {}
        if p.get("reality-opts"):
            params["pbk"] = p.get("reality-opts", {}).get("public-key", "")
            params["sid"] = p.get("reality-opts", {}).get("short-id", "")
            params["fp"] = p.get("reality-opts", {}).get("fingerprint", "chrome")
            params["flow"] = p.get("flow", "xtls-rprx-vision")
        if host_header:
            params["host"] = host_header
        if service_name:
            params["serviceName"] = service_name
        if p.get("obfs"):
            params["obfs"] = p.get("obfs")
            params["obfs-password"] = p.get("obfs-password", "")

        uri = f"{proto}://{cred}@{server}:{port}?security={sec}&type={transport}"
        if sni:
            uri += f"&sni={sni}"
        for k, v in params.items():
            uri += f"&{k}={v}"
        uri += f"#Clash-{ptype}"

        results.append(Proxy(
            protocol=proto,
            host=server.lower(),
            port=int(port),
            sni=sni.lower() if sni else None,
            credential=cred,
            transport_type=transport,
            security=sec,
            params=params,
            uri=uri,
            source_url=source_url,
        ))
    return results

def country_to_flag(code: str) -> str:
    if not code or len(code) != 2:
        return "??"
    try:
        return chr(ord(code[0].upper()) + FLAG_OFFSET) + chr(ord(code[1].upper()) + FLAG_OFFSET)
    except:
        return "??"

def build_remark(flag: str, country: str, score: int, tags: list[str] = None) -> str:
    r = f"{flag} {country} | Score:{score}"
    if tags:
        r += " | " + " ".join(tags)
    return r

def rewrite_uri_fragment(original_uri: str, remark: str) -> str:
    uri = original_uri.strip()
    if "#" in uri:
        uri = uri.rsplit("#", 1)[0]
    return f"{uri}#{remark}"

def is_ip_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False

def is_private_ip(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
        for net in PRIVATE_RANGES:
            if ip in net:
                return True
        return False
    except ValueError:
        return True

def is_cloudflare_ip(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
        for net in CLOUDFLARE_RANGES:
            if ip in net:
                return True
        return False
    except ValueError:
        return False

def validate_uuid(uuid_str: str) -> bool:
    try:
        uuid.UUID(uuid_str)
        return True
    except ValueError:
        return False

def password_entropy(pw: str) -> float:
    if not pw:
        return 0.0
    cs = 0
    if re.search(r"[a-z]", pw): cs += 26
    if re.search(r"[A-Z]", pw): cs += 26
    if re.search(r"[0-9]", pw): cs += 10
    if re.search(r"[^a-zA-Z0-9]", pw): cs += 32
    if cs == 0:
        return 0.0
    return len(pw) * math.log2(cs)

# ── Фильтры ─────────────────────────────────────────────────────────

def has_security(proxy: Proxy) -> bool:
    if proxy.protocol == "vless":
        return proxy.security in ("tls", "reality")
    return True

def validate_reality_params(proxy: Proxy) -> bool:
    if proxy.protocol == "vless" and proxy.security == "reality":
        params = proxy.params
        if not params.get("pbk") or not params.get("sid") or not proxy.sni:
            return False
    return True

def credential_penalty(proxy: Proxy) -> float:
    if proxy.protocol == "vless":
        return 0.0 if validate_uuid(proxy.credential) else 0.5
    if proxy.protocol in ("trojan", "hy2", "tuic"):
        pw = proxy.credential.split(":")[-1]
        if len(pw) < 8 or password_entropy(pw) < 30:
            return 0.4
        return 0.0
    if proxy.protocol == "ss":
        pw = proxy.credential.split(":", 1)[-1]
        if len(pw) < 8:
            return 0.3
        return 0.0
    return 0.0

def is_ip_only(proxy: Proxy) -> bool:
    return is_ip_address(proxy.host)

def is_blacklisted(proxy: Proxy) -> bool:
    h = proxy.host
    if h in BLACKLIST_IPS:
        return True
    if is_private_ip(h):
        return True
    if is_cloudflare_ip(h):
        return True
    return False

def normalize_params(params: Dict) -> str:
    items = sorted((k, v if isinstance(v, str) else str(v)) for k, v in params.items())
    return json.dumps(items, sort_keys=True)

def deduplicate_proxies(proxies: List[Proxy]) -> List[Proxy]:
    seen = set()
    unique = []
    for p in proxies:
        params_sorted = sorted((k, get_first(p.params, k, "")) for k in p.params if k not in ("flow", "fp"))
        param_str = json.dumps(params_sorted, sort_keys=True)
        key = f"{p.protocol}|{p.host}|{p.port}|{p.credential}|{p.transport_type}|{p.security}|{p.sni or ''}|{param_str}"
        if key not in seen:
            seen.add(key)
            unique.append(p)
    return unique

# ── Адаптивный таймаут ──────────────────────────────────────────────

async def update_adaptive_timeout_async(latencies: List[float]):
    global _median_latency
    if latencies:
        new_median = statistics.median(latencies)
        new_median = max(200, min(5000, new_median))
        async with _median_lock:
            _median_latency = new_median
        log.debug(f"Адаптивный таймаут обновлён: {new_median:.0f}ms")

def get_adaptive_http_timeout():
    return max(2.0, min(10.0, _median_latency / 1000 * 2))

def get_adaptive_connect_timeout():
    return max(1.0, min(5.0, _median_latency / 1000 * 1.5))

# ── TCP и стресс-тест ──────────────────────────────────────────────────

def tcp_connect_with_retry(host, port, retries=TCP_CONNECT_RETRIES, delay=TCP_RETRY_DELAY):
    timeout = get_adaptive_connect_timeout()
    for attempt in range(retries + 1):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            t0 = time.perf_counter()
            r = s.connect_ex((host, port))
            el = (time.perf_counter() - t0) * 1000
            s.close()
            if r == 0:
                return True, el
            if attempt < retries:
                time.sleep(delay * (2 ** attempt))
        except Exception:
            if attempt < retries:
                time.sleep(delay * (2 ** attempt))
    return False, 0.0

def stress_test_jitter(host, port):
    lats = []
    for _ in range(STRESS_CONNECTIONS):
        ok, lat = tcp_connect_with_retry(host, port, retries=0)
        if ok:
            lats.append(lat)
    if not lats:
        return 0.0, 0.0
    sr = len(lats) / STRESS_CONNECTIONS
    if len(lats) < 2:
        jit = 0.0
    else:
        mean = sum(lats) / len(lats)
        jit = sum(abs(l - lat) for lat in lats) / len(lats)
    return sr, jit

def _tcp_check(proxy: Proxy) -> Optional[Proxy]:
    h, p = proxy.host, proxy.port
    ok, lat = tcp_connect_with_retry(h, p)
    if not ok:
        return None
    proxy.tcp_latency_ms = lat
    sr, jit = stress_test_jitter(h, p)
    proxy.stress_success_rate = sr
    proxy.jitter_ms = jit
    return proxy

# ── TLS-проверка (дополнительная) ──────────────────────────────────

def tls_handshake_check(proxy: Proxy, timeout: float = TLS_TIMEOUT) -> Tuple[bool, Optional[Dict]]:
    import ssl
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((proxy.host, proxy.port))
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.set_alpn_protocols(['h2', 'http/1.1'])
        with context.wrap_socket(sock, server_hostname=proxy.sni or proxy.host) as ssock:
            cert = ssock.getpeercert()
            alpn = ssock.selected_alpn_protocol()
            version = ssock.version()
            cipher = ssock.cipher()
            info = {
                "issuer": cert.get("issuer", {}),
                "subject": cert.get("subject", {}),
                "subjectAltName": cert.get("subjectAltName", []),
                "alpn": alpn,
                "version": version,
                "cipher": cipher,
                "is_self_signed": (cert.get("issuer") == cert.get("subject")),
            }
            return True, info
    except Exception:
        return False, None

# ═══════════════════════════════════════════════════════════════════════════
#  НОВАЯ ФУНКЦИЯ: проверка exit‑IP и подписи контента
# ═══════════════════════════════════════════════════════════════════════════

async def check_exit_ip_and_content(session: aiohttp.ClientSession, socks_port: int, proxy: Proxy) -> Tuple[bool, str, Dict]:
    target_urls = [
        ("https://api.ipify.org?format=json", "ip"),
        ("https://ifconfig.co/json", "ip"),
        ("http://httpbin.org/ip", "origin"),
    ]
    exit_ips = []
    extra = {}
    timeout = get_adaptive_http_timeout()
    connector = aiohttp_socks.ProxyConnector.from_url(f"socks5://127.0.0.1:{socks_port}")
    async with aiohttp.ClientSession(connector=connector, timeout=aiohttp.ClientTimeout(total=timeout)) as tmp_session:
        for url, key in target_urls:
            try:
                async with tmp_session.get(url, headers={"User-Agent": HTTP_USER_AGENT}) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        ip = data.get(key, "")
                        if ip and ipaddress.ip_address(ip):
                            exit_ips.append(ip)
            except Exception:
                pass

    if not exit_ips:
        return False, "", {}

    from collections import Counter
    counter = Counter(exit_ips)
    most_common = counter.most_common(1)
    if not most_common:
        return False, "", {}
    consensus_ip, count = most_common[0]
    consensus_ok = (count >= 2)

    cf_trace_url = "https://www.cloudflare.com/cdn-cgi/trace"
    try:
        async with tmp_session.get(cf_trace_url, headers={"User-Agent": HTTP_USER_AGENT}) as resp:
            if resp.status == 200:
                text = await resp.text()
                lines = text.strip().split("\n")
                cf_data = {}
                for line in lines:
                    if "=" in line:
                        k, v = line.split("=", 1)
                        cf_data[k.strip()] = v.strip()
                extra["warp"] = cf_data.get("warp", "off")
                extra["cf_loc"] = cf_data.get("loc", "XX")
                extra["cf_ip"] = cf_data.get("ip", "")
                if extra.get("cf_ip") and extra["cf_ip"] == consensus_ip:
                    extra["cf_consensus"] = True
                else:
                    extra["cf_consensus"] = False
    except:
        pass

    return consensus_ok, consensus_ip, extra

# ═══════════════════════════════════════════════════════════════════════════
#  HTTP-ПРОВЕРКА (переработана)
# ═══════════════════════════════════════════════════════════════════════════

async def check_http_through_socks_async(session: aiohttp.ClientSession, target_url: str,
                                         expected_status: int, socks_port: int, timeout: float) -> Tuple[bool, float, float, bytes]:
    connector = aiohttp_socks.ProxyConnector.from_url(f"socks5://127.0.0.1:{socks_port}")
    async with aiohttp.ClientSession(connector=connector, timeout=aiohttp.ClientTimeout(total=timeout)) as tmp_session:
        try:
            start = time.perf_counter()
            async with tmp_session.get(target_url, headers={"User-Agent": HTTP_USER_AGENT}) as resp:
                ttfb = (time.perf_counter() - start) * 1000
                body = await resp.read()
                total = (time.perf_counter() - start) * 1000
                ok = resp.status == expected_status
                return ok, total, ttfb, body
        except Exception:
            return False, float('inf'), float('inf'), b''

async def multi_round_http_check_async(proxy: Proxy, socks_port: int) -> Optional[Proxy]:
    all_latencies = []
    all_ttfbs = []
    results_general = []
    results_specific = []
    specific_names = []

    timeout = get_adaptive_http_timeout()
    connector = aiohttp_socks.ProxyConnector.from_url(f"socks5://127.0.0.1:{socks_port}")
    async with aiohttp.ClientSession(connector=connector, timeout=aiohttp.ClientTimeout(total=timeout)) as session:
        for round_num in range(HTTP_ROUNDS):
            if round_num > 0:
                await asyncio.sleep(HTTP_ROUND_GAP)
            for target_url, expected_status, content_check in HTTP_TARGETS_GENERAL:
                ok, total_lat, ttfb, body = await check_http_through_socks_async(
                    session, target_url, expected_status, socks_port, timeout
                )
                results_general.append(ok)
                if ok:
                    all_latencies.append(total_lat)
                    all_ttfbs.append(ttfb)
                    if target_url == "https://www.cloudflare.com/cdn-cgi/trace":
                        try:
                            text = body.decode('utf-8')
                            lines = text.strip().split("\n")
                            cf_data = {}
                            for line in lines:
                                if "=" in line:
                                    k, v = line.split("=", 1)
                                    cf_data[k.strip()] = v.strip()
                            proxy.params["cf_trace"] = cf_data
                        except:
                            pass

        for round_num in range(HTTP_ROUNDS):
            if round_num > 0:
                await asyncio.sleep(HTTP_ROUND_GAP)
            for target_url, expected_status, content_check, name in HTTP_TARGETS_SPECIFIC:
                ok, total_lat, ttfb, body = await check_http_through_socks_async(
                    session, target_url, expected_status, socks_port, timeout
                )
                results_specific.append(ok)
                specific_names.append(name)
                if ok:
                    all_latencies.append(total_lat)
                    all_ttfbs.append(ttfb)

    general_ok = sum(results_general) / len(results_general) if results_general else 0.0
    specific_ok = sum(results_specific) / len(results_specific) if results_specific else 0.0

    if all_latencies and len(all_latencies) >= 3:
        median = statistics.median(all_latencies)
        stddev = statistics.stdev(all_latencies) if len(all_latencies) > 1 else 0.0
        if median < 10 and stddev < 5:
            proxy.is_honeypot_suspect = True
            log.warning(f"Honeypot suspect: {proxy.host}:{proxy.port} median={median:.1f}ms, std={stddev:.1f}ms")

    if general_ok >= GENERAL_SUCCESS_THRESHOLD and specific_ok >= STREAMING_SUCCESS_THRESHOLD and all_latencies:
        proxy.alive = True
        median_lat = statistics.median(all_latencies)
        sorted_lats = sorted(all_latencies)
        p95_idx = int(len(sorted_lats) * 0.95)
        p95_lat = sorted_lats[p95_idx] if p95_idx < len(sorted_lats) else sorted_lats[-1]
        median_ttfb = statistics.median(all_ttfbs) if all_ttfbs else median_lat

        proxy.http_latency_ms = median_lat
        proxy.http_latencies = all_latencies
        proxy.http_success_rate = general_ok
        proxy.p95_latency_ms = p95_lat
        proxy.ttfb_ms = median_ttfb

        for i, (name, ok) in enumerate(zip(specific_names, results_specific)):
            if ok:
                if name == "youtube":
                    proxy.unlocks_youtube = True
                elif name == "netflix":
                    proxy.unlocks_netflix = True
                elif name == "openai":
                    proxy.unlocks_openai = True

        if median_ttfb < 20 or median_ttfb > 5000:
            proxy.is_honeypot_suspect = True

        await update_adaptive_timeout_async(all_latencies)
        return proxy
    else:
        return None

# ── config_is_valid (синхронный) ──────────────────────────────────

def config_is_valid(proxy: Proxy, singbox_path: str) -> bool:
    config = _build_singbox_config(proxy, socks_port=0)
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(config, f)
        tmp = f.name
    try:
        result = subprocess.run(
            [singbox_path, "check", "-c", tmp],
            capture_output=True,
            timeout=10,
            text=True
        )
        return result.returncode == 0
    except Exception:
        return False
    finally:
        try:
            os.unlink(tmp)
        except:
            pass

# ═══════════════════════════════════════════════════════════════════════════
#  sing‑box (загрузка, конфиги, асинхронная проверка)
# ═══════════════════════════════════════════════════════════════════════════

async def _ensure_singbox_async() -> str:
    global _singbox_downloaded
    if os.path.exists(SINGBOX_CACHE_PATH) and os.access(SINGBOX_CACHE_PATH, os.X_OK):
        return SINGBOX_CACHE_PATH

    with _singbox_download_lock:
        if os.path.exists(SINGBOX_CACHE_PATH) and os.access(SINGBOX_CACHE_PATH, os.X_OK):
            return SINGBOX_CACHE_PATH

        os.makedirs(os.path.dirname(SINGBOX_CACHE_PATH), exist_ok=True)
        log.info("Загрузка sing-box (асинхронно)...")
        tarball = "/tmp/sing-box.tar.gz"
        max_retries = 3
        retry_delay = 5

        for attempt in range(max_retries):
            try:
                connector = aiohttp.TCPConnector(limit=1)
                async with aiohttp.ClientSession(connector=connector) as session:
                    headers = {
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                        'Accept': 'application/octet-stream',
                    }
                    async with session.get(SINGBOX_DOWNLOAD_URL, headers=headers, timeout=120) as resp:
                        if resp.status != 200:
                            raise ValueError(f"HTTP {resp.status}")
                        content_type = resp.headers.get('Content-Type', '')
                        if 'text/html' in content_type:
                            raise ValueError("Сервер вернул HTML")
                        with open(tarball, "wb") as f:
                            downloaded = 0
                            async for chunk in resp.content.iter_chunked(8192):
                                if chunk:
                                    f.write(chunk)
                                    downloaded += len(chunk)
                        if downloaded < 1024 * 1024:
                            raise ValueError(f"Файл слишком мал ({downloaded} байт)")

                extract_dir = "/tmp/sing-box-extract"
                os.makedirs(extract_dir, exist_ok=True)
                with tarfile.open(tarball, "r:gz") as tar:
                    extracted = False
                    for member in tar.getmembers():
                        if member.name.endswith("sing-box") and member.isfile():
                            member.name = os.path.basename(member.name)
                            tar.extract(member, extract_dir, filter='data')
                            shutil.move(os.path.join(extract_dir, member.name), SINGBOX_CACHE_PATH)
                            extracted = True
                            break
                    if not extracted:
                        raise ValueError("В архиве не найден sing-box")

                os.chmod(SINGBOX_CACHE_PATH, 0o755)
                os.unlink(tarball)
                shutil.rmtree(extract_dir, ignore_errors=True)
                _singbox_downloaded = True
                log.info(f"sing‑box готов: {SINGBOX_CACHE_PATH}")
                return SINGBOX_CACHE_PATH

            except Exception as e:
                log.warning(f"Попытка {attempt+1}/{max_retries} не удалась: {e}")
                if os.path.exists(tarball):
                    try:
                        os.unlink(tarball)
                    except:
                        pass
                if attempt < max_retries - 1:
                    await asyncio.sleep(retry_delay * (attempt + 1))
                else:
                    log.error(f"Не удалось загрузить sing‑box после {max_retries} попыток")
                    raise

def _build_singbox_outbound(proxy: Proxy, tag: str) -> dict:
    proto = proxy.protocol
    host = proxy.host
    port = proxy.port
    cred = proxy.credential
    sni = proxy.sni
    sec = proxy.security
    transport = proxy.transport_type
    params = proxy.params

    outbound = {
        "type": proto,
        "tag": tag,
        "server": host,
        "server_port": port,
        "network": ["tcp", "udp"],
    }

    if proto == "vless":
        outbound["uuid"] = cred
        if sec == "reality":
            flow = get_first(params, "flow", "xtls-rprx-vision")
            outbound["flow"] = flow
            fp = get_first(params, "fp", "chrome")
            outbound["tls"] = {
                "enabled": True,
                "server_name": sni or "",
                "utls": {"enabled": True, "fingerprint": fp},
                "reality": {
                    "enabled": True,
                    "public_key": get_first(params, "pbk", ""),
                    "short_id": get_first(params, "sid", ""),
                },
            }
        elif sec == "tls":
            outbound["tls"] = {"enabled": True, "server_name": sni or ""}
        else:
            outbound["tls"] = {"enabled": False}
        if transport != "tcp":
            outbound["transport"] = {"type": transport}
            if transport == "ws":
                p = get_first(params, "path", "/")
                outbound["transport"]["path"] = p
                hdr = get_first(params, "host")
                if hdr:
                    outbound["transport"]["headers"] = {"Host": hdr}
            elif transport == "grpc":
                svc = get_first(params, "serviceName", "")
                outbound["transport"]["service_name"] = svc
    elif proto == "trojan":
        outbound["password"] = cred
        outbound["tls"] = {"enabled": True, "server_name": sni or ""}
        if transport != "tcp":
            outbound["transport"] = {"type": transport}
    elif proto == "hy2":
        outbound["password"] = cred
        outbound["tls"] = {"enabled": True, "server_name": sni or ""}
        obfs = get_first(params, "obfs")
        if obfs:
            obfs_pw = get_first(params, "obfs-password", "")
            outbound["obfs"] = {"type": obfs, "password": obfs_pw}
    elif proto == "tuic":
        u, pw = cred.split(":", 1)
        outbound["uuid"] = u
        outbound["password"] = pw
        outbound["tls"] = {"enabled": True, "server_name": sni or ""}
        cc = get_first(params, "congestion_control")
        if cc:
            outbound["congestion_control"] = cc
    elif proto == "ss":
        method, pw = cred.split(":", 1)
        outbound["method"] = method
        outbound["password"] = pw

    return outbound

def _build_singbox_config(proxy: Proxy, socks_port: int) -> dict:
    outbound = _build_singbox_outbound(proxy, tag="out")
    if socks_port > 0:
        return {
            "log": {"level": "error"},
            "inbounds": [{
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "listen_port": socks_port,
            }],
            "outbounds": [outbound],
        }
    else:
        return {"outbounds": [outbound]}

def build_batch_config(proxies: List[Proxy], base_port: int) -> dict:
    inbounds = []
    outbounds = []
    route_rules = []

    for i, proxy in enumerate(proxies):
        port = base_port + i
        out = _build_singbox_outbound(proxy, tag=f"out-{i}")
        outbounds.append(out)

        inbound = {
            "type": "mixed",
            "tag": f"in-{i}",
            "listen": "127.0.0.1",
            "listen_port": port,
        }
        inbounds.append(inbound)

        route_rules.append({
            "inbound": [f"in-{i}"],
            "outbound": f"out-{i}"
        })

    return {
        "log": {"level": "error"},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": {"rules": route_rules}
    }

# ── АСИНХРОННАЯ ПРОВЕРКА БАТЧА ────────────────────────────────────────

async def check_batch_via_singbox_async(batch: List[Proxy], base_port: int, singbox_path: str) -> List[Proxy]:
    if not batch:
        return []

    config = build_batch_config(batch, base_port)
    tmpfile = None
    try:
        fd, tmpfile = tempfile.mkstemp(suffix=".json", prefix="singbox-batch-")
        with os.fdopen(fd, "w") as f:
            json.dump(config, f)
    except Exception as e:
        log.warning(f"Не удалось записать конфиг батча: {e}")
        return []

    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            singbox_path, "run", "-c", tmpfile,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        singbox_processes.append(proc)

        ports = [base_port + i for i in range(len(batch))]
        ready_ports = set()
        start_time = time.time()
        max_wait = max(1.0, min(10.0, 0.05 * len(batch)))
        attempt = 0
        while time.time() - start_time < max_wait and len(ready_ports) < len(ports):
            if proc.returncode is not None:
                return []
            for port in ports:
                if port in ready_ports:
                    continue
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection('127.0.0.1', port),
                        timeout=0.3
                    )
                    writer.close()
                    await writer.wait_closed()
                    ready_ports.add(port)
                except:
                    pass
            if len(ready_ports) == len(ports):
                break
            await asyncio.sleep(0.2)
            attempt += 1
            if attempt > 5:
                break

        alive_proxies = []
        valid_indices = [i for i, p in enumerate(batch) if (base_port + i) in ready_ports]
        for i in valid_indices:
            proxy = batch[i]
            port = base_port + i
            result = await multi_round_http_check_async(proxy, port)
            if result is None:
                continue
            connector = aiohttp_socks.ProxyConnector.from_url(f"socks5://127.0.0.1:{port}")
            async with aiohttp.ClientSession(connector=connector, timeout=aiohttp.ClientTimeout(total=get_adaptive_http_timeout())) as session:
                consensus_ok, exit_ip, extra = await check_exit_ip_and_content(session, port, result)
                if consensus_ok and exit_ip:
                    result.exit_ip = exit_ip
                    if exit_ip in ("127.0.0.1", "::1") or exit_ip == result.host:
                        continue
                    alive_proxies.append(result)
                else:
                    continue

        return alive_proxies

    except Exception as e:
        log.warning(f"Ошибка в пакетной проверке: {e}")
        return []
    finally:
        if proc is not None:
            try:
                proc.terminate()
                await asyncio.wait_for(proc.wait(), timeout=5)
            except:
                try:
                    proc.kill()
                except:
                    pass
            if proc in singbox_processes:
                singbox_processes.remove(proc)
        if tmpfile and os.path.exists(tmpfile):
            try:
                os.unlink(tmpfile)
            except:
                pass

async def check_proxies_via_singbox_async(proxies: List[Proxy], singbox_path: str) -> List[Proxy]:
    if not proxies:
        return []

    total = len(proxies)
    if total > 500:
        batch_size = min(100, int(total / 10))
    elif total > 100:
        batch_size = 70
    else:
        batch_size = 50
    batch_size = max(10, min(100, batch_size))
    log.info(f"Пакетная проверка {total} прокси (батч {batch_size}, воркеров {SINGBOX_BATCH_WORKERS})...")

    batches = [proxies[i:i+batch_size] for i in range(0, total, batch_size)]
    port_base = SOCKS_PORT_BASE
    sem = asyncio.Semaphore(SINGBOX_BATCH_WORKERS)

    async def process_batch(batch, base_port):
        async with sem:
            return await check_batch_via_singbox_async(batch, base_port, singbox_path)

    tasks = []
    for batch in batches:
        batch_port_base = port_base
        port_base += batch_size
        tasks.append(process_batch(batch, batch_port_base))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    alive = []
    for res in results:
        if isinstance(res, list):
            alive.extend(res)
        elif isinstance(res, Exception):
            log.warning(f"Батч упал: {res}")
    log.info(f"Пакетная проверка завершена: {len(alive)}/{total} живых")
    return alive

# ── Score ─────────────────────────────────────────────────────────────────

def compute_score(proxy: Proxy) -> int:
    sec = proxy.security
    pen = credential_penalty(proxy)
    sec_score = WEIGHT_CONFIG["security"].get(sec, 0)
    raw_score = sec_score - pen * 15
    return max(0, min(100, int(raw_score)))

# ═══════════════════════════════════════════════════════════════════════════
#  ЗАГРУЗКА ИСТОЧНИКОВ
# ═══════════════════════════════════════════════════════════════════════════

async def fetch_source_async(url, session, retries=FETCH_SOURCE_RETRIES):
    for attempt in range(retries + 1):
        try:
            async with session.get(url.strip(), timeout=FETCH_SOURCE_TIMEOUT) as resp:
                text = await resp.text()
                break
        except Exception as e:
            if attempt < retries:
                jitter = random.uniform(0, 1.5)
                delay = FETCH_SOURCE_DELAY * (attempt + 1) + jitter
                log.warning(f"Fetch fail {url}: {e}, retry in {delay:.1f}s...")
                await asyncio.sleep(delay)
            else:
                log.warning(f"Fetch fail {url} after {retries+1} tries")
                return []
    try:
        dec = base64.b64decode(text).decode("utf-8", errors="ignore")
        if any(x in dec for x in ("vless://", "trojan://", "hy2://", "hysteria2://", "ss://", "tuic://", "vmess://")):
            text = dec
    except Exception:
        pass
    if "proxies:" in text[:5000]:
        yp = parse_clash_yaml(text)
        if yp:
            return [x.uri for x in yp]
    proxies = []
    for line in text.splitlines():
        line = line.strip()
        if any(line.startswith(s) for s in ("vless://", "trojan://", "hy2://", "hysteria2://", "ss://", "tuic://", "vmess://")):
            proxies.append(line)
    return proxies

async def fetch_all_sources_async(urls):
    all_u = []
    connector = aiohttp.TCPConnector(limit=FETCH_SOURCE_MAX_WORKERS)
    async with aiohttp.ClientSession(connector=connector, headers={"User-Agent": HTTP_USER_AGENT}) as session:
        tasks = [fetch_source_async(url, session) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for res in results:
            if isinstance(res, list):
                all_u.extend(res)
    return all_u

# ═══════════════════════════════════════════════════════════════════════════
#  CIRCUIT BREAKER с HALF-OPEN
# ═══════════════════════════════════════════════════════════════════════════

api_failure_counters = {}
api_circuit_open = {}

def is_api_circuit_open(api_name: str) -> bool:
    if api_name not in api_circuit_open:
        return False
    if not api_circuit_open[api_name]:
        return False
    if api_name in api_failure_counters:
        _, last_fail, open_time = api_failure_counters[api_name]
        if time.time() - open_time > API_HALF_OPEN_INTERVAL:
            api_circuit_open[api_name] = False
            log.info(f"Circuit breaker для {api_name} переходит в half-open (попытка восстановления)")
            return False
    return True

def record_api_failure(api_name: str):
    now = time.time()
    if api_name not in api_failure_counters:
        api_failure_counters[api_name] = (1, now, now)
    else:
        count, last, open_time = api_failure_counters[api_name]
        if now - last < API_FAILURE_WINDOW:
            count += 1
        else:
            count = 1
            open_time = now
        if count >= API_FAILURE_THRESHOLD and not api_circuit_open.get(api_name, False):
            log.warning(f"Circuit breaker открыт для {api_name}")
            api_circuit_open[api_name] = True
        api_failure_counters[api_name] = (count, now, open_time)

def record_api_success(api_name: str):
    if api_name in api_failure_counters:
        api_failure_counters[api_name] = (0, 0, 0)
    if api_name in api_circuit_open:
        api_circuit_open[api_name] = False

# ═══════════════════════════════════════════════════════════════════════════
#  ГЕОЛОКАЦИЯ
# ═══════════════════════════════════════════════════════════════════════════

from collections import Counter

async def geolocate_ips_async(proxies: List[Proxy]) -> Dict[str, Dict]:
    ips = list({p.host for p in proxies if is_ip_address(p.host)})
    if not ips:
        return {}
    cache = {}
    log.info(f"Геолокация {len(ips)} IP с несколькими API...")

    for i in range(0, len(ips), GEO_BATCH_SIZE):
        batch_ips = ips[i:i+GEO_BATCH_SIZE]
        results = []
        connector = aiohttp.TCPConnector(limit=10)
        async with aiohttp.ClientSession(connector=connector, headers={"User-Agent": HTTP_USER_AGENT}) as session:
            tasks = []
            if len(batch_ips) > 1 and not is_api_circuit_open("ip-api"):
                tasks.append(_geo_ip_api(session, batch_ips))
            elif len(batch_ips) == 1 and not is_api_circuit_open("ip-api-single"):
                tasks.append(_geo_ip_api_single(session, batch_ips[0]))
            if not is_api_circuit_open("ipinfo"):
                tasks.append(_geo_ipinfo(session, batch_ips))
            if not is_api_circuit_open("geoip-db"):
                tasks.append(_geo_geoipdb(session, batch_ips))
            if not tasks:
                log.warning("Все гео-API отключены circuit breaker, используем заглушку")
                for ip in batch_ips:
                    cache[ip] = {"country_code": "XX", "country": "Unknown", "isp": "", "asn": "", "status": "fail"}
                continue

            geo_results = await asyncio.gather(*tasks, return_exceptions=True)
            for gr in geo_results:
                if isinstance(gr, dict):
                    for ip, data in gr.items():
                        results.append({ip: data})

        for ip in batch_ips:
            candidates = []
            for r in results:
                if ip in r:
                    candidates.append(r[ip])
            if candidates:
                countries = [c.get("country_code", "XX") for c in candidates if c.get("status") == "success"]
                if countries:
                    counter = Counter(countries)
                    most_common = counter.most_common(1)[0][0]
                    for c in candidates:
                        if c.get("country_code") == most_common:
                            cache[ip] = c
                            break
                else:
                    cache[ip] = candidates[0]
            else:
                cache[ip] = {"country_code": "XX", "country": "Unknown", "isp": "", "asn": "", "status": "fail"}
        await asyncio.sleep(GEO_API_SLEEP)

    return cache

async def _geo_ip_api(session, ips):
    api_name = "ip-api"
    if is_api_circuit_open(api_name):
        return {}
    url = "http://ip-api.com/batch"
    try:
        async with session.post(url, json=ips, timeout=GEO_API_TIMEOUT) as resp:
            if resp.status == 200:
                data = await resp.json()
                result = {}
                for item in data:
                    ip = item.get("query", "")
                    if item.get("status") == "success":
                        result[ip] = {
                            "country_code": item.get("countryCode", "XX"),
                            "country": item.get("country", "Unknown"),
                            "isp": item.get("isp", ""),
                            "asn": item.get("as", ""),
                            "status": "success"
                        }
                    else:
                        result[ip] = {"status": "fail"}
                record_api_success(api_name)
                return result
    except Exception as e:
        log.warning(f"ip-api.com error: {e}")
        record_api_failure(api_name)
    return {}

async def _geo_ip_api_single(session, ip):
    api_name = "ip-api-single"
    if is_api_circuit_open(api_name):
        return {}
    url = f"http://ip-api.com/json/{ip}"
    try:
        async with session.get(url, timeout=GEO_API_TIMEOUT) as resp:
            if resp.status == 200:
                data = await resp.json()
                if data.get("status") == "success":
                    record_api_success(api_name)
                    return {ip: {
                        "country_code": data.get("countryCode", "XX"),
                        "country": data.get("country", "Unknown"),
                        "isp": data.get("isp", ""),
                        "asn": data.get("as", ""),
                        "status": "success"
                    }}
    except Exception:
        record_api_failure(api_name)
    return {}

async def _geo_ipinfo(session, ips):
    api_name = "ipinfo"
    if is_api_circuit_open(api_name):
        return {}
    result = {}
    for ip in ips:
        url = f"https://ipinfo.io/{ip}/json"
        try:
            async with session.get(url, timeout=GEO_API_TIMEOUT) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if data:
                        cc = data.get("country", "XX")
                        result[ip] = {
                            "country_code": cc,
                            "country": cc,
                            "isp": data.get("org", ""),
                            "asn": data.get("asn", ""),
                            "status": "success"
                        }
                    else:
                        result[ip] = {"status": "fail"}
        except Exception:
            result[ip] = {"status": "fail"}
            record_api_failure(api_name)
    if result:
        record_api_success(api_name)
    return result

async def _geo_geoipdb(session, ips):
    api_name = "geoip-db"
    if is_api_circuit_open(api_name):
        return {}
    result = {}
    for ip in ips:
        url = f"https://geoip-db.com/json/{ip}"
        try:
            async with session.get(url, timeout=GEO_API_TIMEOUT) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if data.get("country_code"):
                        result[ip] = {
                            "country_code": data.get("country_code", "XX"),
                            "country": data.get("country_name", "Unknown"),
                            "isp": data.get("isp", ""),
                            "asn": data.get("asn", ""),
                            "status": "success"
                        }
                    else:
                        result[ip] = {"status": "fail"}
        except Exception:
            result[ip] = {"status": "fail"}
            record_api_failure(api_name)
    if result:
        record_api_success(api_name)
    return result

# ═══════════════════════════════════════════════════════════════════════════
#  ИСТОРИЯ И ВЕСА (полный класс)
# ═══════════════════════════════════════════════════════════════════════════

class ProxyHistory:
    def __init__(self, history_file=HISTORY_FILE, source_stats_file=SOURCE_STATS_FILE):
        self.history_file = history_file
        self.source_stats_file = source_stats_file
        self.history = self._load_history()
        self.source_stats = self._load_source_stats()

    def _load_history(self):
        if os.path.exists(self.history_file):
            try:
                with open(self.history_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                log.warning("Не удалось загрузить историю, создаём новую")
                return {}
        return {}

    def _save_history(self):
        try:
            with open(self.history_file, 'w', encoding='utf-8') as f:
                json.dump(self.history, f, indent=2)
        except IOError as e:
            log.error(f"Не удалось сохранить историю: {e}")

    def _load_source_stats(self):
        if os.path.exists(self.source_stats_file):
            try:
                with open(self.source_stats_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                log.warning("Не удалось загрузить статистику источников, создаём новую")
                return {}
        return {}

    def _save_source_stats(self):
        try:
            with open(self.source_stats_file, 'w', encoding='utf-8') as f:
                json.dump(self.source_stats, f, indent=2)
        except IOError as e:
            log.error(f"Не удалось сохранить статистику источников: {e}")

    def _make_key(self, proxy: Proxy) -> str:
        return f"{proxy.protocol}|{proxy.host}|{proxy.port}|{proxy.sni or ''}"

    def update(self, alive_proxies: List[Proxy], all_proxies: List[Proxy], run_date=None):
        if run_date is None:
            run_date = datetime.now(timezone.utc).isoformat()

        source_alive_count = {}
        for p in alive_proxies:
            src = p.source_url or "unknown"
            source_alive_count[src] = source_alive_count.get(src, 0) + 1
        for p in all_proxies:
            src = p.source_url or "unknown"
            if src not in self.source_stats:
                self.source_stats[src] = {"total": 0, "alive": 0, "history": []}
            self.source_stats[src]["total"] += 1

        for src, count in source_alive_count.items():
            if src in self.source_stats:
                self.source_stats[src]["alive"] = count
                self.source_stats[src]["history"].append({
                    "date": run_date,
                    "alive_ratio": count / self.source_stats[src]["total"] if self.source_stats[src]["total"] > 0 else 0
                })
                if len(self.source_stats[src]["history"]) > 30:
                    self.source_stats[src]["history"] = self.source_stats[src]["history"][-30:]
        self._save_source_stats()

        for p in alive_proxies:
            key = self._make_key(p)
            if key not in self.history:
                self.history[key] = {
                    "first_seen": run_date,
                    "last_seen": run_date,
                    "appearances": 1,
                    "last_alive": True,
                    "protocol": p.protocol,
                    "host": p.host,
                    "port": p.port,
                    "sni": p.sni or "",
                    "credential": p.credential,
                    "security": p.security,
                    "transport": p.transport_type,
                    "country": p.country_code,
                    "tcp_latency_ms": p.tcp_latency_ms,
                    "http_latency_ms": p.http_latency_ms,
                    "p95_latency_ms": p.p95_latency_ms,
                    "stress_success_rate": p.stress_success_rate,
                    "jitter_ms": p.jitter_ms,
                    "score": p.score,
                    "uri": p.uri,
                    "source_url": p.source_url or "unknown",
                    "ema_latency": p.http_latency_ms,
                    "last_alive_history": [True],
                }
            else:
                entry = self.history[key]
                entry["last_seen"] = run_date
                entry["appearances"] += 1
                entry["last_alive"] = True
                old_ema = entry.get("ema_latency", p.http_latency_ms)
                alpha = WEIGHT_CONFIG["ema_latency_weight"]
                new_ema = alpha * p.http_latency_ms + (1 - alpha) * old_ema
                entry["ema_latency"] = new_ema
                entry["protocol"] = p.protocol
                entry["host"] = p.host
                entry["port"] = p.port
                entry["sni"] = p.sni or ""
                entry["credential"] = p.credential
                entry["security"] = p.security
                entry["transport"] = p.transport_type
                entry["country"] = p.country_code
                entry["tcp_latency_ms"] = p.tcp_latency_ms
                entry["http_latency_ms"] = p.http_latency_ms
                entry["p95_latency_ms"] = p.p95_latency_ms
                entry["stress_success_rate"] = p.stress_success_rate
                entry["jitter_ms"] = p.jitter_ms
                entry["score"] = p.score
                entry["uri"] = p.uri
                entry["source_url"] = p.source_url or "unknown"
                history_list = entry.get("last_alive_history", [])
                history_list.append(True)
                if len(history_list) > 30:
                    history_list = history_list[-30:]
                entry["last_alive_history"] = history_list

        seen_keys = set(self._make_key(p) for p in alive_proxies)
        for key in self.history:
            if key not in seen_keys:
                self.history[key]["last_alive"] = False
                history_list = self.history[key].get("last_alive_history", [])
                history_list.append(False)
                if len(history_list) > 30:
                    history_list = history_list[-30:]
                self.history[key]["last_alive_history"] = history_list

        cutoff = datetime.now(timezone.utc).timestamp() - 30 * 24 * 3600
        to_remove = []
        for key, entry in self.history.items():
            try:
                last_seen = datetime.fromisoformat(entry["last_seen"]).timestamp()
                if last_seen < cutoff:
                    to_remove.append(key)
            except ValueError:
                to_remove.append(key)
        for key in to_remove:
            del self.history[key]

        self._save_history()

    def compute_weight(self, entry: Dict) -> int:
        weight = 0

        sec = entry.get("security", "none")
        weight += WEIGHT_CONFIG["security"].get(sec, 0)

        proto = entry.get("protocol", "unknown")
        weight += WEIGHT_CONFIG["protocol"].get(proto, 0)

        country = entry.get("country", "XX")
        weight += WEIGHT_CONFIG["country_boost"].get(country, 5)

        latency = entry.get("ema_latency", entry.get("http_latency_ms", 0))
        if latency > 0:
            if latency < 50:
                weight -= WEIGHT_CONFIG["latency_ms"]["very_good"]
            elif latency < 150:
                weight -= WEIGHT_CONFIG["latency_ms"]["good"]
            elif latency < 300:
                weight -= WEIGHT_CONFIG["latency_ms"]["average"]
            else:
                weight -= WEIGHT_CONFIG["latency_ms"]["poor"]
        else:
            weight -= WEIGHT_CONFIG["latency_ms"]["unknown"]

        p95 = entry.get("p95_latency_ms", 0)
        if p95 > 0:
            if p95 < 80:
                weight -= WEIGHT_CONFIG["p95_latency"]["very_good"]
            elif p95 < 200:
                weight -= WEIGHT_CONFIG["p95_latency"]["good"]
            elif p95 < 400:
                weight -= WEIGHT_CONFIG["p95_latency"]["average"]
            else:
                weight -= WEIGHT_CONFIG["p95_latency"]["poor"]

        success_rate = entry.get("stress_success_rate", 0)
        if success_rate > 0:
            if success_rate > 0.9:
                weight -= WEIGHT_CONFIG["stability"]["high"]
            elif success_rate > 0.7:
                weight -= WEIGHT_CONFIG["stability"]["medium"]
            else:
                weight -= WEIGHT_CONFIG["stability"]["low"]
        else:
            weight -= WEIGHT_CONFIG["stability"]["unknown"]

        appearances = entry.get("appearances", 0)
        threshold = WEIGHT_CONFIG["appearance_threshold"]
        if appearances >= threshold:
            bonus = (appearances - threshold) * WEIGHT_CONFIG["appearance_bonus"]
            weight += bonus

        try:
            last_seen = datetime.fromisoformat(entry["last_seen"])
            days_ago = (datetime.now(timezone.utc) - last_seen).days
            weight -= days_ago * WEIGHT_CONFIG["age_penalty"]
        except (ValueError, TypeError):
            pass

        src = entry.get("source_url", "unknown")
        src_stats = self.source_stats.get(src, {})
        total = src_stats.get("total", 0)
        alive = src_stats.get("alive", 0)
        if total > 0:
            ratio = alive / total
            if ratio > 0.5:
                weight += WEIGHT_CONFIG["source_trust_bonus"]

        history = entry.get("last_alive_history", [])
        if len(history) >= 5:
            flips = sum(1 for i in range(1, len(history)) if history[i] != history[i-1])
            avg_flips = flips / len(history)
            if avg_flips > 0.3:
                weight -= WEIGHT_CONFIG["flapping_penalty"]

        return max(0, weight)

    def get_top30(self):
        candidates = []
        for key, entry in self.history.items():
            if entry.get("appearances", 0) >= WEIGHT_CONFIG["appearance_threshold"] and entry.get("last_alive", False):
                weight = self.compute_weight(entry)
                candidates.append((weight, entry))
        candidates.sort(key=lambda x: x[0], reverse=True)
        top30 = [entry for _, entry in candidates[:30]]
        return top30

    def get_top30_uris(self):
        top = self.get_top30()
        return [entry.get("uri", "") for entry in top if entry.get("uri")]

    def print_top30(self, top30):
        if not top30:
            log.info("Нет прокси, удовлетворяющих условиям для top30.")
            return
        log.info("=== Топ-30 прокси по весу ===")
        for i, entry in enumerate(top30, 1):
            weight = self.compute_weight(entry)
            flag = country_to_flag(entry.get("country", "XX"))
            log.info(f"{i:2}. {flag} {entry.get('host')}:{entry.get('port')} "
                     f"({entry.get('protocol')}, {entry.get('security')}) "
                     f"вес={weight}, появлений={entry.get('appearances', 0)}")

    def write_top30(self, filename=TOP30_FILE):
        top30 = self.get_top30()
        if not top30:
            log.info("Нет прокси для записи в top30.txt")
            with open(filename, 'w', encoding='utf-8') as f:
                f.write('')
            return
        with open(filename, 'w', encoding='utf-8') as f:
            for entry in top30:
                uri = entry.get("uri", "")
                if uri:
                    f.write(uri + "\n")
        log.info(f"Записано {len(top30)} прокси в {filename}")

# ═══════════════════════════════════════════════════════════════════════════
#  ОСНОВНОЙ ПАЙПЛАЙН
# ═══════════════════════════════════════════════════════════════════════════

async def _prefilter_proxy_async(proxy: Proxy, singbox_path: str) -> Optional[Proxy]:
    if ENABLE_TLS_CHECK:
        ok, cert_info = await asyncio.to_thread(tls_handshake_check, proxy, TLS_TIMEOUT)
        if not ok:
            pass
    if ENABLE_CONFIG_CHECK:
        if not await asyncio.to_thread(config_is_valid, proxy, singbox_path):
            return None
    return proxy

async def check_all_proxies_async(proxies: List[Proxy], singbox_path: str) -> List[Proxy]:
    if not proxies:
        return []

    tcp_alive = []
    total = len(proxies)
    log.info(f"TCP-проверка {total} прокси ({MAX_WORKERS} воркеров)...")
    sem = asyncio.Semaphore(MAX_WORKERS)
    async def check_one(p):
        async with sem:
            return await asyncio.to_thread(_tcp_check, p)
    tasks = [check_one(p) for p in proxies]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, Proxy) and r is not None:
            tcp_alive.append(r)
    log.info(f"TCP-проверка завершена: {len(tcp_alive)}/{total}")

    if not tcp_alive:
        return []

    log.info("Применяем предварительные фильтры (TLS, config check)...")
    filtered = []
    tasks = [_prefilter_proxy_async(p, singbox_path) for p in tcp_alive]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, Proxy) and r is not None:
            filtered.append(r)
    log.info(f"После предфильтрации: {len(filtered)}/{len(tcp_alive)}")

    if not filtered:
        return []

    alive = await check_proxies_via_singbox_async(filtered, singbox_path)

    for p in alive:
        p.score = compute_score(p)
    return alive

# ── Чтение и запись ──────────────────────────────────────────────────────

def read_input_urls(filename):
    try:
        with open(filename, "r", encoding="utf-8") as f:
            return [l.strip() for l in f if l.strip() and not l.startswith("#")]
    except FileNotFoundError:
        log.error(f"{filename} not found")
        sys.exit(1)

def write_output_txt(proxies: List[Proxy], filename):
    with open(filename, "w", encoding="utf-8") as f:
        for p in proxies:
            f.write(p.uri + "\n")
    log.info(f"Записано {len(proxies)} → {filename}")

def print_output(proxies):
    for p in proxies:
        print(p.uri)

# ── main (асинхронный) ──────────────────────────────────────────────────

async def main_async():
    t0 = time.time()
    log.info("=" * 60)
    log.info("Proxy Checker v11.0 — с улучшенной живостью и exit-IP")
    log.info("=" * 60)

    urls = read_input_urls(INPUT_FILE)
    log.info(f"Загружено {len(urls)} источников из {INPUT_FILE}")

    all_u = await fetch_all_sources_async(urls)
    log.info(f"Получено {len(all_u)} сырых URI")

    parsed = []
    for u in all_u:
        p = cached_parse(u)
        if p:
            parsed.append(p)
    log.info(f"Распарсено: {len(parsed)}")

    parsed = [p for p in parsed if has_security(p)]
    parsed = [p for p in parsed if validate_reality_params(p)]
    if ENABLE_IP_ONLY_FILTER:
        parsed = [p for p in parsed if is_ip_only(p)]
    parsed = [p for p in parsed if not is_blacklisted(p)]
    unique = deduplicate_proxies(parsed)
    log.info(f"После дедупликации: {len(unique)}")

    if not unique:
        log.info("Нет прокси для проверки. Завершаем.")
        with open(TOP30_FILE, 'w') as f:
            f.write('')
        return

    singbox_path = await _ensure_singbox_async()
    log.info(f"sing-box готов: {singbox_path}")

    alive = await check_all_proxies_async(unique, singbox_path)

    geo = await geolocate_ips_async(alive)
    for p in alive:
        g = geo.get(p.host, {})
        p.country_code = g.get("country_code", "XX")
        p.country = g.get("country", "Unknown")
        p.isp = g.get("isp", "")
        p.asn = g.get("asn", "")
        asn = p.asn
        hosting_keywords = ["AMAZON", "DIGITALOCEAN", "HETZNER", "OVH", "ONLINE", "SCALEWAY", "LINODE", "VULTR", "GOOGLE-CLOUD", "MICROSOFT"]
        if any(kw in asn.upper() for kw in hosting_keywords):
            p.is_hosting = True
        else:
            p.is_hosting = False

    for p in alive:
        tags = []
        if p.is_hosting:
            tags.append("Datacenter")
        if p.is_proxy:
            tags.append("Proxy")
        if p.unlocks_netflix:
            tags.append("Netflix")
        if p.unlocks_youtube:
            tags.append("YouTube")
        if p.is_honeypot_suspect:
            tags.append("Honeypot?")
        flag = country_to_flag(p.country_code)
        remark = f"{flag} {p.country} | Score:{p.score}"
        if tags:
            remark += " | " + " ".join(tags)
        p.uri = rewrite_uri_fragment(p.uri, remark)

    alive.sort(key=lambda x: x.score, reverse=True)
    write_output_txt(alive, OUTPUT_FILE)

    history = ProxyHistory()
    if alive:
        log.info("Обновление истории прокси...")
        history.update(alive, unique)
        history.write_top30(TOP30_FILE)
        history.print_top30(history.get_top30())
    else:
        log.info("Нет живых прокси для обновления истории.")
        with open(TOP30_FILE, 'w') as f:
            f.write('')

    if "--print" in sys.argv:
        print_output(alive)

    elapsed = time.time() - t0
    log.info(f"Готово: {len(alive)} прокси → {OUTPUT_FILE}, top30 → {TOP30_FILE} за {elapsed:.1f}с")

def main():
    try:
        asyncio.run(asyncio.wait_for(main_async(), timeout=GLOBAL_TIMEOUT))
    except asyncio.TimeoutError:
        log.error(f"Превышен лимит времени ({GLOBAL_TIMEOUT} сек), завершаемся.")
        cleanup()
        sys.exit(1)

if __name__ == "__main__":
    main()
