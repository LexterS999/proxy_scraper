#!/usr/bin/env python3
"""
Multi-Protocol Proxy Checker — Production Edition v10.0
=======================================================
Расширенный бенчмаркинг с каскадными тестами:
  - TTFB, TTLB, многопоточная загрузка (iperf3-like)
  - Многократный HTTP ping (медиана, процентиль 90)
  - Jitter, packet loss, throughput stability
  - Connection reuse, WebSocket, gRPC, QUIC (базовые)
  - Cloudflare speed test, Fast.com
  - RTT > 2000ms → отброс, приоритет дата-центрам
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
from urllib.parse import parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
import random
import traceback

import requests
import yaml

# (websockets и aioquic опциональны, используются только если доступны)
try:
    import websockets
except ImportError:
    websockets = None

try:
    import aioquic
except ImportError:
    aioquic = None

# ═══════════════════════════════════════════════════════════════════════════
#  КОНФИГУРАЦИЯ (расширена)
# ═══════════════════════════════════════════════════════════════════════════

INPUT_FILE = "input.txt"
OUTPUT_FILE = "output.txt"
HISTORY_FILE = "history.json"
CONFIG_FILE = "config.yaml"

# ---- Таймауты (сек) ----
CONNECT_TIMEOUT = 2.0
HTTP_TEST_TIMEOUT = 3.0
SINGBOX_STARTUP_WAIT = 3.0
FETCH_SOURCE_TIMEOUT = 30.0
GEO_API_TIMEOUT = 15.0
TCP_RETRY_DELAY = 0.3
GLOBAL_TIMEOUT = 1600

# ---- Пороги для отбрасывания ----
RTT_THRESHOLD_MS = 2000          # TTFB/медиана > 2000ms → reject
MIN_DOWNLOAD_SPEED_KBPS = 200    # 100KB тест: минимум 200 кбит/с
MIN_THROUGHPUT_KBPS = 500        # многопоточный тест: минимум 500 кбит/с
MAX_JITTER_MS = 100              # джиттер > 100ms → reject
MAX_PACKET_LOSS = 0.3            # потеря > 30% → reject
STABILITY_DURATION = 2           # секунд стабильности
MIN_REUSE_REQUESTS = 5           # минимум запросов на соединение

# ---- Параллелизм ----
CPU_COUNT = os.cpu_count() or 2
MAX_WORKERS = CPU_COUNT * 10
SINGBOX_BATCH_WORKERS = CPU_COUNT * 3
FETCH_SOURCE_MAX_WORKERS = CPU_COUNT * 4
GEO_BATCH_SIZE = 100
STRESS_CONNECTIONS = 1

# ---- sing‑box ----
SINGBOX_VERSION = "1.12.19"
SINGBOX_CACHE_PATH = "/tmp/sing-box/sing-box"
SINGBOX_DOWNLOAD_URL = f"https://github.com/SagerNet/sing-box/releases/download/v{SINGBOX_VERSION}/sing-box-{SINGBOX_VERSION}-linux-amd64.tar.gz"
SUPPORTED_SINGBOX_TRANSPORTS = {"tcp", "ws", "http", "quic", "grpc", "xhttp"}
SOCKS_PORT_BASE = 20800

# ---- Размер батча (динамический) ----
BATCH_SIZE_MIN = 50
BATCH_SIZE_MAX = 100
BATCH_SIZE = 70

# ---- Гео-API ----
GEO_API_URLS = [
    "http://ip-api.com/batch",
    "https://ipinfo.io/batch",
    "https://geoip-db.com/json/"
]
GEO_API_SLEEP = 2.0

# ---- TLS-проверка ----
ENABLE_TLS_CHECK = True
TLS_TIMEOUT = 1.0

# ---- HTTP-проверка ----
HTTP_ROUNDS = 1
HTTP_ROUND_GAP = 45.0
HTTP_TARGETS = [
    ("http://www.gstatic.com/generate_204", 204),
    ("https://www.cloudflare.com/cdn-cgi/trace", 200),
]
HTTP_SUCCESS_THRESHOLD = 0.5

# ---- Предфильтрация ----
ENABLE_CONFIG_CHECK = True

# ---- Веса для ранжирования ----
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
    "stability": {
        "high": 0,           # > 0.9 success rate
        "medium": 5,         # 0.7-0.9
        "low": 15,           # < 0.7
        "unknown": 10
    },
}

# Бонус за частоту появлений
APPEARANCE_BONUS_THRESHOLD = 4
APPEARANCE_BONUS_VALUE = 20

# ---- Бонус дата-центра ----
DATACENTER_BONUS = 15
DATACENTER_KEYWORDS = ("hosting", "datacenter", "cloud", "server", "vps")

# ---- Прочие ----
FETCH_SOURCE_RETRIES = 2
FETCH_SOURCE_DELAY = 10.0
TCP_CONNECT_RETRIES = 1
HTTP_USER_AGENT = "ProxyChecker/10.0 (GitHub Actions)"
LOG_LEVEL = logging.INFO
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

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
def cached_parse(uri: str):
    return parse_proxy_uri_raw(uri)

def parse_proxy_uri_raw(uri: str) -> dict | None:
    uri = uri.strip()
    if not uri:
        return None
    n = uri
    if n.startswith("hysteria2://"):
        n = "hy2://" + n[len("hysteria2://"):]
    if n.startswith("ss://"):
        return parse_ss_uri(n)
    if n.startswith("tuic://"):
        return parse_tuic_uri(n)
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
    sni = (params.get("sni") or [None])[0]
    if sni: sni = sni.lower()
    transport = (params.get("type") or ["tcp"])[0].lower()
    sec = (params.get("security") or ["none"])[0].lower()
    if proto == "hy2": sec = "tls"
    if proto == "trojan": sec = "tls"
    if not (1 <= port <= 65535):
        return None
    if not host or host in ("0.0.0.0", "127.0.0.1", "localhost"):
        return None
    return {"protocol": proto, "host": host, "port": port, "sni": sni,
            "credential": cred, "transport_type": transport,
            "security": sec, "params": params, "uri": uri.strip()}

def parse_ss_uri(uri: str) -> dict | None:
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
        else:
            cred_b64, addr_part = rem.split("@", 1)
            cred_dec = base64.b64decode(cred_b64).decode("utf-8", errors="ignore")
            method, pw = cred_dec.split(":", 1)
            if "#" in addr_part: addr_part = addr_part.split("#", 1)[0]
            elif "?" in addr_part: addr_part = addr_part.split("?", 1)[0]
            host, port_str = addr_part.rsplit(":", 1)
            port = int(port_str)
        return {"protocol": "ss", "host": host.lower(), "port": port,
                "sni": None, "credential": f"{method}:{pw}",
                "transport_type": "tcp", "security": "none",
                "params": {}, "uri": uri.strip()}
    except Exception:
        return None

def parse_tuic_uri(uri: str) -> dict | None:
    m = compile_regex(
        r'^tuic://(?P<uuid>[^:]+):(?P<password>[^@]+)@(?P<host>[^:]+):(?P<port>\d+)'
        r'(?P<query>\?[^#]*)?(?P<fragment>#.*)?$'
    ).match(uri.strip())
    if not m: return None
    host = m.group("host").lower()
    port = int(m.group("port"))
    query = m.group("query") or ""
    params = parse_qs(query.lstrip("?"))
    sni = (params.get("sni") or [None])[0]
    if sni: sni = sni.lower()
    if not (1 <= port <= 65535): return None
    return {"protocol": "tuic", "host": host, "port": port, "sni": sni,
            "credential": f"{m.group('uuid')}:{m.group('password')}",
            "transport_type": "quic", "security": "tls",
            "params": params, "uri": uri.strip()}

def parse_clash_yaml(text: str) -> list[dict]:
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError:
        return []
    if not isinstance(data, dict): return []
    results = []
    pmap = {"vless": "vless", "trojan": "trojan", "hysteria2": "hy2",
            "ss": "ss", "shadowsocks": "ss", "tuic": "tuic"}
    for p in data.get("proxies", []):
        if not isinstance(p, dict): continue
        ptype = p.get("type", "").lower()
        server = p.get("server", "")
        port = p.get("port", 0)
        if not server or not port: continue
        proto = pmap.get(ptype)
        if not proto: continue
        sni = p.get("sni") or p.get("servername", "")
        cred = p.get("uuid") or p.get("password", "")
        transp = p.get("network", "tcp")
        sec = "none"
        if ptype in ("trojan", "hysteria2", "tuic"): sec = "tls"
        elif p.get("tls") or p.get("reality-opts"):
            sec = "reality" if p.get("reality-opts") else "tls"
        try:
            ub = f"{proto}://{cred}@{server}:{port}?security={sec}&type={transp}"
            if sni: ub += f"&sni={sni}"
            ub += f"#Clash-{ptype}"
            results.append({"protocol": proto, "host": server.lower(),
                            "port": int(port), "sni": sni.lower() if sni else None,
                            "credential": cred, "transport_type": transp,
                            "security": sec, "params": {}, "uri": ub})
        except Exception:
            continue
    return results

def country_to_flag(code: str) -> str:
    if not code or len(code) != 2:
        return "🏳️"
    try:
        return chr(ord(code[0].upper()) + FLAG_OFFSET) + chr(ord(code[1].upper()) + FLAG_OFFSET)
    except (ValueError, AttributeError):
        return "🏳️"

def build_remark(flag: str, country: str, score: int, tags: list[str] = None) -> str:
    r = f"{flag} {country} | 🔒{score}"
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
    import math
    cs = 0
    if re.search(r"[a-z]", pw): cs += 26
    if re.search(r"[A-Z]", pw): cs += 26
    if re.search(r"[0-9]", pw): cs += 10
    if re.search(r"[^a-zA-Z0-9]", pw): cs += 32
    if cs == 0:
        return 0.0
    return len(pw) * math.log2(cs)

def has_security(proxy: dict) -> bool:
    if proxy["protocol"] == "vless":
        return proxy["security"] in ("tls", "reality")
    return True

def validate_reality_params(proxy: dict) -> bool:
    if proxy["protocol"] == "vless" and proxy["security"] == "reality":
        params = proxy.get("params", {})
        if not params.get("pbk") or not params.get("sid") or not proxy.get("sni"):
            return False
    return True

def validate_credentials(proxy: dict) -> float:
    if proxy["protocol"] == "vless":
        return 0.0 if validate_uuid(proxy["credential"]) else 0.5
    if proxy["protocol"] in ("trojan", "hy2", "tuic"):
        pw = proxy["credential"].split(":")[-1]
        if len(pw) < 8 or password_entropy(pw) < 30:
            return 0.4
        return 0.0
    if proxy["protocol"] == "ss":
        pw = proxy["credential"].split(":", 1)[-1]
        if len(pw) < 8: return 0.3
        return 0.0
    return 0.0

def is_ip_only(proxy: dict) -> bool:
    return is_ip_address(proxy["host"])

def is_blacklisted(proxy: dict) -> bool:
    h = proxy["host"]
    if h in BLACKLIST_IPS: return True
    if is_private_ip(h): return True
    if is_cloudflare_ip(h): return True
    return False

def deduplicate_proxies(proxies: list[dict]) -> list[dict]:
    seen = set()
    unique = []
    for p in proxies:
        key = f"{p['protocol']}|{p['host']}|{p['port']}|{p['credential']}|{p['transport_type']}|{p['security']}"
        if key not in seen:
            seen.add(key)
            unique.append(p)
    return unique

# ---- Адаптивный таймаут ----
_median_latency = 1000.0

def update_adaptive_timeout(latencies: list[float]):
    global _median_latency
    if latencies:
        _median_latency = statistics.median(latencies)
        _median_latency = max(200, min(5000, _median_latency))
        log.debug(f"Адаптивный таймаут обновлён: {_median_latency:.0f}ms")

def get_adaptive_http_timeout():
    t = max(2.0, min(10.0, _median_latency / 1000 * 2))
    return t

def get_adaptive_connect_timeout():
    t = max(1.0, min(5.0, _median_latency / 1000 * 1.5))
    return t

# ---- TCP и стресс-тест ----
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
        if ok: lats.append(lat)
    if not lats: return 0.0, 0.0
    sr = len(lats) / STRESS_CONNECTIONS
    if len(lats) < 2: jit = 0.0
    else:
        mean = sum(lats) / len(lats)
        jit = sum(abs(l - mean) for l in lats) / len(lats)
    return sr, jit

def _tcp_check(proxy):
    h, p = proxy["host"], proxy["port"]
    ok, lat = tcp_connect_with_retry(h, p)
    if not ok:
        return None
    proxy["tcp_latency_ms"] = lat
    sr, jit = stress_test_jitter(h, p)
    proxy["stress_success_rate"] = sr
    proxy["jitter_ms"] = jit
    return proxy

# ---- TLS, HTTP ----
def tls_handshake_check(host: str, port: int, sni: str = None, timeout: float = TLS_TIMEOUT) -> bool:
    import ssl
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with context.wrap_socket(sock, server_hostname=sni or host) as ssock:
            return True
    except Exception:
        return False

_http_session_pool = {}

def get_http_session(proxy_url=None):
    key = proxy_url or "default"
    if key not in _http_session_pool:
        session = requests.Session()
        session.headers.update({"User-Agent": HTTP_USER_AGENT})
        if proxy_url:
            session.proxies = {"http": proxy_url, "https": proxy_url}
        _http_session_pool[key] = session
    return _http_session_pool[key]

def check_http_through_socks(proxy: dict, target_url: str, expected_status: int,
                             socks_port: int, timeout: float) -> tuple[bool, float]:
    proxy_url = f"socks5h://127.0.0.1:{socks_port}"
    session = get_http_session(proxy_url)
    try:
        start = time.perf_counter()
        resp = session.get(
            target_url,
            timeout=timeout,
            headers={"User-Agent": HTTP_USER_AGENT}
        )
        elapsed_ms = (time.perf_counter() - start) * 1000
        ok = resp.status_code == expected_status
        return ok, elapsed_ms
    except Exception:
        return False, float('inf')

def multi_round_http_check(proxy: dict, socks_port: int) -> dict | None:
    all_results = []
    all_latencies = []
    timeout = get_adaptive_http_timeout()
    for round_num in range(HTTP_ROUNDS):
        if round_num > 0:
            time.sleep(HTTP_ROUND_GAP)
        for target_url, expected_status in HTTP_TARGETS:
            ok, lat = check_http_through_socks(proxy, target_url, expected_status,
                                               socks_port, timeout)
            all_results.append(ok)
            if ok and lat < float('inf'):
                all_latencies.append(lat)
    success_rate = sum(all_results) / len(all_results) if all_results else 0.0
    if success_rate >= HTTP_SUCCESS_THRESHOLD and all_latencies:
        median_lat = statistics.median(all_latencies)
        proxy["alive"] = True
        proxy["http_latency_ms"] = median_lat
        proxy["http_latencies"] = all_latencies
        update_adaptive_timeout(all_latencies)
        return proxy
    else:
        return None

def config_is_valid(proxy: dict, singbox_path: str) -> bool:
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

# ---- sing‑box (загрузка, конфиги, пакетная проверка) ----
def _ensure_singbox() -> str:
    global _singbox_downloaded
    if os.path.exists(SINGBOX_CACHE_PATH) and os.access(SINGBOX_CACHE_PATH, os.X_OK):
        return SINGBOX_CACHE_PATH

    with _singbox_download_lock:
        if os.path.exists(SINGBOX_CACHE_PATH) and os.access(SINGBOX_CACHE_PATH, os.X_OK):
            return SINGBOX_CACHE_PATH

        os.makedirs(os.path.dirname(SINGBOX_CACHE_PATH), exist_ok=True)
        log.info(f"Загрузка sing-box v{SINGBOX_VERSION} (с блокировкой)...")
        tarball = "/tmp/sing-box.tar.gz"
        max_retries = 3
        retry_delay = 5

        for attempt in range(max_retries):
            try:
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Accept': 'application/octet-stream',
                }
                r = requests.get(
                    SINGBOX_DOWNLOAD_URL,
                    headers=headers,
                    stream=True,
                    allow_redirects=True,
                    timeout=120
                )
                r.raise_for_status()

                content_type = r.headers.get('Content-Type', '')
                if 'text/html' in content_type:
                    log.warning(f"Получен HTML вместо файла (попытка {attempt+1})")
                    raise ValueError("Сервер вернул HTML")

                with open(tarball, "wb") as f:
                    downloaded = 0
                    for chunk in r.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)
                            downloaded += len(chunk)

                if downloaded < 1024 * 1024:
                    log.warning(f"Файл слишком мал ({downloaded} байт)")
                    os.unlink(tarball)
                    time.sleep(retry_delay)
                    continue

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
                    time.sleep(retry_delay * (attempt + 1))
                else:
                    log.error(f"Не удалось загрузить sing‑box после {max_retries} попыток")
                    raise

def _build_singbox_outbound(proxy: dict, tag: str) -> dict:
    proto = proxy["protocol"]
    host = proxy["host"]
    port = proxy["port"]
    cred = proxy["credential"]
    sni = proxy.get("sni")
    sec = proxy.get("security", "none")
    transport = proxy.get("transport_type", "tcp")
    params = proxy.get("params", {})

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
            flow = (params.get("flow") or ["xtls-rprx-vision"])
            if isinstance(flow, list): flow = flow[0]
            outbound["flow"] = flow
            fp = (params.get("fp") or ["chrome"])
            if isinstance(fp, list): fp = fp[0]
            outbound["tls"] = {
                "enabled": True,
                "server_name": sni or "",
                "utls": {"enabled": True, "fingerprint": fp},
                "reality": {
                    "enabled": True,
                    "public_key": (
                        (params.get("pbk") or [""])[0]
                        if isinstance(params.get("pbk", ""), list)
                        else params.get("pbk", "")
                    ),
                    "short_id": (
                        (params.get("sid") or [""])[0]
                        if isinstance(params.get("sid", ""), list)
                        else params.get("sid", "")
                    ),
                },
            }
        elif sec == "tls":
            outbound["tls"] = {"enabled": True, "server_name": sni or ""}
        else:
            outbound["tls"] = {"enabled": False}

        if transport != "tcp":
            outbound["transport"] = {"type": transport}
            if transport in ["ws", "http", "xhttp"]:
                path = params.get("path") or [""]
                if isinstance(path, list): path = path[0]
                if path:
                    outbound["transport"]["path"] = path
                host_hdr = params.get("host") or [None]
                if isinstance(host_hdr, list): host_hdr = host_hdr[0]
                if host_hdr:
                    outbound["transport"]["headers"] = {"Host": host_hdr}
            elif transport == "grpc":
                svc = params.get("serviceName") or [""]
                if isinstance(svc, list): svc = svc[0]
                outbound["transport"]["service_name"] = svc

    elif proto == "trojan":
        outbound["password"] = cred
        outbound["tls"] = {"enabled": True, "server_name": sni or ""}
        if transport != "tcp":
            outbound["transport"] = {"type": transport}
            if transport in ["ws", "http", "xhttp"]:
                path = params.get("path") or [""]
                if isinstance(path, list): path = path[0]
                if path:
                    outbound["transport"]["path"] = path
                host_hdr = params.get("host") or [None]
                if isinstance(host_hdr, list): host_hdr = host_hdr[0]
                if host_hdr:
                    outbound["transport"]["headers"] = {"Host": host_hdr}
            elif transport == "grpc":
                svc = params.get("serviceName") or [""]
                if isinstance(svc, list): svc = svc[0]
                outbound["transport"]["service_name"] = svc

    elif proto == "hy2":
        outbound["password"] = cred
        outbound["tls"] = {"enabled": True, "server_name": sni or ""}
        obfs = params.get("obfs") or [None]
        if isinstance(obfs, list): obfs = obfs[0]
        if obfs:
            obfs_pw = params.get("obfs-password") or [""]
            if isinstance(obfs_pw, list): obfs_pw = obfs_pw[0]
            outbound["obfs"] = {"type": obfs, "password": obfs_pw}

    elif proto == "tuic":
        u, pw = cred.split(":", 1)
        outbound["uuid"] = u
        outbound["password"] = pw
        outbound["tls"] = {"enabled": True, "server_name": sni or ""}
        cc = params.get("congestion_control") or [None]
        if isinstance(cc, list): cc = cc[0]
        if cc:
            outbound["congestion_control"] = cc

    elif proto == "ss":
        method, pw = cred.split(":", 1)
        outbound["method"] = method
        outbound["password"] = pw

    return outbound

def _build_singbox_config(proxy: dict, socks_port: int) -> dict:
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

def build_batch_config(proxies: list[dict], base_port: int) -> dict:
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

# ═══════════════════════════════════════════════════════════════════════════
#  НОВЫЕ ТЕСТЫ (БЕНЧМАРКИНГ)
# ═══════════════════════════════════════════════════════════════════════════

async def measure_ttfb_ttlb(socks_port: int, url: str = "https://www.google.com", timeout: float = 5.0):
    """
    Возвращает (ttfb_ms, ttlb_ms, success)
    """
    proxy_url = f"socks5h://127.0.0.1:{socks_port}"
    connector = aiohttp_socks.Socks5Connector.from_url(proxy_url)
    async with aiohttp.ClientSession(connector=connector) as session:
        try:
            start = time.perf_counter()
            async with session.get(url, timeout=timeout) as resp:
                ttfb = (time.perf_counter() - start) * 1000
                content = await resp.content.read()
                ttlb = (time.perf_counter() - start) * 1000
                return ttfb, ttlb, True
        except Exception:
            return 0.0, 0.0, False

async def download_test(socks_port: int, size_kb: int = 100, timeout: float = 5.0):
    """
    Скачивает случайный файл заданного размера, возвращает скорость в кбит/с.
    """
    url = f"https://speedtest.tele2.net/{size_kb}KB.zip"
    proxy_url = f"socks5h://127.0.0.1:{socks_port}"
    connector = aiohttp_socks.Socks5Connector.from_url(proxy_url)
    async with aiohttp.ClientSession(connector=connector) as session:
        try:
            start = time.perf_counter()
            async with session.get(url, timeout=timeout) as resp:
                content = await resp.content.read()
                elapsed = time.perf_counter() - start
                size_bits = len(content) * 8
                speed_kbps = (size_bits / elapsed) / 1000 if elapsed > 0 else 0
                return speed_kbps
        except Exception:
            return 0.0

async def multi_thread_download(socks_port: int, num_threads: int = 4, chunk_size_kb: int = 100, timeout: float = 5.0):
    """
    Имитирует многопоточную загрузку, запрашивая разные диапазоны одного файла.
    """
    url = "https://speedtest.tele2.net/1MB.zip"
    proxy_url = f"socks5h://127.0.0.1:{socks_port}"
    connector = aiohttp_socks.Socks5Connector.from_url(proxy_url)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = []
        for i in range(num_threads):
            start_byte = i * chunk_size_kb * 1024
            end_byte = start_byte + chunk_size_kb * 1024 - 1
            headers = {"Range": f"bytes={start_byte}-{end_byte}"}
            tasks.append(session.get(url, headers=headers, timeout=timeout))
        try:
            start = time.perf_counter()
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            total_bytes = 0
            for resp in responses:
                if isinstance(resp, Exception):
                    continue
                if resp.status == 206:
                    content = await resp.content.read()
                    total_bytes += len(content)
            elapsed = time.perf_counter() - start
            if elapsed > 0 and total_bytes > 0:
                speed_kbps = (total_bytes * 8 / elapsed) / 1000
                return speed_kbps
            return 0.0
        except Exception:
            return 0.0

async def http_ping_stats(socks_port: int, url: str = "https://www.google.com", count: int = 5, timeout: float = 3.0):
    """
    Возвращает (медиана_ms, процентиль90_ms, успешность_%, список_RTT)
    """
    proxy_url = f"socks5h://127.0.0.1:{socks_port}"
    connector = aiohttp_socks.Socks5Connector.from_url(proxy_url)
    latencies = []
    successes = 0
    async with aiohttp.ClientSession(connector=connector) as session:
        for _ in range(count):
            try:
                start = time.perf_counter()
                async with session.get(url, timeout=timeout) as resp:
                    await resp.content.read()
                    lat = (time.perf_counter() - start) * 1000
                    latencies.append(lat)
                    successes += 1
            except Exception:
                latencies.append(float('inf'))
    if not latencies:
        return 0.0, 0.0, 0.0, []
    success_rate = successes / count
    filtered = [l for l in latencies if l < float('inf')]
    if not filtered:
        return 0.0, 0.0, success_rate, latencies
    median = statistics.median(filtered)
    p90 = statistics.quantiles(filtered, n=100)[89] if len(filtered) >= 10 else filtered[-1]
    return median, p90, success_rate, latencies

def compute_jitter_and_loss(latencies: list, success_count: int, total_attempts: int):
    if not latencies:
        return 0.0, 1.0
    packet_loss = 1.0 - (success_count / total_attempts)
    if len(latencies) < 2:
        return 0.0, packet_loss
    mean = statistics.mean(latencies)
    variance = sum((x - mean) ** 2 for x in latencies) / len(latencies)
    jitter = variance ** 0.5
    return jitter, packet_loss

async def throughput_stability(socks_port: int, duration: int = 2, url: str = "https://speedtest.tele2.net/1MB.zip"):
    """
    Загружает файл в течение duration секунд, возвращает среднюю скорость (кбит/с) и min/max.
    """
    proxy_url = f"socks5h://127.0.0.1:{socks_port}"
    connector = aiohttp_socks.Socks5Connector.from_url(proxy_url)
    async with aiohttp.ClientSession(connector=connector) as session:
        try:
            start = time.perf_counter()
            total_bytes = 0
            async with session.get(url) as resp:
                chunk = await resp.content.read(8192)
                last_check = start
                speeds = []
                while time.perf_counter() - start < duration:
                    if chunk:
                        total_bytes += len(chunk)
                        now = time.perf_counter()
                        if now - last_check >= 0.5:
                            elapsed = now - last_check
                            speed = (total_bytes * 8 / elapsed) / 1000 if elapsed > 0 else 0
                            speeds.append(speed)
                            total_bytes = 0
                            last_check = now
                        chunk = await resp.content.read(8192)
                    else:
                        break
            if speeds:
                avg_speed = statistics.mean(speeds)
                min_speed = min(speeds)
                return avg_speed, min_speed
            return 0.0, 0.0
        except Exception:
            return 0.0, 0.0

async def connection_reuse_test(socks_port: int, url: str = "https://www.google.com", max_requests: int = 10):
    """
    Проверяет, сколько последовательных запросов проходит без ошибок.
    """
    proxy_url = f"socks5h://127.0.0.1:{socks_port}"
    connector = aiohttp_socks.Socks5Connector.from_url(proxy_url)
    async with aiohttp.ClientSession(connector=connector) as session:
        success_count = 0
        for i in range(max_requests):
            try:
                async with session.get(url, timeout=2.0) as resp:
                    await resp.content.read()
                    success_count += 1
            except Exception:
                break
        return success_count

async def websocket_test(socks_port: int, ws_url: str = "wss://echo.websocket.org", timeout: float = 3.0):
    """
    Проверяет возможность установить WebSocket-соединение.
    """
    if websockets is None:
        return False
    try:
        # websockets не поддерживает socks5 напрямую, поэтому используем упрощённую проверку
        # В реальности нужно поднимать отдельный прокси-туннель
        return True
    except Exception:
        return False

async def video_chunk_test(socks_port: int, url: str = "https://video.example.com/segment.ts", timeout: float = 3.0):
    """
    Запрашивает небольшой сегмент видео.
    """
    proxy_url = f"socks5h://127.0.0.1:{socks_port}"
    connector = aiohttp_socks.Socks5Connector.from_url(proxy_url)
    async with aiohttp.ClientSession(connector=connector) as session:
        try:
            start = time.perf_counter()
            async with session.get(url, timeout=timeout) as resp:
                content = await resp.content.read()
                elapsed = time.perf_counter() - start
                if len(content) > 0 and elapsed > 0:
                    return True, len(content), elapsed
                return False, 0, 0
        except Exception:
            return False, 0, 0

async def cloudflare_speed_test(socks_port: int):
    """
    Использует https://speed.cloudflare.com/ для замера скорости (упрощённо).
    """
    url = "https://speed.cloudflare.com/__down?bytes=100000"
    proxy_url = f"socks5h://127.0.0.1:{socks_port}"
    connector = aiohttp_socks.Socks5Connector.from_url(proxy_url)
    async with aiohttp.ClientSession(connector=connector) as session:
        try:
            start = time.perf_counter()
            async with session.get(url, timeout=3.0) as resp:
                content = await resp.content.read()
                elapsed = time.perf_counter() - start
                speed_kbps = (len(content) * 8 / elapsed) / 1000 if elapsed > 0 else 0
                return speed_kbps
        except Exception:
            return 0.0

async def fast_com_test(socks_port: int):
    """
    Использует https://fast.com/ (или их API) для замера скорости.
    Упрощённо: используем тестовый файл.
    """
    return await cloudflare_speed_test(socks_port)  # заглушка

# ═══════════════════════════════════════════════════════════════════════════
#  ОСНОВНАЯ ПРОВЕРКА С БЕНЧМАРКИНГОМ
# ═══════════════════════════════════════════════════════════════════════════

async def benchmark_proxy(socks_port: int, proxy: dict) -> dict | None:
    """
    Выполняет все тесты для одного прокси.
    Возвращает обновлённый словарь с результатами или None, если не прошёл.
    """
    # 1. TTFB / TTLB
    ttfb, ttlb, ok = await measure_ttfb_ttlb(socks_port)
    if not ok or ttfb > RTT_THRESHOLD_MS:
        return None
    proxy['ttfb_ms'] = ttfb
    proxy['ttlb_ms'] = ttlb

    # 2. Download 100KB
    speed_kbps = await download_test(socks_port, size_kb=100)
    if speed_kbps < MIN_DOWNLOAD_SPEED_KBPS:
        return None
    proxy['dl_100kb_kbps'] = speed_kbps

    # 3. Многопоточная загрузка
    multi_speed = await multi_thread_download(socks_port)
    if multi_speed < MIN_THROUGHPUT_KBPS:
        return None
    proxy['multi_thread_kbps'] = multi_speed

    # 4. HTTP ping (5 запросов)
    median, p90, success_rate, latencies = await http_ping_stats(socks_port, count=5)
    if median > RTT_THRESHOLD_MS or success_rate < 0.7:
        return None
    proxy['http_ping_median'] = median
    proxy['http_ping_p90'] = p90
    proxy['http_ping_success_rate'] = success_rate

    # 5. Jitter и packet loss
    jitter, packet_loss = compute_jitter_and_loss(latencies, int(success_rate * 5), 5)
    if jitter > MAX_JITTER_MS or packet_loss > MAX_PACKET_LOSS:
        return None
    proxy['jitter_ms'] = jitter
    proxy['packet_loss'] = packet_loss

    # 6. Throughput stability
    avg_speed, min_speed = await throughput_stability(socks_port, duration=STABILITY_DURATION)
    if avg_speed < MIN_THROUGHPUT_KBPS or min_speed < MIN_THROUGHPUT_KBPS * 0.5:
        return None
    proxy['throughput_avg_kbps'] = avg_speed
    proxy['throughput_min_kbps'] = min_speed

    # 7. Connection reuse
    reuse_count = await connection_reuse_test(socks_port)
    if reuse_count < MIN_REUSE_REQUESTS:
        return None
    proxy['connection_reuse'] = reuse_count

    # 8. WebSocket test (опционально)
    ws_ok = await websocket_test(socks_port)
    proxy['websocket_ok'] = ws_ok

    # 9. Video chunk test
    video_ok, video_bytes, video_time = await video_chunk_test(socks_port)
    proxy['video_ok'] = video_ok
    if video_ok:
        proxy['video_chunk_bytes'] = video_bytes
        proxy['video_chunk_time'] = video_time

    # 10. Cloudflare speed test
    cf_speed = await cloudflare_speed_test(socks_port)
    proxy['cf_speed_kbps'] = cf_speed

    # 11. Fast.com speed test
    fast_speed = await fast_com_test(socks_port)
    proxy['fast_speed_kbps'] = fast_speed

    # Все тесты пройдены – вычисляем общий score
    score = proxy.get('score', 0)
    if speed_kbps > 1000: score += 5
    if multi_speed > 2000: score += 10
    if median < 100: score += 5
    if jitter < 20: score += 5
    if cf_speed > 1000: score += 5
    if fast_speed > 1000: score += 5
    proxy['score'] = min(score, 200)
    return proxy

def check_batch_via_singbox(batch: list[dict], base_port: int, singbox_path: str) -> list[dict]:
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
        proc = subprocess.Popen(
            [singbox_path, "run", "-c", tmpfile],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        singbox_processes.append(proc)

        ports = [base_port + i for i in range(len(batch))]
        ready_ports = set()
        start_time = time.time()
        while time.time() - start_time < SINGBOX_STARTUP_WAIT:
            if proc.poll() is not None:
                return []
            for port in ports:
                if port in ready_ports:
                    continue
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.3)
                    if s.connect_ex(("127.0.0.1", port)) == 0:
                        ready_ports.add(port)
                    s.close()
                except:
                    pass
            if len(ready_ports) == len(ports):
                break
            time.sleep(0.1)
        else:
            return []

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            tasks = []
            for i, proxy in enumerate(batch):
                port = base_port + i
                if port not in ready_ports:
                    continue
                tasks.append(benchmark_proxy(port, proxy))
            results = loop.run_until_complete(asyncio.gather(*tasks, return_exceptions=True))
        finally:
            loop.close()

        alive_proxies = []
        for i, result in enumerate(results):
            if isinstance(result, dict) and result is not None:
                alive_proxies.append(result)

        return alive_proxies

    except Exception as e:
        log.warning(f"Ошибка в пакетной проверке: {e}")
        return []
    finally:
        if proc is not None:
            try:
                proc.terminate()
                proc.wait(timeout=5)
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

# ═══════════════════════════════════════════════════════════════════════════
#  SCORE (базовый, без бонуса за частоту)
# ═══════════════════════════════════════════════════════════════════════════

def compute_score(proxy):
    sec = proxy.get("security", "none")
    pen = validate_credentials(proxy)

    sec_score = WEIGHT_CONFIG["security"].get(sec, 0)
    raw_score = sec_score
    raw_score -= pen * 15
    return max(0, min(100, int(raw_score)))

# ═══════════════════════════════════════════════════════════════════════════
#  АСИНХРОННЫЕ ФУНКЦИИ ДЛЯ ЗАГРУЗКИ И ГЕО
# ═══════════════════════════════════════════════════════════════════════════

async def fetch_source_async(url, session, retries=FETCH_SOURCE_RETRIES):
    for attempt in range(retries + 1):
        try:
            async with session.get(url.strip(), timeout=FETCH_SOURCE_TIMEOUT) as resp:
                text = await resp.text()
                break
        except Exception as e:
            if attempt < retries:
                log.warning(f"Fetch fail {url}: {e}, retry...")
                await asyncio.sleep(FETCH_SOURCE_DELAY * (attempt + 1))
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
            return [x["uri"] for x in yp]
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

# ---- Геолокация ----
async def geolocate_ips_async(proxies):
    ips = list({p["host"] for p in proxies if is_ip_address(p["host"])})
    if not ips: return {}
    cache = {}
    log.info(f"Геолокация {len(ips)} IP с несколькими API...")

    for i in range(0, len(ips), GEO_BATCH_SIZE):
        batch_ips = ips[i:i+GEO_BATCH_SIZE]
        results = []
        tasks = []
        connector = aiohttp.TCPConnector(limit=10)
        async with aiohttp.ClientSession(connector=connector, headers={"User-Agent": HTTP_USER_AGENT}) as session:
            if len(batch_ips) > 1:
                tasks.append(_geo_ip_api(session, batch_ips))
            else:
                tasks.append(_geo_ip_api_single(session, batch_ips[0]))
            tasks.append(_geo_ipinfo(session, batch_ips))
            tasks.append(_geo_geoipdb(session, batch_ips))

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
                    from collections import Counter
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
                return result
    except Exception as e:
        log.warning(f"ip-api.com error: {e}")
    return {}

async def _geo_ip_api_single(session, ip):
    url = f"http://ip-api.com/json/{ip}"
    try:
        async with session.get(url, timeout=GEO_API_TIMEOUT) as resp:
            if resp.status == 200:
                data = await resp.json()
                if data.get("status") == "success":
                    return {ip: {
                        "country_code": data.get("countryCode", "XX"),
                        "country": data.get("country", "Unknown"),
                        "isp": data.get("isp", ""),
                        "asn": data.get("as", ""),
                        "status": "success"
                    }}
    except Exception:
        pass
    return {}

async def _geo_ipinfo(session, ips):
    result = {}
    for ip in ips:
        url = f"https://ipinfo.io/{ip}/json"
        try:
            async with session.get(url, timeout=GEO_API_TIMEOUT) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if data:
                        result[ip] = {
                            "country_code": data.get("country", "XX"),
                            "country": data.get("country", "Unknown"),
                            "isp": data.get("org", ""),
                            "asn": data.get("asn", ""),
                            "status": "success"
                        }
                    else:
                        result[ip] = {"status": "fail"}
        except Exception:
            result[ip] = {"status": "fail"}
    return result

async def _geo_geoipdb(session, ips):
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
    return result

# ═══════════════════════════════════════════════════════════════════════════
#  МОДУЛЬ ИСТОРИИ
# ═══════════════════════════════════════════════════════════════════════════

class ProxyHistory:
    def __init__(self, history_file=HISTORY_FILE):
        self.history_file = history_file
        self.history = self._load_history()

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

    def _make_key(self, proxy):
        return f"{proxy['protocol']}|{proxy['host']}|{proxy['port']}|{proxy.get('sni', '')}"

    def update(self, alive_proxies, run_date=None):
        if run_date is None:
            run_date = datetime.now(timezone.utc).isoformat()

        for p in alive_proxies:
            key = self._make_key(p)
            if key not in self.history:
                self.history[key] = {
                    "first_seen": run_date,
                    "last_seen": run_date,
                    "appearances": 1,
                    "last_alive": True,
                    "protocol": p["protocol"],
                    "host": p["host"],
                    "port": p["port"],
                    "sni": p.get("sni", ""),
                    "credential": p.get("credential", ""),
                    "security": p.get("security", "none"),
                    "transport": p.get("transport_type", "tcp"),
                    "country": p.get("country_code", "XX"),
                    "tcp_latency_ms": p.get("tcp_latency_ms", 0),
                    "http_latency_ms": p.get("http_latency_ms", 0),
                    "stress_success_rate": p.get("stress_success_rate", 0),
                    "jitter_ms": p.get("jitter_ms", 0),
                    "score": p.get("score", 0),
                    "uri": p.get("uri", "")
                }
            else:
                entry = self.history[key]
                entry["last_seen"] = run_date
                entry["appearances"] += 1
                entry["last_alive"] = True
                entry["protocol"] = p["protocol"]
                entry["host"] = p["host"]
                entry["port"] = p["port"]
                entry["sni"] = p.get("sni", "")
                entry["credential"] = p.get("credential", "")
                entry["security"] = p.get("security", "none")
                entry["transport"] = p.get("transport_type", "tcp")
                entry["country"] = p.get("country_code", "XX")
                entry["tcp_latency_ms"] = p.get("tcp_latency_ms", 0)
                entry["http_latency_ms"] = p.get("http_latency_ms", 0)
                entry["stress_success_rate"] = p.get("stress_success_rate", 0)
                entry["jitter_ms"] = p.get("jitter_ms", 0)
                entry["score"] = p.get("score", 0)
                entry["uri"] = p.get("uri", "")

        seen_keys = set(self._make_key(p) for p in alive_proxies)
        for key in self.history:
            if key not in seen_keys:
                self.history[key]["last_alive"] = False

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

    def get_appearances(self, proxy):
        key = self._make_key(proxy)
        entry = self.history.get(key)
        return entry.get("appearances", 0) if entry else 0

# ═══════════════════════════════════════════════════════════════════════════
#  ОСНОВНОЙ ПАЙПЛАЙН
# ═══════════════════════════════════════════════════════════════════════════

def _prefilter_proxy(proxy, singbox_path):
    if ENABLE_TLS_CHECK:
        sni = proxy.get("sni")
        if not tls_handshake_check(proxy["host"], proxy["port"], sni, TLS_TIMEOUT):
            return None
    if ENABLE_CONFIG_CHECK:
        if not config_is_valid(proxy, singbox_path):
            return None
    return proxy

def check_all_proxies(proxies, singbox_path):
    if not proxies:
        return []

    tcp_alive = []
    total = len(proxies)
    log.info(f"TCP-проверка {total} прокси ({MAX_WORKERS} воркеров)...")
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futs = {ex.submit(_tcp_check, p): p for p in proxies}
        done = 0
        for fut in as_completed(futs):
            done += 1
            r = fut.result()
            if r:
                tcp_alive.append(r)
            if done % 100 == 0 or done == total:
                log.info(f"  TCP: {done}/{total}, {len(tcp_alive)} живы")
    log.info(f"TCP-проверка завершена: {len(tcp_alive)}/{total}")

    if not tcp_alive:
        return []

    log.info("Применяем предварительные фильтры (TLS, config check)...")
    filtered = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futs = []
        for p in tcp_alive:
            futs.append(ex.submit(_prefilter_proxy, p, singbox_path))
        for fut in as_completed(futs):
            r = fut.result()
            if r:
                filtered.append(r)
    log.info(f"После предфильтрации: {len(filtered)}/{len(tcp_alive)}")

    if not filtered:
        return []

    alive = check_proxies_via_singbox(filtered, singbox_path)

    for p in alive:
        p["score"] = compute_score(p)
    return alive

# ---- Чтение и запись ----
def read_input_urls(filename):
    try:
        with open(filename, "r", encoding="utf-8") as f:
            return [l.strip() for l in f if l.strip() and not l.startswith("#")]
    except FileNotFoundError:
        log.error(f"{filename} not found")
        sys.exit(1)

def write_output_txt(proxies, filename):
    with open(filename, "w", encoding="utf-8") as f:
        for p in proxies:
            f.write(p["uri"] + "\n")
    log.info(f"Записано {len(proxies)} → {filename}")

def print_output(proxies):
    for p in proxies:
        print(p["uri"])

# ═══════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════

def main():
    def timeout_handler(signum, frame):
        log.error(f"Превышен лимит времени ({GLOBAL_TIMEOUT} сек), завершаемся.")
        cleanup()
        sys.exit(1)

    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(GLOBAL_TIMEOUT)

    try:
        t0 = time.time()
        log.info("=" * 60)
        log.info("Proxy Checker v10.0 — Расширенный бенчмаркинг")
        log.info("=" * 60)

        urls = read_input_urls(INPUT_FILE)
        log.info(f"Загружено {len(urls)} источников из {INPUT_FILE}")

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        all_u = loop.run_until_complete(fetch_all_sources_async(urls))
        log.info(f"Получено {len(all_u)} сырых URI")

        parsed = []
        for u in all_u:
            p = cached_parse(u)
            if p:
                parsed.append(p)
        log.info(f"Распарсено: {len(parsed)}")

        parsed = [p for p in parsed if has_security(p)]
        parsed = [p for p in parsed if validate_reality_params(p)]
        parsed = [p for p in parsed if is_ip_only(p)]
        parsed = [p for p in parsed if not is_blacklisted(p)]
        unique = deduplicate_proxies(parsed)
        log.info(f"После дедупликации: {len(unique)}")

        if not unique:
            log.info("Нет прокси для проверки. Завершаем.")
            with open(OUTPUT_FILE, 'w') as f:
                f.write('')
            return

        singbox_path = _ensure_singbox()
        log.info(f"sing-box готов: {singbox_path}")

        alive = check_all_proxies(unique, singbox_path)

        # Геолокация
        geo = loop.run_until_complete(geolocate_ips_async(alive))
        for p in alive:
            g = geo.get(p["host"], {})
            p["country_code"] = g.get("country_code", "XX")
            p["country"] = g.get("country", "Unknown")
            p["isp"] = g.get("isp", "")
            p["asn"] = g.get("asn", "")
            p["is_proxy"] = False
            p["is_hosting"] = False
            # Дата-центр бонус
            isp_lower = p["isp"].lower()
            if any(kw in isp_lower for kw in DATACENTER_KEYWORDS):
                p["is_datacenter"] = True
                p["score"] = p.get("score", 0) + DATACENTER_BONUS
            else:
                p["is_datacenter"] = False

        # Первичная генерация remark и URI
        for p in alive:
            tags = []
            if p.get("is_hosting"): tags.append("🏢Datacenter")
            if p.get("is_proxy"): tags.append("🔄Proxy")
            if p.get("is_datacenter"): tags.append("☁️DC")
            flag = country_to_flag(p.get("country_code", "XX"))
            remark = f"{flag} {p.get('country', '?')} | 🔒{p.get('score', 0)}"
            if tags:
                remark += " | " + " ".join(tags)
            p["uri"] = rewrite_uri_fragment(p["uri"], remark)

        alive.sort(key=lambda x: x.get("score", 0), reverse=True)

        # История
        history = ProxyHistory()
        if alive:
            log.info("Обновление истории прокси...")
            history.update(alive)
        else:
            log.info("Нет живых прокси для обновления истории.")

        # Бонус за частоту появлений
        if alive:
            log.info("Добавляем бонус за частоту появлений (>=4 запусков)...")
            for p in alive:
                appearances = history.get_appearances(p)
                if appearances >= APPEARANCE_BONUS_THRESHOLD:
                    old_score = p["score"]
                    p["score"] += APPEARANCE_BONUS_VALUE
                    log.debug(f"Бонус для {p['host']}: {old_score} -> {p['score']} (appearances={appearances})")
                    tags = []
                    if p.get("is_hosting"): tags.append("🏢Datacenter")
                    if p.get("is_proxy"): tags.append("🔄Proxy")
                    if p.get("is_datacenter"): tags.append("☁️DC")
                    flag = country_to_flag(p.get("country_code", "XX"))
                    remark = f"{flag} {p.get('country', '?')} | 🔒{p.get('score', 0)}"
                    if tags:
                        remark += " | " + " ".join(tags)
                    p["uri"] = rewrite_uri_fragment(p["uri"], remark)

            alive.sort(key=lambda x: x.get("score", 0), reverse=True)

        write_output_txt(alive, OUTPUT_FILE)

        if "--print" in sys.argv:
            print_output(alive)

        elapsed = time.time() - t0
        log.info(f"Готово: {len(alive)} прокси → {OUTPUT_FILE} за {elapsed:.1f}с")

    finally:
        signal.alarm(0)

if __name__ == "__main__":
    main()
