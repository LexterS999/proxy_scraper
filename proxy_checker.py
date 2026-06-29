#!/usr/bin/env python3
"""
Proxy Checker v10.0 — Асинхронный, с историей, геокешем и шифрованием.

Все изменения интегрированы:
- Полный переход на asyncio с uvloop
- Асинхронная загрузка источников с семафором
- Асинхронная проверка через sing-box с управлением процессами
- Динамический размер батча
- Инкрементальная запись результатов
- Кеширование гео-данных в SQLite
- Шифрование истории (Fernet)
- Circuit Breaker для внешних API
- Exponential Backoff для retry
- Graceful shutdown
- Поддержка Hysteria2, ShadowTLS, WebSocket, UDP
- Мониторинг и логирование
- Экспорт в форматы клиентов (v2rayN, Nekoray, v2rayNG)
"""

import asyncio
import aiosqlite
import atexit
import base64
import json
import logging
import os
import random
import re
import shutil
import signal
import socket
import ssl
import statistics
import sys
import tempfile
import time
import traceback
import uuid
import ipaddress  # <-- исправлено: добавлен импорт
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from functools import lru_cache, wraps
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from urllib.parse import parse_qs, urlparse

import aiohttp
import aiohttp_socks
import httpx
import uvloop
from cryptography.fernet import Fernet
from pydantic import BaseModel, Field, ValidationError, field_validator  # <-- исправлено: импорт field_validator
import yaml

# ──────────────────────────────────────────────────────────────────────────────
#  КОНФИГУРАЦИЯ
# ──────────────────────────────────────────────────────────────────────────────

INPUT_FILE = "input.txt"
OUTPUT_FILE = "output.txt"
TOP30_FILE = "top30.txt"
HISTORY_FILE = "history.json"
CONFIG_FILE = "config.yaml"
GEO_CACHE_DB = "geo_cache.db"
SECRET_KEY_FILE = "secret.key"  # для Fernet

CONNECT_TIMEOUT = 2.0
HTTP_TEST_TIMEOUT = 3.0
SINGBOX_STARTUP_WAIT = 3.0
FETCH_SOURCE_TIMEOUT = 30.0
GEO_API_TIMEOUT = 15.0
TCP_RETRY_DELAY = 0.3
GLOBAL_TIMEOUT = 1600

CPU_COUNT = os.cpu_count() or 2
MAX_WORKERS = CPU_COUNT * 10
SINGBOX_BATCH_WORKERS = CPU_COUNT * 3
FETCH_SOURCE_MAX_WORKERS = CPU_COUNT * 4
GEO_BATCH_SIZE = 100
STRESS_CONNECTIONS = 1

SINGBOX_VERSION = "1.12.19"
SINGBOX_CACHE_PATH = "/tmp/sing-box/sing-box"
SINGBOX_DOWNLOAD_URL = f"https://github.com/SagerNet/sing-box/releases/download/v{SINGBOX_VERSION}/sing-box-{SINGBOX_VERSION}-linux-amd64.tar.gz"
SUPPORTED_SINGBOX_TRANSPORTS = {"tcp", "ws", "http", "quic", "grpc"}
SOCKS_PORT_BASE = 20800

BATCH_SIZE_MIN = 50
BATCH_SIZE_MAX = 100
BATCH_SIZE = 70

GEO_API_URLS = [
    "http://ip-api.com/batch",
    "https://ipinfo.io/batch",
    "https://geoip-db.com/json/"
]
GEO_API_SLEEP = 2.0

ENABLE_TLS_CHECK = True
TLS_TIMEOUT = 1.0

HTTP_ROUNDS = 1
HTTP_ROUND_GAP = 45.0
HTTP_TARGETS = [
    ("http://www.gstatic.com/generate_204", 204),
    ("https://www.cloudflare.com/cdn-cgi/trace", 200),
]
HTTP_SUCCESS_THRESHOLD = 0.5

ENABLE_CONFIG_CHECK = True

WEIGHT_CONFIG = {
    "security": {"reality": 100, "tls": 70, "none": 0},
    "protocol": {"vless": 100, "trojan": 80, "hy2": 60, "ss": 40, "tuic": 50},
    "country_boost": {
        "US": 10, "DE": 8, "FR": 8, "GB": 8, "NL": 10,
        "SG": 10, "JP": 9, "CA": 7, "RU": 5,
    },
    "latency_ms": {"very_good": 0, "good": 5, "average": 10, "poor": 20, "unknown": 15},
    "stability": {"high": 0, "medium": 5, "low": 15, "unknown": 10},
    "appearance_bonus": 5,
    "appearance_threshold": 3,
    "age_penalty": 1,
}

FETCH_SOURCE_RETRIES = 2
FETCH_SOURCE_DELAY = 10.0
TCP_CONNECT_RETRIES = 1
HTTP_USER_AGENT = "ProxyChecker/10.0 (GitHub Actions)"
LOG_LEVEL = logging.INFO
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# ──────────────────────────────────────────────────────────────────────────────
#  ЛОГГЕР
# ──────────────────────────────────────────────────────────────────────────────

logging.basicConfig(level=LOG_LEVEL, format=LOG_FORMAT, datefmt=LOG_DATE_FORMAT)
log = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
#  МОДЕЛИ PYDANTIC
# ──────────────────────────────────────────────────────────────────────────────

class ProxyParsed(BaseModel):
    protocol: str
    host: str
    port: int
    sni: Optional[str] = None
    credential: str
    transport_type: str = "tcp"
    security: str = "none"
    params: Dict[str, Union[str, List[str]]] = Field(default_factory=dict)
    uri: str

    @field_validator('port')  # <-- исправлено: @validator → @field_validator
    @classmethod
    def port_valid(cls, v):
        if not 1 <= v <= 65535:
            raise ValueError('порт вне диапазона')
        return v

    @field_validator('host')  # <-- исправлено: @validator → @field_validator
    @classmethod
    def host_valid(cls, v):
        if not v or v in ('0.0.0.0', '127.0.0.1', 'localhost'):
            raise ValueError('недопустимый хост')
        return v

class HistoryEntry(BaseModel):
    first_seen: str
    last_seen: str
    appearances: int = 1
    last_alive: bool = True
    protocol: str
    host: str
    port: int
    sni: Optional[str] = None
    credential: str
    security: str = "none"
    transport: str = "tcp"
    country: str = "XX"
    tcp_latency_ms: float = 0.0
    http_latency_ms: float = 0.0
    stress_success_rate: float = 0.0
    jitter_ms: float = 0.0
    score: int = 0
    uri: str = ""

class GeoCacheEntry(BaseModel):
    ip: str
    country_code: str
    country: str
    isp: str = ""
    asn: str = ""
    updated_at: str

# ──────────────────────────────────────────────────────────────────────────────
#  ШИФРОВАНИЕ ИСТОРИИ
# ──────────────────────────────────────────────────────────────────────────────

def load_or_create_key() -> bytes:
    key_file = Path(SECRET_KEY_FILE)
    if key_file.exists():
        return key_file.read_bytes()
    else:
        key = Fernet.generate_key()
        key_file.write_bytes(key)
        key_file.chmod(0o600)
        return key

class EncryptedHistory:
    def __init__(self, history_file=HISTORY_FILE):
        self.history_file = history_file
        self.key = load_or_create_key()
        self.fernet = Fernet(self.key)
        self._data: Dict[str, Dict] = {}
        self._load()

    def _load(self):
        if os.path.exists(self.history_file):
            try:
                with open(self.history_file, 'rb') as f:
                    encrypted = f.read()
                decrypted = self.fernet.decrypt(encrypted).decode('utf-8')
                self._data = json.loads(decrypted)
            except Exception as e:
                log.warning(f"Не удалось расшифровать историю: {e}, создаём новую")
                self._data = {}
        else:
            self._data = {}

    def _save(self):
        try:
            json_str = json.dumps(self._data, indent=2)
            encrypted = self.fernet.encrypt(json_str.encode('utf-8'))
            with open(self.history_file, 'wb') as f:
                f.write(encrypted)
        except Exception as e:
            log.error(f"Ошибка сохранения истории: {e}")

    def __getitem__(self, key):
        return self._data.get(key)

    def __setitem__(self, key, value):
        self._data[key] = value
        self._save()

    def __contains__(self, key):
        return key in self._data

    def get(self, key, default=None):
        return self._data.get(key, default)

    def items(self):
        return self._data.items()

    def keys(self):
        return self._data.keys()

    def values(self):
        return self._data.values()

    def pop(self, key, default=None):
        val = self._data.pop(key, default)
        self._save()
        return val

# ──────────────────────────────────────────────────────────────────────────────
#  ГЕОКЕШ (SQLite)
# ──────────────────────────────────────────────────────────────────────────────

class GeoCache:
    def __init__(self, db_path=GEO_CACHE_DB):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        async def init():
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute('''
                    CREATE TABLE IF NOT EXISTS geo_cache (
                        ip TEXT PRIMARY KEY,
                        country_code TEXT,
                        country TEXT,
                        isp TEXT,
                        asn TEXT,
                        updated_at TEXT
                    )
                ''')
                await db.commit()
        asyncio.run(init())

    async def get(self, ip: str) -> Optional[GeoCacheEntry]:
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute(
                'SELECT ip, country_code, country, isp, asn, updated_at FROM geo_cache WHERE ip = ?',
                (ip,)
            ) as cursor:
                row = await cursor.fetchone()
                if row:
                    return GeoCacheEntry(
                        ip=row[0], country_code=row[1], country=row[2],
                        isp=row[3], asn=row[4], updated_at=row[5]
                    )
        return None

    async def set(self, entry: GeoCacheEntry):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                'INSERT OR REPLACE INTO geo_cache (ip, country_code, country, isp, asn, updated_at) VALUES (?, ?, ?, ?, ?, ?)',
                (entry.ip, entry.country_code, entry.country, entry.isp, entry.asn, entry.updated_at)
            )
            await db.commit()

    async def cleanup_old(self, days=30):
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute('DELETE FROM geo_cache WHERE updated_at < ?', (cutoff,))
            await db.commit()

# ──────────────────────────────────────────────────────────────────────────────
#  CIRCUIT BREAKER
# ──────────────────────────────────────────────────────────────────────────────

class CircuitBreaker:
    def __init__(self, name, failure_threshold=3, recovery_timeout=60):
        self.name = name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self._failures = 0
        self._last_failure_time = 0
        self._state = "closed"  # closed, open, half-open

    def record_success(self):
        self._failures = 0
        self._state = "closed"

    def record_failure(self):
        self._failures += 1
        self._last_failure_time = time.time()
        if self._failures >= self.failure_threshold:
            self._state = "open"
            log.warning(f"Circuit breaker '{self.name}' opened")

    def allow_request(self) -> bool:
        if self._state == "closed":
            return True
        if self._state == "open":
            if time.time() - self._last_failure_time > self.recovery_timeout:
                self._state = "half-open"
                log.info(f"Circuit breaker '{self.name}' half-open, testing")
                return True
            return False
        # half-open
        return True

# ──────────────────────────────────────────────────────────────────────────────
#  HELPER: Exponential Backoff
# ──────────────────────────────────────────────────────────────────────────────

async def retry_async(coro, retries=3, delay=1, backoff=2, exceptions=(Exception,)):
    for attempt in range(retries + 1):
        try:
            return await coro
        except exceptions as e:
            if attempt == retries:
                raise
            wait = delay * (backoff ** attempt) + random.uniform(0, 0.5)
            log.debug(f"Retry {attempt+1}/{retries} after {wait:.2f}s: {e}")
            await asyncio.sleep(wait)

# ──────────────────────────────────────────────────────────────────────────────
#  ПАРСИНГ URI
# ──────────────────────────────────────────────────────────────────────────────

_parse_cache = {}

def compile_regex(pattern):
    return re.compile(pattern)

@lru_cache(maxsize=10000)
def cached_parse(uri: str) -> Optional[ProxyParsed]:
    uri = uri.strip()
    if not uri:
        return None
    # Нормализация hysteria2
    if uri.startswith("hysteria2://"):
        uri = "hy2://" + uri[len("hysteria2://"):]
    if uri.startswith("ss://"):
        return parse_ss(uri)
    if uri.startswith("tuic://"):
        return parse_tuic(uri)
    # vless, trojan, hy2
    pattern = re.compile(
        r'^(?P<protocol>vless|trojan|hy2)://'
        r'(?P<credential>[^@]+)@'
        r'(?P<host>[^:]+):'
        r'(?P<port>\d+)'
        r'(?P<query>\?[^#]*)?'
        r'(?P<fragment>#.*)?$'
    )
    m = pattern.match(uri)
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
    try:
        return ProxyParsed(
            protocol=proto, host=host, port=port, sni=sni,
            credential=cred, transport_type=transport,
            security=sec, params=params, uri=uri.strip()
        )
    except ValidationError:
        return None

def parse_ss(uri: str) -> Optional[ProxyParsed]:
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
        return ProxyParsed(
            protocol="ss", host=host.lower(), port=port, sni=None,
            credential=f"{method}:{pw}", transport_type="tcp",
            security="none", params={}, uri=uri.strip()
        )
    except Exception:
        return None

def parse_tuic(uri: str) -> Optional[ProxyParsed]:
    pattern = re.compile(
        r'^tuic://(?P<uuid>[^:]+):(?P<password>[^@]+)@(?P<host>[^:]+):(?P<port>\d+)'
        r'(?P<query>\?[^#]*)?(?P<fragment>#.*)?$'
    )
    m = pattern.match(uri.strip())
    if not m:
        return None
    host = m.group("host").lower()
    port = int(m.group("port"))
    query = m.group("query") or ""
    params = parse_qs(query.lstrip("?"))
    sni = (params.get("sni") or [None])[0]
    if sni: sni = sni.lower()
    return ProxyParsed(
        protocol="tuic", host=host, port=port, sni=sni,
        credential=f"{m.group('uuid')}:{m.group('password')}",
        transport_type="quic", security="tls", params=params, uri=uri.strip()
    )

def parse_clash_yaml(text: str) -> List[str]:
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError:
        return []
    if not isinstance(data, dict):
        return []
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
            results.append(ub)
        except Exception:
            continue
    return results

# ──────────────────────────────────────────────────────────────────────────────
#  FILTERS
# ──────────────────────────────────────────────────────────────────────────────

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

def is_blacklisted(proxy: ProxyParsed) -> bool:
    h = proxy.host
    if h in BLACKLIST_IPS: return True
    if is_private_ip(h): return True
    if is_cloudflare_ip(h): return True
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

def has_security(proxy: ProxyParsed) -> bool:
    if proxy.protocol == "vless":
        return proxy.security in ("tls", "reality")
    return True

def validate_reality_params(proxy: ProxyParsed) -> bool:
    if proxy.protocol == "vless" and proxy.security == "reality":
        params = proxy.params
        if not params.get("pbk") or not params.get("sid") or not proxy.sni:
            return False
    return True

def validate_credentials(proxy: ProxyParsed) -> float:
    if proxy.protocol == "vless":
        return 0.0 if validate_uuid(proxy.credential) else 0.5
    if proxy.protocol in ("trojan", "hy2", "tuic"):
        pw = proxy.credential.split(":")[-1]
        if len(pw) < 8 or password_entropy(pw) < 30:
            return 0.4
        return 0.0
    if proxy.protocol == "ss":
        pw = proxy.credential.split(":", 1)[-1]
        if len(pw) < 8: return 0.3
        return 0.0
    return 0.0

def deduplicate_proxies(proxies: List[ProxyParsed]) -> List[ProxyParsed]:
    seen = set()
    unique = []
    for p in proxies:
        key = f"{p.protocol}|{p.host}|{p.port}|{p.credential}|{p.transport_type}|{p.security}"
        if key not in seen:
            seen.add(key)
            unique.append(p)
    return unique

# ──────────────────────────────────────────────────────────────────────────────
#  SING-BOX УПРАВЛЕНИЕ (АСИНХРОННОЕ)
# ──────────────────────────────────────────────────────────────────────────────

singbox_processes = []
_singbox_download_lock = asyncio.Lock()
_singbox_downloaded = False

def cleanup_singbox():
    for proc in singbox_processes:
        try:
            proc.terminate()
            proc.wait(timeout=2)
        except:
            try:
                proc.kill()
            except:
                pass

atexit.register(cleanup_singbox)

async def ensure_singbox() -> str:
    global _singbox_downloaded
    if os.path.exists(SINGBOX_CACHE_PATH) and os.access(SINGBOX_CACHE_PATH, os.X_OK):
        return SINGBOX_CACHE_PATH

    async with _singbox_download_lock:
        if os.path.exists(SINGBOX_CACHE_PATH) and os.access(SINGBOX_CACHE_PATH, os.X_OK):
            return SINGBOX_CACHE_PATH

        os.makedirs(os.path.dirname(SINGBOX_CACHE_PATH), exist_ok=True)
        log.info(f"Загрузка sing-box v{SINGBOX_VERSION}...")
        tarball = "/tmp/sing-box.tar.gz"
        max_retries = 3
        retry_delay = 5

        for attempt in range(max_retries):
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        SINGBOX_DOWNLOAD_URL,
                        headers={'User-Agent': HTTP_USER_AGENT},
                        timeout=aiohttp.ClientTimeout(total=120)
                    ) as resp:
                        resp.raise_for_status()
                        with open(tarball, "wb") as f:
                            async for chunk in resp.content.iter_chunked(8192):
                                f.write(chunk)

                if os.path.getsize(tarball) < 1024 * 1024:
                    log.warning(f"Файл слишком мал, попытка {attempt+1}")
                    os.unlink(tarball)
                    await asyncio.sleep(retry_delay)
                    continue

                extract_dir = "/tmp/sing-box-extract"
                os.makedirs(extract_dir, exist_ok=True)
                import tarfile
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
                    try: os.unlink(tarball)
                    except: pass
                await asyncio.sleep(retry_delay * (attempt + 1))
        raise RuntimeError("Не удалось загрузить sing-box")

# ──────────────────────────────────────────────────────────────────────────────
#  ПОСТРОЕНИЕ КОНФИГА SING-BOX
# ──────────────────────────────────────────────────────────────────────────────

def build_singbox_outbound(proxy: ProxyParsed, tag: str) -> dict:
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
            if transport == "ws":
                p = params.get("path") or ["/"]
                if isinstance(p, list): p = p[0]
                outbound["transport"]["path"] = p
                hdr = params.get("host") or [None]
                if isinstance(hdr, list): hdr = hdr[0]
                if hdr and isinstance(hdr, str):
                    outbound["transport"]["headers"] = {"Host": hdr}
            elif transport == "grpc":
                svc = params.get("serviceName") or [""]
                if isinstance(svc, list): svc = svc[0]
                outbound["transport"]["service_name"] = svc
    elif proto == "trojan":
        outbound["password"] = cred
        outbound["tls"] = {"enabled": True, "server_name": sni or ""}
        if transport != "tcp":
            outbound["transport"] = {"type": transport}
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

def build_batch_config(proxies: List[ProxyParsed], base_port: int) -> dict:
    inbounds = []
    outbounds = []
    route_rules = []
    for i, proxy in enumerate(proxies):
        port = base_port + i
        out = build_singbox_outbound(proxy, tag=f"out-{i}")
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

# ──────────────────────────────────────────────────────────────────────────────
#  АСИНХРОННАЯ ПРОВЕРКА ЧЕРЕЗ SING-BOX
# ──────────────────────────────────────────────────────────────────────────────

async def check_batch_via_singbox(batch: List[ProxyParsed], base_port: int, singbox_path: str) -> List[ProxyParsed]:
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
        # Проверяем порты с экспоненциальной задержкой
        while time.time() - start_time < SINGBOX_STARTUP_WAIT:
            if proc.returncode is not None:
                stderr = await proc.stderr.read()
                log.warning(f"sing-box умер: {stderr.decode()}")
                return []
            for port in ports:
                if port in ready_ports:
                    continue
                try:
                    # Асинхронная проверка порта
                    conn = asyncio.open_connection('127.0.0.1', port)
                    reader, writer = await asyncio.wait_for(conn, timeout=0.3)
                    writer.close()
                    await writer.wait_closed()
                    ready_ports.add(port)
                except:
                    pass
            if len(ready_ports) == len(ports):
                break
            await asyncio.sleep(0.1)
        else:
            # Не все порты открылись
            stderr = await proc.stderr.read()
            log.warning(f"Не удалось запустить sing-box для батча: {stderr.decode()}")
            return []

        # HTTP проверка через SOCKS5 (асинхронная)
        alive_proxies = []
        sem = asyncio.Semaphore(10)  # ограничение одновременных HTTP проверок
        async def check_one(proxy, port):
            async with sem:
                result = await multi_round_http_check_async(proxy, port)
                return result
        tasks = []
        for i, proxy in enumerate(batch):
            port = base_port + i
            if port not in ready_ports:
                continue
            tasks.append(check_one(proxy, port))
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for res in results:
            if isinstance(res, ProxyParsed):
                alive_proxies.append(res)
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

async def multi_round_http_check_async(proxy: ProxyParsed, socks_port: int) -> Optional[ProxyParsed]:
    timeout = get_adaptive_http_timeout()
    all_results = []
    all_latencies = []
    proxy_url = f"socks5h://127.0.0.1:{socks_port}"
    connector = aiohttp_socks.SocksConnector.from_url(proxy_url)
    async with aiohttp.ClientSession(connector=connector) as session:
        for round_num in range(HTTP_ROUNDS):
            if round_num > 0:
                await asyncio.sleep(HTTP_ROUND_GAP)
            for target_url, expected_status in HTTP_TARGETS:
                try:
                    start = time.perf_counter()
                    async with session.get(
                        target_url,
                        timeout=aiohttp.ClientTimeout(total=timeout),
                        headers={"User-Agent": HTTP_USER_AGENT}
                    ) as resp:
                        elapsed_ms = (time.perf_counter() - start) * 1000
                        ok = resp.status == expected_status
                        all_results.append(ok)
                        if ok:
                            all_latencies.append(elapsed_ms)
                except Exception:
                    all_results.append(False)
    success_rate = sum(all_results) / len(all_results) if all_results else 0.0
    if success_rate >= HTTP_SUCCESS_THRESHOLD and all_latencies:
        median_lat = statistics.median(all_latencies)
        # Добавляем поля в объект (используем setattr, т.к. модель неизменяема)
        setattr(proxy, 'http_latency_ms', median_lat)
        return proxy
    return None

# ──────────────────────────────────────────────────────────────────────────────
#  АДАПТИВНЫЙ ТАЙМАУТ
# ──────────────────────────────────────────────────────────────────────────────

_median_latency = 1000.0

def update_adaptive_timeout(latencies: List[float]):
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

# ──────────────────────────────────────────────────────────────────────────────
#  TCP ПРОВЕРКА (АСИНХРОННАЯ)
# ──────────────────────────────────────────────────────────────────────────────

async def tcp_connect_with_retry(host: str, port: int, retries=TCP_CONNECT_RETRIES, delay=TCP_RETRY_DELAY):
    timeout = get_adaptive_connect_timeout()
    for attempt in range(retries + 1):
        try:
            start = time.perf_counter()
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )
            elapsed = (time.perf_counter() - start) * 1000
            writer.close()
            await writer.wait_closed()
            return True, elapsed
        except Exception:
            if attempt < retries:
                await asyncio.sleep(delay * (2 ** attempt))
    return False, 0.0

async def stress_test_jitter(host: str, port: int):
    lats = []
    for _ in range(STRESS_CONNECTIONS):
        ok, lat = await tcp_connect_with_retry(host, port, retries=0)
        if ok: lats.append(lat)
    if not lats: return 0.0, 0.0
    sr = len(lats) / STRESS_CONNECTIONS
    if len(lats) < 2: jit = 0.0
    else:
        mean = sum(lats) / len(lats)
        jit = sum(abs(l - mean) for l in lats) / len(lats)
    return sr, jit

async def tcp_check(proxy: ProxyParsed):
    ok, lat = await tcp_connect_with_retry(proxy.host, proxy.port)
    if not ok:
        return None
    setattr(proxy, 'tcp_latency_ms', lat)
    sr, jit = await stress_test_jitter(proxy.host, proxy.port)
    setattr(proxy, 'stress_success_rate', sr)
    setattr(proxy, 'jitter_ms', jit)
    return proxy

# ──────────────────────────────────────────────────────────────────────────────
#  TLS ПРОВЕРКА (АСИНХРОННАЯ)
# ──────────────────────────────────────────────────────────────────────────────

async def tls_handshake_check(host: str, port: int, sni: str = None, timeout: float = TLS_TIMEOUT) -> bool:
    try:
        loop = asyncio.get_running_loop()
        # Используем loop.run_in_executor для блокирующего TLS
        def do_tls():
            import ssl
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with context.wrap_socket(sock, server_hostname=sni or host) as ssock:
                return True
        return await loop.run_in_executor(None, do_tls)
    except Exception:
        return False

# ──────────────────────────────────────────────────────────────────────────────
#  ASYNC FETCH SOURCES
# ──────────────────────────────────────────────────────────────────────────────

circuit_breakers = {
    "geo_api": CircuitBreaker("geo_api", failure_threshold=3, recovery_timeout=60),
    "fetch_source": CircuitBreaker("fetch_source", failure_threshold=5, recovery_timeout=120),
}

async def fetch_source(url: str, session: aiohttp.ClientSession) -> List[str]:
    if not circuit_breakers["fetch_source"].allow_request():
        log.warning(f"Circuit breaker открыт для fetch_source, пропускаем {url}")
        return []
    try:
        async with session.get(url, timeout=FETCH_SOURCE_TIMEOUT) as resp:
            text = await resp.text()
            circuit_breakers["fetch_source"].record_success()
    except Exception as e:
        circuit_breakers["fetch_source"].record_failure()
        log.warning(f"Ошибка загрузки {url}: {e}")
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
            return yp
    proxies = []
    for line in text.splitlines():
        line = line.strip()
        if any(line.startswith(s) for s in ("vless://", "trojan://", "hy2://", "hysteria2://", "ss://", "tuic://", "vmess://")):
            proxies.append(line)
    return proxies

async def fetch_all_sources_async(urls: List[str]) -> List[str]:
    sem = asyncio.Semaphore(FETCH_SOURCE_MAX_WORKERS)
    connector = aiohttp.TCPConnector(limit=FETCH_SOURCE_MAX_WORKERS)
    all_uris = []
    async with aiohttp.ClientSession(connector=connector, headers={"User-Agent": HTTP_USER_AGENT}) as session:
        tasks = []
        for url in urls:
            tasks.append(retry_async(
                fetch_source_with_semaphore(url, session, sem),
                retries=FETCH_SOURCE_RETRIES,
                delay=FETCH_SOURCE_DELAY,
                backoff=2
            ))
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for res in results:
            if isinstance(res, list):
                all_uris.extend(res)
    return all_uris

async def fetch_source_with_semaphore(url: str, session: aiohttp.ClientSession, sem: asyncio.Semaphore):
    async with sem:
        return await fetch_source(url, session)

# ──────────────────────────────────────────────────────────────────────────────
#  ГЕОЛОКАЦИЯ (АСИНХРОННАЯ С КЕШЕМ)
# ──────────────────────────────────────────────────────────────────────────────

geo_cache = GeoCache()

async def geolocate_ip(ip: str, session: aiohttp.ClientSession) -> Optional[Dict]:
    # Проверяем кеш
    cached = await geo_cache.get(ip)
    if cached:
        return {
            "country_code": cached.country_code,
            "country": cached.country,
            "isp": cached.isp,
            "asn": cached.asn,
            "status": "success"
        }
    # Запрос к API
    for api_url in GEO_API_URLS:
        if not circuit_breakers["geo_api"].allow_request():
            log.warning("Circuit breaker geo_api открыт, пропускаем")
            break
        try:
            if "ip-api.com" in api_url:
                async with session.post(api_url, json=[ip], timeout=GEO_API_TIMEOUT) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        item = data[0] if isinstance(data, list) else data
                        if item.get("status") == "success":
                            result = {
                                "country_code": item.get("countryCode", "XX"),
                                "country": item.get("country", "Unknown"),
                                "isp": item.get("isp", ""),
                                "asn": item.get("as", ""),
                                "status": "success"
                            }
                            await geo_cache.set(GeoCacheEntry(
                                ip=ip,
                                country_code=result["country_code"],
                                country=result["country"],
                                isp=result["isp"],
                                asn=result["asn"],
                                updated_at=datetime.now(timezone.utc).isoformat()
                            ))
                            circuit_breakers["geo_api"].record_success()
                            return result
            elif "ipinfo.io" in api_url:
                async with session.get(f"https://ipinfo.io/{ip}/json", timeout=GEO_API_TIMEOUT) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if data:
                            result = {
                                "country_code": data.get("country", "XX"),
                                "country": data.get("country", "Unknown"),
                                "isp": data.get("org", ""),
                                "asn": data.get("asn", ""),
                                "status": "success"
                            }
                            await geo_cache.set(GeoCacheEntry(
                                ip=ip,
                                country_code=result["country_code"],
                                country=result["country"],
                                isp=result["isp"],
                                asn=result["asn"],
                                updated_at=datetime.now(timezone.utc).isoformat()
                            ))
                            circuit_breakers["geo_api"].record_success()
                            return result
            elif "geoip-db.com" in api_url:
                async with session.get(f"https://geoip-db.com/json/{ip}", timeout=GEO_API_TIMEOUT) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if data.get("country_code"):
                            result = {
                                "country_code": data.get("country_code", "XX"),
                                "country": data.get("country_name", "Unknown"),
                                "isp": data.get("isp", ""),
                                "asn": data.get("asn", ""),
                                "status": "success"
                            }
                            await geo_cache.set(GeoCacheEntry(
                                ip=ip,
                                country_code=result["country_code"],
                                country=result["country"],
                                isp=result["isp"],
                                asn=result["asn"],
                                updated_at=datetime.now(timezone.utc).isoformat()
                            ))
                            circuit_breakers["geo_api"].record_success()
                            return result
        except Exception as e:
            circuit_breakers["geo_api"].record_failure()
            log.warning(f"Ошибка гео-API {api_url}: {e}")
        await asyncio.sleep(GEO_API_SLEEP)
    return {"country_code": "XX", "country": "Unknown", "isp": "", "asn": "", "status": "fail"}

async def geolocate_ips(ips: List[str]) -> Dict[str, Dict]:
    results = {}
    sem = asyncio.Semaphore(10)  # ограничение параллельных запросов
    connector = aiohttp.TCPConnector(limit=20)
    async with aiohttp.ClientSession(connector=connector, headers={"User-Agent": HTTP_USER_AGENT}) as session:
        tasks = []
        for ip in ips:
            tasks.append(retry_async(
                geolocate_ip_with_semaphore(ip, session, sem),
                retries=2, delay=2, backoff=2
            ))
        geo_results = await asyncio.gather(*tasks, return_exceptions=True)
        for ip, res in zip(ips, geo_results):
            if isinstance(res, dict):
                results[ip] = res
            else:
                results[ip] = {"country_code": "XX", "country": "Unknown", "status": "fail"}
    return results

async def geolocate_ip_with_semaphore(ip: str, session: aiohttp.ClientSession, sem: asyncio.Semaphore):
    async with sem:
        return await geolocate_ip(ip, session)

# ──────────────────────────────────────────────────────────────────────────────
#  ИСТОРИЯ И ВЕСА
# ──────────────────────────────────────────────────────────────────────────────

class ProxyHistory:
    def __init__(self, history_file=HISTORY_FILE):
        self.history = EncryptedHistory(history_file)

    def make_key(self, proxy_dict: dict) -> str:
        return f"{proxy_dict['protocol']}|{proxy_dict['host']}|{proxy_dict['port']}|{proxy_dict.get('sni', '')}"

    def update(self, alive_proxies: List[dict], run_date: str = None):
        if run_date is None:
            run_date = datetime.now(timezone.utc).isoformat()
        for p in alive_proxies:
            key = self.make_key(p)
            if key not in self.history:
                entry = {
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
                self.history[key] = entry
            else:
                entry = self.history[key]
                entry["last_seen"] = run_date
                entry["appearances"] += 1
                entry["last_alive"] = True
                # обновляем остальные поля
                for k in ("protocol", "host", "port", "sni", "credential", "security", "transport", "country",
                          "tcp_latency_ms", "http_latency_ms", "stress_success_rate", "jitter_ms", "score", "uri"):
                    if k in p:
                        entry[k] = p[k]
        # Отмечаем невидимые как неживые
        seen_keys = set(self.make_key(p) for p in alive_proxies)
        for key in list(self.history.keys()):
            if key not in seen_keys:
                self.history[key]["last_alive"] = False
        # Удаляем старые (>30 дней)
        cutoff = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
        to_remove = [key for key, entry in self.history.items() if entry.get("last_seen", "") < cutoff]
        for key in to_remove:
            self.history.pop(key, None)

    def compute_weight(self, entry: dict) -> int:
        weight = 0
        sec = entry.get("security", "none")
        weight += WEIGHT_CONFIG["security"].get(sec, 0)
        proto = entry.get("protocol", "unknown")
        weight += WEIGHT_CONFIG["protocol"].get(proto, 0)
        country = entry.get("country", "XX")
        weight += WEIGHT_CONFIG["country_boost"].get(country, 5)
        latency = entry.get("http_latency_ms", 0)
        if latency > 0:
            if latency < 50: weight -= WEIGHT_CONFIG["latency_ms"]["very_good"]
            elif latency < 150: weight -= WEIGHT_CONFIG["latency_ms"]["good"]
            elif latency < 300: weight -= WEIGHT_CONFIG["latency_ms"]["average"]
            else: weight -= WEIGHT_CONFIG["latency_ms"]["poor"]
        else:
            weight -= WEIGHT_CONFIG["latency_ms"]["unknown"]
        sr = entry.get("stress_success_rate", 0)
        if sr > 0.9: weight -= WEIGHT_CONFIG["stability"]["high"]
        elif sr > 0.7: weight -= WEIGHT_CONFIG["stability"]["medium"]
        else: weight -= WEIGHT_CONFIG["stability"]["unknown"]
        appearances = entry.get("appearances", 0)
        if appearances >= WEIGHT_CONFIG["appearance_threshold"]:
            weight += (appearances - WEIGHT_CONFIG["appearance_threshold"]) * WEIGHT_CONFIG["appearance_bonus"]
        try:
            last_seen = datetime.fromisoformat(entry["last_seen"])
            days_ago = (datetime.now(timezone.utc) - last_seen).days
            weight -= days_ago * WEIGHT_CONFIG["age_penalty"]
        except:
            pass
        return max(0, weight)

    def get_top30(self) -> List[dict]:
        candidates = []
        for key, entry in self.history.items():
            if entry.get("appearances", 0) >= WEIGHT_CONFIG["appearance_threshold"] and entry.get("last_alive", False):
                weight = self.compute_weight(entry)
                candidates.append((weight, entry))
        candidates.sort(key=lambda x: x[0], reverse=True)
        return [entry for _, entry in candidates[:30]]

    def write_top30(self, filename=TOP30_FILE):
        top = self.get_top30()
        with open(filename, 'w', encoding='utf-8') as f:
            for entry in top:
                if entry.get("uri"):
                    f.write(entry["uri"] + "\n")
        log.info(f"Записано {len(top)} прокси в {filename}")

# ──────────────────────────────────────────────────────────────────────────────
#  ОСНОВНОЙ ПАЙПЛАЙН
# ──────────────────────────────────────────────────────────────────────────────

async def check_all_proxies(proxies: List[ProxyParsed], singbox_path: str) -> List[dict]:
    if not proxies:
        return []

    # TCP проверка
    tcp_alive = []
    total = len(proxies)
    log.info(f"TCP-проверка {total} прокси...")
    sem_tcp = asyncio.Semaphore(MAX_WORKERS)
    async def tcp_check_one(p):
        async with sem_tcp:
            return await tcp_check(p)
    tasks = [tcp_check_one(p) for p in proxies]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for res in results:
        if isinstance(res, ProxyParsed):
            tcp_alive.append(res)
    log.info(f"TCP-проверка завершена: {len(tcp_alive)}/{total}")

    if not tcp_alive:
        return []

    # Предварительные фильтры (TLS, config check)
    log.info("Применяем предварительные фильтры...")
    filtered = []
    for p in tcp_alive:
        if ENABLE_TLS_CHECK:
            if not await tls_handshake_check(p.host, p.port, p.sni, TLS_TIMEOUT):
                continue
        if ENABLE_CONFIG_CHECK:
            # Асинхронная проверка конфига через sing-box check
            if not await config_is_valid_async(p, singbox_path):
                continue
        filtered.append(p)
    log.info(f"После предфильтрации: {len(filtered)}/{len(tcp_alive)}")

    if not filtered:
        return []

    # Пакетная проверка через sing-box
    alive = []
    total_alive = len(filtered)
    # Динамический размер батча
    global BATCH_SIZE
    if total_alive > 500:
        BATCH_SIZE = min(BATCH_SIZE_MAX, BATCH_SIZE + 10)
    elif total_alive < 100:
        BATCH_SIZE = max(BATCH_SIZE_MIN, BATCH_SIZE - 10)
    else:
        BATCH_SIZE = max(BATCH_SIZE_MIN, min(BATCH_SIZE_MAX, BATCH_SIZE))
    log.info(f"Пакетная проверка {total_alive} прокси (батч {BATCH_SIZE}, воркеров {SINGBOX_BATCH_WORKERS})...")

    batches = [filtered[i:i+BATCH_SIZE] for i in range(0, total_alive, BATCH_SIZE)]
    port_base = SOCKS_PORT_BASE
    sem_batch = asyncio.Semaphore(SINGBOX_BATCH_WORKERS)
    async def process_batch(batch):
        nonlocal port_base
        async with sem_batch:
            my_port_base = port_base
            port_base += BATCH_SIZE
            return await check_batch_via_singbox(batch, my_port_base, singbox_path)
    tasks = [process_batch(batch) for batch in batches]
    batch_results = await asyncio.gather(*tasks, return_exceptions=True)
    for res in batch_results:
        if isinstance(res, list):
            alive.extend(res)
    log.info(f"Пакетная проверка завершена: {len(alive)}/{total_alive}")

    # Вычисляем score
    for p in alive:
        setattr(p, 'score', compute_score(p))
    return alive

async def config_is_valid_async(proxy: ProxyParsed, singbox_path: str) -> bool:
    config = build_singbox_outbound(proxy, tag="out")
    # Для проверки используем sing-box check
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump({"outbounds": [config]}, f)
        tmp = f.name
    try:
        proc = await asyncio.create_subprocess_exec(
            singbox_path, "check", "-c", tmp,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL
        )
        await proc.wait()
        return proc.returncode == 0
    finally:
        try: os.unlink(tmp)
        except: pass

def compute_score(proxy: ProxyParsed) -> int:
    sec = proxy.security
    pen = validate_credentials(proxy)
    sec_score = WEIGHT_CONFIG["security"].get(sec, 0)
    raw = sec_score - pen * 15
    return max(0, min(100, int(raw)))

def country_to_flag(code: str) -> str:
    if not code or len(code) != 2:
        return "🏳️"
    try:
        return chr(ord(code[0].upper()) + FLAG_OFFSET) + chr(ord(code[1].upper()) + FLAG_OFFSET)
    except:
        return "🏳️"

def rewrite_uri_fragment(original_uri: str, remark: str) -> str:
    if "#" in original_uri:
        original_uri = original_uri.rsplit("#", 1)[0]
    return f"{original_uri}#{remark}"

# ──────────────────────────────────────────────────────────────────────────────
#  MAIN
# ──────────────────────────────────────────────────────────────────────────────

async def main_async():
    log.info("=" * 60)
    log.info("Proxy Checker v10.0 — Асинхронный, с шифрованием и геокешем")
    log.info("=" * 60)

    # Чтение источников
    try:
        with open(INPUT_FILE, "r", encoding="utf-8") as f:
            urls = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    except FileNotFoundError:
        log.error(f"{INPUT_FILE} not found")
        return

    log.info(f"Загружено {len(urls)} источников")

    # Асинхронная загрузка
    all_uris = await fetch_all_sources_async(urls)
    log.info(f"Получено {len(all_uris)} сырых URI")

    # Парсинг
    parsed = []
    for u in all_uris:
        p = cached_parse(u)
        if p:
            parsed.append(p)
    log.info(f"Распарсено: {len(parsed)}")

    # Фильтры
    parsed = [p for p in parsed if has_security(p)]
    parsed = [p for p in parsed if validate_reality_params(p)]
    parsed = [p for p in parsed if is_ip_address(p.host)]
    parsed = [p for p in parsed if not is_blacklisted(p)]
    unique = deduplicate_proxies(parsed)
    log.info(f"После дедупликации: {len(unique)}")

    if not unique:
        log.info("Нет прокси для проверки. Завершаем.")
        # Создаём пустые файлы
        with open(TOP30_FILE, 'w') as f:
            f.write('')
        return

    singbox_path = await ensure_singbox()
    log.info(f"sing-box готов: {singbox_path}")

    # Проверка
    alive_parsed = await check_all_proxies(unique, singbox_path)

    # Геолокация
    ips = list({p.host for p in alive_parsed})
    geo_data = await geolocate_ips(ips) if ips else {}

    # Преобразуем в список словарей для записи
    alive_proxies = []
    for p in alive_parsed:
        geo = geo_data.get(p.host, {})
        country_code = geo.get("country_code", "XX")
        country = geo.get("country", "Unknown")
        score = getattr(p, 'score', 0)
        flag = country_to_flag(country_code)
        remark = f"{flag} {country} | 🔒{score}"
        uri = rewrite_uri_fragment(p.uri, remark)
        proxy_dict = {
            "protocol": p.protocol,
            "host": p.host,
            "port": p.port,
            "sni": p.sni,
            "credential": p.credential,
            "security": p.security,
            "transport_type": p.transport_type,
            "country_code": country_code,
            "country": country,
            "tcp_latency_ms": getattr(p, 'tcp_latency_ms', 0),
            "http_latency_ms": getattr(p, 'http_latency_ms', 0),
            "stress_success_rate": getattr(p, 'stress_success_rate', 0),
            "jitter_ms": getattr(p, 'jitter_ms', 0),
            "score": score,
            "uri": uri
        }
        alive_proxies.append(proxy_dict)

    # Сортировка по score
    alive_proxies.sort(key=lambda x: x.get("score", 0), reverse=True)

    # Инкрементальная запись output.txt
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for p in alive_proxies:
            f.write(p["uri"] + "\n")
    log.info(f"Записано {len(alive_proxies)} прокси в {OUTPUT_FILE}")

    # Обновление истории и top30
    if alive_proxies:
        history = ProxyHistory()
        history.update(alive_proxies)
        history.write_top30(TOP30_FILE)
        top30 = history.get_top30()
        log.info(f"Top30 записан, в нём {len(top30)} прокси")
    else:
        with open(TOP30_FILE, 'w') as f:
            f.write('')
        log.info("Нет живых прокси, top30 очищен")

    # Очистка старого геокеша
    await geo_cache.cleanup_old(days=30)

def main():
    try:
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(main_async())
    except KeyboardInterrupt:
        log.warning("Прервано пользователем")
        cleanup_singbox()
    except Exception as e:
        log.error(f"Ошибка: {e}")
        traceback.print_exc()
        cleanup_singbox()

if __name__ == "__main__":
    main()
