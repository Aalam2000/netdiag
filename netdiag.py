#!/usr/bin/env python3
"""
NetDiag — мониторинг роутера и интернета с проводного сервера.

Режимы:
    python netdiag.py                    — сбор данных (бесконечно)
    python netdiag.py report             — отчёт по всем накопленным данным
                                           (report.txt и report.html с графиками)
    python netdiag.py report --since 2026-10-12 --until 2026-10-19

Что измеряется каждые INTERVAL_SEC секунд:
    * TCP-подключение к роутеру по локальной сети (жив ли он и как быстро отвечает);
    * DNS-запрос к роутеру (работает ли его DNS-прокси);
    * TCP-подключение к внешним ресурсам (идёт ли трафик наружу).
Раз в DEVICE_SCAN_SEC секунд считается число устройств в локальной сети —
это объективная мера нагрузки, с которой сопоставляются сбои.
"""
import fcntl
import glob
import gzip
import ipaddress
import json
import logging
import os
import random
import re
import signal
import socket
import statistics
import struct
import sys
import threading
import time
import urllib.request
from array import array
from collections import Counter, defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutTimeout
from datetime import date, datetime, timedelta
from zoneinfo import ZoneInfo

TZ = ZoneInfo("Asia/Baku")

# ==== КОНФИГ ====
GATEWAY = "192.168.0.1"          # главный роутер

# Что известно о сети академии (установлено 11.10.26, влияет на формулировки
# отчёта):
#  - устройствам по DHCP выдаётся DNS 8.8.8.8, DNS роутера они не используют;
#  - дополнительный роутер раздаёт свою подсеть (двойной NAT), устройства за
#    ним серверу не видны.
CLIENTS_USE_ROUTER_DNS = False
HIDDEN_SUBNETS = ["192.168.1.0/24"]
LAN_NET = "192.168.0.0/24"       # локальная сеть (для подсчёта устройств)

# (имя, тип, хост, порт). Имена gw_* — роутер, остальные — внешние ресурсы.
LOCAL_TARGETS = [
    ("gw_80",  "tcp", GATEWAY, 80),
    ("gw_443", "tcp", GATEWAY, 443),
]
ROUTER_DNS_TARGETS = [
    ("gw_dns", "dns", GATEWAY, 53),      # DNS-прокси роутера
]
# Контрольный DNS: тот же запрос напрямую публичному серверу, мимо DNS
# роутера. Если роутер запросы теряет, а контрольный отвечает — виноват
# роутер, а не канал и не вышестоящий DNS.
CONTROL_DNS_TARGETS = [
    ("ctl_dns", "dns", "8.8.8.8", 53),
]
EXTERNAL_TARGETS = [
    ("dns_google",   "tcp", "8.8.8.8",        53),
    ("dns_cf",       "tcp", "1.1.1.1",        53),
    ("dns_quad9",    "tcp", "9.9.9.9",        53),
    ("https_google", "tcp", "google.com",     443),
    ("https_cf",     "tcp", "cloudflare.com", 443),
    ("https_github", "tcp", "github.com",     443),
]
TARGETS = (LOCAL_TARGETS + ROUTER_DNS_TARGETS + CONTROL_DNS_TARGETS
           + EXTERNAL_TARGETS)
DNS_PROBE_NAME = "google.com"    # какое имя спрашиваем у DNS роутера

INTERVAL_SEC   = 5       # период опроса
TCP_TIMEOUT    = 2.0     # таймаут одной проверки

# Опрос роутера по UPnP: статус и время соединения с провайдером, счётчики
# трафика. Работает, только если UPnP на роутере включён.
UPNP_POLL          = False   # на роутере академии UPnP выключен, доступа к нему нет
UPNP_POLL_SEC      = 60
UPNP_RETRY_SEC     = 600     # как часто искать UPnP заново, если его нет

# Серия быстрых проб: BURST_COUNT подключений подряд раз в BURST_SEC.
# Ловит замирания короче INTERVAL_SEC. Нагрузка — 20 пустых подключений
# в минуту.
BURST_PROBE        = True
BURST_SEC          = 60
BURST_COUNT        = 20
BURST_GAP          = 0.1     # пауза между пробами, сек
BURST_TIMEOUT      = 1.0
BURST_TARGET       = ("8.8.8.8", 53)

# Состояние самого сервера: процессор, память, диск. Раз в SYS_SEC.
SYS_STATS          = True
SYS_SEC            = 60
DISK_WARN_PCT      = 70      # с какой заполненности диска предупреждать
DISK_CRIT_PCT      = 85      # с какой — требовать действий

# Состав устройств: постоянным считается устройство, отвечавшее не реже
# чем в INFRA_SHARE подсчётов; массовое отключение — когда за один подсчёт
# пропало не меньше DROP_MIN устройств и не меньше DROP_SHARE от всех.
INFRA_SHARE        = 0.9
INFRA_MIN_SCANS    = 30
DROP_MIN           = 6
DROP_SHARE         = 0.25
DROP_BACK_SCANS    = 5       # сколько подсчётов ждём возвращения устройств
DROP_BACK_SHARE    = 0.5     # какая доля должна вернуться, чтобы это был сброс,
                             # а не люди, ушедшие после занятия
DNS_TRIES      = 2       # попыток DNS-запроса за замер (как у обычного клиента)
SLOW_FACTOR    = 3       # «медленный» замер: задержка наружу в 3+ раза выше
SLOW_MIN_MS    = 100     # обычной и не меньше чем на 100 мс
CYCLE_BUDGET   = 3.5     # предел на весь цикл (зависший DNS не тормозит замеры)
OUTAGE_MIN_SEC = 30      # от какой длительности событие попадает в список
MERGE_SEC      = 30      # события с паузой короче этой склеиваются в одно
GAP_SEC        = 60      # пауза между замерами дольше этой = сервер не работал

# Подсчёт устройств: сервер сам рассылает ARP-запросы по всей подсети
# (как arp-scan) и считает ответившие MAC-адреса. В число входят серверы и
# роутеры — это постоянный «ночной» уровень; всё, что выше, — люди.
DEVICE_SCAN        = True
USE_DEVICE_COUNT   = True
DEVICE_SCAN_SEC    = 60  # как часто считать устройства
DEVICE_ROUNDS      = 3   # сколько раз повторять рассылку за один подсчёт
DEVICE_BUCKETS     = [(0, 30), (31, 45), (46, 60), (61, 80), (81, None)]

# Сторож петель и широковещательных штормов. Ничего не отправляет в сеть:
# слушает широковещательные и групповые пакеты, которые и так приходят на
# сервер, и раз в BCAST_SEC записывает, сколько их было и кто слал больше всех.
BCAST_WATCH        = True
BCAST_SEC          = 60
BCAST_READ_MAX     = 5000    # больше за минуту не разбираем (при шторме
                             # остальное досчитывает ядро) — бережём процессор
STORM_PPS          = 200     # пакетов в секунду в среднем за минуту — всплеск
                             # (обычно в сети академии около 6)
ARP_DUP_MIN        = 4       # столько и больше ответов на один ARP-запрос —
                             # аномалия (признак петли)

WORK_HOURS = (9, 21)     # используется, только если нет данных о числе устройств
MAX_EVENTS_LISTED = 150

WORK_DIR   = os.environ.get("NETDIAG_DATA", "/data")
OUT_JSONL  = f"{WORK_DIR}/netdiag.jsonl"     # лог старого формата (один файл)

# Лог пишется по файлу на сутки: netdiag-ГГГГ-ММ-ДД.jsonl.
RETAIN_DAYS = 90        # сколько суток хранить
REPORT_DAYS = 14        # за сколько последних суток строить отчёт по умолчанию

# Журналы самого сервера (в docker-compose.yml: /var/log:/host_log:ro).
HOST_LOG_DIR   = os.environ.get("NETDIAG_HOST_LOG", "/host_log")
SEC_STALE_DAYS = 3      # журнал без записей дольше этого считается неведущимся
OUT_REPORT = f"{WORK_DIR}/report.txt"
OUT_HTML   = f"{WORK_DIR}/report.html"
OUT_FULL   = f"{WORK_DIR}/report-full.txt"   # подробный технический
HEARTBEAT  = f"{WORK_DIR}/heartbeat"

# Отчёт по сети: отдельный контейнер netdiag-report (команда serve) раз в
# REPORT_EVERY_MIN перестраивает отчёт за последние REPORT_DAYS суток и
# отдаёт его по HTTP — только чтение, только файлы отчёта. Сайт ставит на
# него ссылку или проксирует путь /netdiag/ на этот порт.
REPORT_EVERY_MIN   = 60
REPORT_HTTP_BIND   = os.environ.get("NETDIAG_HTTP_BIND", "0.0.0.0")
REPORT_HTTP_PORT   = int(os.environ.get("NETDIAG_HTTP_PORT", "8090"))
# ================

os.makedirs(WORK_DIR, exist_ok=True)
logging.basicConfig(
    filename=f"{WORK_DIR}/netdiag.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logging.Formatter.converter = lambda *args: datetime.now(TZ).timetuple()
log = logging.getLogger("netdiag")

_stop = False


def _on_term(sig, frm):
    global _stop
    _stop = True
    log.info("signal %s received", sig)


def now():
    return datetime.now(TZ)


# ============================================================
#  СБОР ДАННЫХ
# ============================================================

def _is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def tcp_check(host, port, timeout=TCP_TIMEOUT):
    """TCP-подключение. Для имён разрешение DNS выполняется отдельно
    и в RTT не входит; ошибка разрешения возвращается как err='dns'."""
    ip = host
    if not _is_ip(host):
        try:
            ip = socket.gethostbyname(host)
        except Exception:
            return {"ok": False, "rtt": None, "err": "dns"}
    t0 = time.perf_counter()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        return {"ok": True, "rtt": (time.perf_counter() - t0) * 1000, "err": None}
    except socket.timeout:
        return {"ok": False, "rtt": None, "err": "timeout"}
    except ConnectionRefusedError:
        return {"ok": False, "rtt": None, "err": "refused"}
    except Exception as e:
        return {"ok": False, "rtt": None, "err": type(e).__name__}
    finally:
        s.close()


def dns_check(host, port, name=DNS_PROBE_NAME, timeout=TCP_TIMEOUT,
              tries=DNS_TRIES):
    """DNS-запрос с повтором. В записи остаётся, сколько попыток было
    сделано (tries) и сколько из них осталось без ответа (lost): одиночная
    потеря — показатель качества, отказом считается потеря всех попыток."""
    lost = 0
    d = None
    for i in range(tries):
        d = _dns_once(host, port, name, timeout / tries)
        if d["ok"]:
            break
        lost += 1
    d["tries"] = i + 1
    d["lost"] = lost
    return d


def _dns_once(host, port, name, timeout):
    """Настоящий DNS-запрос (UDP, запись A) к указанному серверу."""
    qid = random.randint(0, 0xFFFF)
    q = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    for part in name.strip(".").split("."):
        q += bytes([len(part)]) + part.encode("ascii")
    q += b"\x00" + struct.pack(">HH", 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    t0 = time.perf_counter()
    try:
        s.sendto(q, (host, port))
        while True:
            left = timeout - (time.perf_counter() - t0)
            if left <= 0:
                return {"ok": False, "rtt": None, "err": "timeout"}
            s.settimeout(left)
            resp, _ = s.recvfrom(2048)
            if len(resp) >= 12 and struct.unpack(">H", resp[:2])[0] == qid:
                break
        rtt = (time.perf_counter() - t0) * 1000
        flags, _qd, ancount = struct.unpack(">HHH", resp[2:8])
        rcode = flags & 0x000F
        if rcode == 0 and ancount > 0:
            return {"ok": True, "rtt": rtt, "err": None}
        return {"ok": False, "rtt": rtt, "err": f"rcode{rcode}"}
    except socket.timeout:
        return {"ok": False, "rtt": None, "err": "timeout"}
    except Exception as e:
        return {"ok": False, "rtt": None, "err": type(e).__name__}
    finally:
        s.close()


def _check(kind, host, port):
    return dns_check(host, port) if kind == "dns" else tcp_check(host, port)


_pool = ThreadPoolExecutor(max_workers=32)
_inflight = {}


def sample_all():
    """Один замер всех целей. Цикл ограничен CYCLE_BUDGET: проверка, которая
    не уложилась (обычно завис системный резолвер), помечается err='stuck',
    и новая для этой цели не запускается, пока старая не завершится."""
    deadline = time.monotonic() + CYCLE_BUDGET
    futs = {}
    for n, kind, h, p in TARGETS:
        old = _inflight.get(n)
        if old is not None and not old.done():
            continue
        futs[n] = _inflight[n] = _pool.submit(_check, kind, h, p)
    res = {}
    for n, kind, h, p in TARGETS:
        f = futs.get(n)
        if f is None:
            d = {"ok": False, "rtt": None, "err": "stuck"}
        else:
            try:
                d = f.result(timeout=max(0.0, deadline - time.monotonic()))
            except FutTimeout:
                d = {"ok": False, "rtt": None, "err": "stuck"}
            except Exception as e:
                d = {"ok": False, "rtt": None, "err": type(e).__name__}
        d = dict(d)
        d["host"] = h
        d["port"] = p
        d["kind"] = kind
        res[n] = d
    return res


# ---- результаты фоновых проверок ----
# Фоновые потоки кладут сюда свежий результат; основной цикл один раз
# дописывает его в очередной замер.

_extra = {}
_extra_lock = threading.Lock()


def put_extra(key, value):
    with _extra_lock:
        _extra[key] = value


def take_extras():
    with _extra_lock:
        d = dict(_extra)
        _extra.clear()
    return d


def _pause(t0, period):
    while not _stop and time.time() - t0 < period:
        time.sleep(1)


# ---- UPnP: что роутер сам сообщает о соединении с провайдером ----

_NO_PROXY = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def upnp_discover(host, timeout=3.0):
    """Ищет описание UPnP-устройства на роутере. Возвращает URL или None."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.5)
    try:
        for st in ("urn:schemas-upnp-org:device:InternetGatewayDevice:1",
                   "upnp:rootdevice"):
            msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
                   'MAN: "ssdp:discover"\r\nMX: 2\r\nST: ' + st + "\r\n\r\n").encode()
            for dst in ((host, 1900), ("239.255.255.250", 1900)):
                try:
                    s.sendto(msg, dst)
                except OSError:
                    pass
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            try:
                data, addr = s.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            if addr[0] != host:
                continue
            for line in data.decode("latin-1", "replace").split("\r\n"):
                if line.lower().startswith("location:"):
                    return line.split(":", 1)[1].strip()
    finally:
        s.close()
    return None


def upnp_services(location, timeout=4.0):
    """Адреса управления нужных служб: {'wan': (тип, url), 'common': (тип, url)}."""
    import xml.etree.ElementTree as ET
    from urllib.parse import urljoin
    with _NO_PROXY.open(location, timeout=timeout) as r:
        root = ET.fromstring(r.read())
    strip = lambda tag: tag.rsplit("}", 1)[-1]
    base = location
    for el in root.iter():
        if strip(el.tag) == "URLBase" and (el.text or "").strip():
            base = el.text.strip()
    out = {}
    for el in root.iter():
        if strip(el.tag) != "service":
            continue
        f = {strip(c.tag): (c.text or "").strip() for c in el}
        stype, ctl = f.get("serviceType", ""), f.get("controlURL", "")
        if not ctl:
            continue
        if "WANIPConnection" in stype or "WANPPPConnection" in stype:
            out.setdefault("wan", (stype, urljoin(base, ctl)))
        elif "WANCommonInterfaceConfig" in stype:
            out.setdefault("common", (stype, urljoin(base, ctl)))
    return out


def upnp_call(svc, action, timeout=4.0):
    import xml.etree.ElementTree as ET
    stype, url = svc
    body = ('<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/'
            'soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/'
            f'encoding/"><s:Body><u:{action} xmlns:u="{stype}"/></s:Body>'
            '</s:Envelope>').encode()
    req = urllib.request.Request(url, data=body, headers={
        "Content-Type": 'text/xml; charset="utf-8"',
        "SOAPAction": f'"{stype}#{action}"'})
    with _NO_PROXY.open(req, timeout=timeout) as r:
        root = ET.fromstring(r.read())
    return {el.tag.rsplit("}", 1)[-1]: (el.text or "").strip()
            for el in root.iter() if not len(el)}


def upnp_poll(svcs):
    """Один опрос: статус и время соединения, внешний адрес, счётчики байт."""
    def num(d, key):
        try:
            return int(d.get(key, ""))
        except ValueError:
            return None
    out = {}
    if "wan" in svcs:
        d = upnp_call(svcs["wan"], "GetStatusInfo")
        out["st"] = d.get("NewConnectionStatus")
        out["up"] = num(d, "NewUptime")
        try:
            out["ip"] = upnp_call(svcs["wan"], "GetExternalIPAddress").get(
                "NewExternalIPAddress")
        except Exception:
            pass
    if "common" in svcs:
        for key, action, field in (
                ("rx", "GetTotalBytesReceived", "NewTotalBytesReceived"),
                ("tx", "GetTotalBytesSent", "NewTotalBytesSent")):
            try:
                out[key] = num(upnp_call(svcs["common"], action), field)
            except Exception:
                pass
    return {k: v for k, v in out.items() if v is not None}


def upnp_poller():
    """Раз в UPNP_POLL_SEC спрашивает роутер по UPnP. Если роутер UPnP не
    поддерживает или он выключен — проверка тихо не работает, повторяя
    поиск раз в UPNP_RETRY_SEC."""
    svcs, fails, told = None, 0, False
    while not _stop:
        t0 = time.time()
        if svcs is None:
            try:
                loc = upnp_discover(GATEWAY)
                svcs = upnp_services(loc) if loc else None
                if svcs:
                    log.info("upnp: найдено на %s (%s)", loc, ", ".join(sorted(svcs)))
                    told = False
                else:
                    svcs = None
            except Exception as e:
                svcs = None
                if not told:
                    log.warning("upnp: ошибка поиска: %s", e)
            if svcs is None:
                if not told:
                    log.warning("upnp: роутер %s не отвечает по UPnP — "
                                "проверка не работает", GATEWAY)
                    told = True
                _pause(t0, UPNP_RETRY_SEC)
                continue
        try:
            res = upnp_poll(svcs)
            if res:
                put_extra("upnp", res)
            fails = 0
        except Exception:
            fails += 1
            if fails >= 2:              # роутер перезагрузился — ищем заново
                svcs, fails = None, 0
        _pause(t0, UPNP_POLL_SEC)


# ---- серия быстрых проб: замирания короче обычного интервала ----

def burst_once():
    host, port = BURST_TARGET
    rtts, lost = [], 0
    for _ in range(BURST_COUNT):
        t0 = time.perf_counter()
        d = tcp_check(host, port, timeout=BURST_TIMEOUT)
        if d["ok"]:
            rtts.append(d["rtt"])
        else:
            lost += 1
        time.sleep(max(0.0, BURST_GAP - (time.perf_counter() - t0)))
    res = {"n": BURST_COUNT, "lost": lost}
    if rtts:
        res["p50"] = round(statistics.median(rtts), 1)
        res["max"] = round(max(rtts), 1)
    return res


def burst_prober():
    while not _stop:
        t0 = time.time()
        try:
            put_extra("burst", burst_once())
        except Exception as e:
            log.warning("burst probe failed: %s", e)
        _pause(t0, BURST_SEC)


# ---- состояние сервера: процессор, память, диск ----

def _cpu_times():
    with open("/proc/stat") as f:
        v = [int(x) for x in f.readline().split()[1:]]
    idle = v[3] + (v[4] if len(v) > 4 else 0)        # idle + iowait
    return sum(v), idle


def _mem_pct():
    m = {}
    with open("/proc/meminfo") as f:
        for line in f:
            k, _, rest = line.partition(":")
            m[k] = int(rest.split()[0])
    total = m["MemTotal"]
    avail = m.get("MemAvailable", m.get("MemFree", 0))
    return 100.0 * (total - avail) / total, total * 1024


def sys_sampler():
    """Раз в SYS_SEC: средняя загрузка процессора за интервал, занятая
    память, место на диске с данными и размер лога. В контейнере /proc
    показывает значения всего сервера, а не одного контейнера."""
    try:
        prev = _cpu_times()
    except Exception as e:
        log.warning("sys stats disabled: %s", e)
        return
    while not _stop:
        t0 = time.time()
        _pause(t0, SYS_SEC)
        if _stop:
            break
        try:
            cur = _cpu_times()
            dt, di = cur[0] - prev[0], cur[1] - prev[1]
            prev = cur
            mem, mem_total = _mem_pct()
            st = os.statvfs(WORK_DIR)
            res = {"cpu": round(100.0 * (dt - di) / dt, 1) if dt > 0 else 0.0,
                   "mem": round(mem, 1), "mem_total": mem_total,
                   "disk_total": st.f_frsize * st.f_blocks,
                   "disk_free": st.f_frsize * st.f_bavail,
                   "log": data_size()}
            try:
                with open("/proc/loadavg") as f:
                    res["load"] = float(f.read().split()[0])
            except Exception:
                pass
            put_extra("sys", res)
        except Exception as e:
            log.warning("sys stats failed: %s", e)


# ---- подсчёт устройств в локальной сети ----

_dev = {"n": None, "t": 0.0}


def _lan_iface():
    """Интерфейс сервера, адрес которого лежит в LAN_NET: (имя, ip, mac)."""
    net = ipaddress.ip_network(LAN_NET)
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        for _idx, name in socket.if_nameindex():
            ifr = struct.pack("256s", name.encode()[:15])
            try:
                ip = socket.inet_ntoa(fcntl.ioctl(probe.fileno(), 0x8915, ifr)[20:24])
                if ipaddress.ip_address(ip) not in net:
                    continue
                mac = fcntl.ioctl(probe.fileno(), 0x8927, ifr)[18:24]
                return name, ip, mac
            except OSError:
                continue
    finally:
        probe.close()
    return None


def arp_scan(iface, my_ip, my_mac, rounds=DEVICE_ROUNDS):
    """Рассылает ARP-запросы на все адреса LAN_NET и возвращает {ip: mac}
    ответивших и {ip: сколько ответов пришло нам}. Запросы повторяются:
    устройства на Wi-Fi отвечают не сразу."""
    net = ipaddress.ip_network(LAN_NET)
    hosts = [h for h in net.hosts() if str(h) != my_ip]
    spa = socket.inet_aton(my_ip)
    head = (b"\xff" * 6 + my_mac + b"\x08\x06"
            + struct.pack(">HHBBH", 1, 0x0800, 6, 4, 1) + my_mac + spa + b"\x00" * 6)
    found, replies = {}, Counter()
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
    try:
        s.bind((iface, 0))

        def listen(sec):
            end = time.monotonic() + sec
            while True:
                left = end - time.monotonic()
                if left <= 0:
                    return
                s.settimeout(left)
                try:
                    pkt = s.recv(128)
                except socket.timeout:
                    return
                except OSError:
                    return
                if len(pkt) < 42 or pkt[12:14] != b"\x08\x06" or pkt[20:22] != b"\x00\x02":
                    continue
                ip = socket.inet_ntoa(pkt[28:32])
                if ip != my_ip and ipaddress.ip_address(ip) in net:
                    found[ip] = pkt[22:28]
                    if pkt[38:42] == spa:          # ответ именно нам
                        replies[ip] += 1

        for _ in range(rounds):
            for h in hosts:
                if str(h) in found:
                    continue
                try:
                    s.send(head + h.packed)
                except OSError:
                    pass
                listen(0.004)
            listen(1.5)
    finally:
        s.close()
    return found, replies


def device_scanner():
    """Раз в DEVICE_SCAN_SEC считает устройства в локальной сети по ARP."""
    try:
        n_hosts = ipaddress.ip_network(LAN_NET).num_addresses
    except Exception as e:
        log.warning("device scan disabled: bad LAN_NET (%s)", e)
        return
    if n_hosts > 1024:
        log.warning("device scan disabled: сеть %s слишком велика", LAN_NET)
        return
    try:
        me = _lan_iface()
    except Exception as e:
        me = None
        log.warning("device scan: не удалось определить интерфейс (%s)", e)
    if me is None:
        log.warning("device scan disabled: у сервера нет адреса в %s", LAN_NET)
        return
    iface, my_ip, my_mac = me
    log.info("device scan: %s %s, сеть %s", iface, my_ip, LAN_NET)
    failures = 0
    while not _stop:
        t0 = time.time()
        try:
            found, replies = arp_scan(iface, my_ip, my_mac)
            _dev["n"] = len(found)
            _dev["t"] = time.time()
            put_extra("devs", {ip: mac.hex() for ip, mac in found.items()})
            dups = {ip: [found[ip].hex(), n] for ip, n in replies.items()
                    if n >= ARP_DUP_MIN and ip in found}
            if dups:
                put_extra("arpdup", dups)
                log.warning("arp: многократные ответы %s", dups)
            failures = 0
        except PermissionError:
            log.warning("device scan disabled: нет прав на ARP "
                        "(нужен root и cap NET_RAW в контейнере)")
            return
        except Exception as e:
            failures += 1
            if failures <= 3:
                log.warning("device scan failed: %s", e)
        while not _stop and time.time() - t0 < DEVICE_SCAN_SEC:
            time.sleep(1)


def _pkt_stats(s):
    """Сколько пакетов прошло фильтр сокета с прошлого вызова (вместе с теми,
    что ядро отбросило из-за переполнения очереди). Счётчик сбрасывается."""
    packets, _drops = struct.unpack("II", s.getsockopt(263, 6, 8))  # SOL_PACKET, PACKET_STATISTICS
    return packets


def bcast_socket(iface):
    """Сокет, получающий только широковещательные и групповые кадры: фильтр
    в ядре отсекает всё остальное, поэтому обычный трафик сервера не мешает."""
    import ctypes
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    try:
        prog = [(0x20, 0, 0, 0xfffff004),   # A = тип кадра (pkt_type)
                (0x15, 2, 0, 1),            # broadcast → принять
                (0x15, 1, 0, 2),            # multicast → принять
                (0x06, 0, 0, 0),            # остальное — отбросить
                (0x06, 0, 0, 64)]           # принять первые 64 байта
        buf = ctypes.create_string_buffer(
            b"".join(struct.pack("HBBI", *i) for i in prog))
        s.setsockopt(socket.SOL_SOCKET, 26,                  # SO_ATTACH_FILTER
                     struct.pack("HL", len(prog), ctypes.addressof(buf)))
        # ядро копирует фильтр при подключении — buf дальше не нужен
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 18)
        s.bind((iface, 0))
        while True:                         # выбрасываем пришедшее до фильтра
            s.setblocking(False)
            try:
                s.recv(64)
            except (BlockingIOError, OSError):
                break
        s.setblocking(True)
        _pkt_stats(s)
        return s
    except Exception:
        s.close()
        raise


def bcast_watcher():
    """Раз в BCAST_SEC: сколько широковещательных и групповых пакетов пришло
    и кто слал больше всех. Петля или шторм видны как резкий рост."""
    try:
        me = _lan_iface()
        if me is None:
            log.warning("bcast watch disabled: у сервера нет адреса в %s", LAN_NET)
            return
        s = bcast_socket(me[0])
    except Exception as e:
        log.warning("bcast watch disabled: %s", e)
        return
    log.info("bcast watch: %s", me[0])
    try:
        while not _stop:
            t0, seen, read = time.monotonic(), Counter(), 0
            while not _stop:
                left = BCAST_SEC - (time.monotonic() - t0)
                if left <= 0:
                    break
                if read >= BCAST_READ_MAX:      # шторм: дальше считает ядро
                    time.sleep(min(left, 1.0))
                    continue
                s.settimeout(min(left, 1.0))
                try:
                    pkt = s.recv(64)
                except socket.timeout:
                    continue
                if len(pkt) >= 12:
                    read += 1
                    seen[pkt[6:12]] += 1
            if _stop:
                break
            if read >= BCAST_READ_MAX:          # выбрасываем накопившееся, чтобы
                s.setblocking(False)            # оно не попало в следующую минуту
                try:
                    for _ in range(100000):
                        s.recv(64)
                except (BlockingIOError, OSError):
                    pass
                s.setblocking(True)
            try:
                n = _pkt_stats(s)
            except OSError:
                n = read
            put_extra("bc", {"n": n, "sec": round(time.monotonic() - t0, 1),
                             "top": [[m.hex(), c] for m, c in seen.most_common(3)]})
    except Exception as e:
        log.warning("bcast watch stopped: %s", e)
    finally:
        s.close()


def current_devices():
    if _dev["n"] is None or time.time() - _dev["t"] > DEVICE_SCAN_SEC * 3:
        return None
    return _dev["n"]


# ---- хранение лога ----

def day_file(d):
    return f"{WORK_DIR}/netdiag-{d.isoformat()}.jsonl"


def data_files():
    """Файлы лога по порядку времени: [(дата или None для старого, путь)]."""
    out = []
    if os.path.exists(OUT_JSONL):
        out.append((None, OUT_JSONL))
    for path in sorted(glob.glob(f"{WORK_DIR}/netdiag-????-??-??.jsonl")):
        try:
            out.append((date.fromisoformat(os.path.basename(path)[8:18]), path))
        except ValueError:
            pass
    return out


def data_size():
    n = 0
    for _d, path in data_files():
        try:
            n += os.path.getsize(path)
        except OSError:
            pass
    return n


def purge_old(today):
    """Удаляет файлы лога старше RETAIN_DAYS."""
    limit = today - timedelta(days=RETAIN_DAYS)
    for d, path in data_files():
        try:
            if d is None:
                d = datetime.fromtimestamp(os.path.getmtime(path), TZ).date()
            if d < limit:
                os.remove(path)
                log.info("удалён старый лог %s", os.path.basename(path))
        except OSError as e:
            log.warning("не удалось удалить %s: %s", path, e)


# ---- журналы сервера: файрвол, входы по SSH, fail2ban ----

def _log_files(name):
    return sorted(p for p in glob.glob(f"{HOST_LOG_DIR}/{name}*")
                  if os.path.isfile(p))


def _log_lines(path):
    opener = gzip.open if path.endswith(".gz") else open
    try:
        with opener(path, "rt", encoding="utf-8", errors="replace") as f:
            yield from f
    except OSError:
        return


def _newest(paths):
    """Время последней записи в журнале: mtime самого свежего непустого файла."""
    best = None
    for path in paths:
        try:
            if os.path.getsize(path) > 0:
                m = os.path.getmtime(path)
                best = m if best is None or m > best else best
        except OSError:
            pass
    return datetime.fromtimestamp(best, TZ) if best else None


def _host_tz():
    """Часовой пояс самого сервера: в нём fail2ban пишет время в свой журнал.
    Контейнер живёт в TZ, а /etc/localtime у него подключён от сервера."""
    try:
        with open("/etc/localtime", "rb") as f:
            return ZoneInfo.from_file(f)
    except Exception:
        return TZ


_UFW_FIELD = re.compile(r"\b(IN|OUT|SRC|DST|PROTO|DPT)=(\S*)")


def security_summary(t_from, t_to):
    """Блокировки файрвола, входы по SSH и срабатывания fail2ban за период.
    None — журналы сервера контейнеру недоступны."""
    if not os.path.isdir(HOST_LOG_DIR):
        return None
    R = {"ufw_in": 0, "ufw_out": 0, "ufw_noise": 0,
         "top_in": Counter(), "top_out": Counter(), "ssh_ok": 0, "ssh_fail": 0,
         "found": 0, "ban": 0, "ips": Counter(), "banned": Counter(),
         "syslog_stale": False, "syslog_last": None, "f2b": False}
    fresh_from = t_from.timestamp() - 86400

    def in_period(ts):
        return ts is not None and t_from <= ts <= t_to

    def iso(line):
        try:
            return datetime.fromisoformat(line[:40].split(" ", 1)[0]).astimezone(TZ)
        except ValueError:
            return None

    auth, ufw = _log_files("auth.log"), _log_files("ufw.log")
    last = _newest(auth)
    R["syslog_last"] = last
    R["syslog_stale"] = (last is None
                         or (now() - last).total_seconds() > SEC_STALE_DAYS * 86400)
    for paths, kind in ((ufw, "ufw"), (auth, "auth")):
        for path in paths:
            try:
                if os.path.getsize(path) == 0 or os.path.getmtime(path) < fresh_from:
                    continue
            except OSError:
                continue
            for line in _log_lines(path):
                if kind == "ufw":
                    if "[UFW BLOCK]" not in line or not in_period(iso(line)):
                        continue
                    f = dict(m.groups() for m in _UFW_FIELD.finditer(line))
                    dst = f.get("DST", "")
                    first = dst.split(".", 1)[0]
                    if (dst.lower().startswith("ff") or dst == "255.255.255.255"
                            or dst.endswith(".255")
                            or (first.isdigit() and 224 <= int(first) <= 239)):
                        R["ufw_noise"] += 1      # групповые и широковещательные
                        continue
                    if f.get("PROTO") == "TCP" and " SYN " not in line:
                        R["ufw_noise"] += 1      # хвост уже закрытого соединения
                        continue
                    what = (f"порт {f['DPT']}" if f.get("DPT")
                            else f.get("PROTO", "?"))
                    if f.get("IN"):
                        R["ufw_in"] += 1
                        R["top_in"][f"{f.get('SRC', '?')} → {what}"] += 1
                    else:
                        R["ufw_out"] += 1
                        R["top_out"][f"{dst} → {what}"] += 1
                elif "sshd" in line:
                    if "Accepted " in line:
                        if in_period(iso(line)):
                            R["ssh_ok"] += 1
                    elif ("Invalid user " in line
                          or ("Failed password for " in line
                              and "invalid user" not in line)
                          or "Failed publickey for " in line):
                        if in_period(iso(line)):
                            R["ssh_fail"] += 1
    f2b = _log_files("fail2ban.log")
    R["f2b"] = bool(f2b)
    host_tz = _host_tz()
    for path in f2b:
        try:
            if os.path.getsize(path) == 0 or os.path.getmtime(path) < fresh_from:
                continue
        except OSError:
            continue
        for line in _log_lines(path):
            what = "found" if "] Found " in line else "ban" if "] Ban " in line else None
            if not what:
                continue
            try:
                ts = datetime.strptime(line[:19], "%Y-%m-%d %H:%M:%S").replace(
                    tzinfo=host_tz)
            except ValueError:
                continue
            if not in_period(ts):
                continue
            R[what] += 1
            ip = line.split("] Found " if what == "found" else "] Ban ", 1)[1].split()[0]
            (R["ips"] if what == "found" else R["banned"])[ip] += 1
    return R


def _top(counter, word, n=2):
    if not counter:
        return ""
    return f" ({word}: " + ", ".join(f"{k} ×{v}" for k, v in counter.most_common(n)) + ")"


def security_lines(R):
    """Строки о безопасности на двух языках: [{'ru':…, 'az':…}]."""
    if R is None:
        return []
    out = []
    if R["syslog_stale"]:
        when = (fmt_dt(R["syslog_last"])[:8] if R["syslog_last"] else None)
        out.append({
            "ru": ("Системные журналы сервера (auth.log, ufw.log) "
                   + (f"не пополняются с {when}" if when else "не ведутся")
                   + ": блокировки файрвола и входы по SSH не учитываются. "
                   "Проверить службу rsyslog."),
            "az": ("Serverin sistem jurnalları (auth.log, ufw.log) "
                   + (f"{when} tarixindən yenilənmir" if when else "aparılmır")
                   + ": faervol bloklamaları və SSH girişləri nəzərə alınmır. "
                   "rsyslog xidmətini yoxlamaq lazımdır.")})
    else:
        out.append({
            "ru": f"Файрвол заблокировал адресных пакетов: входящих {R['ufw_in']}"
                  + _top(R["top_in"], "чаще всего")
                  + f", исходящих {R['ufw_out']}" + _top(R["top_out"], "чаще всего")
                  + f". Служебных рассылок и хвостов закрытых соединений: "
                    f"{R['ufw_noise']} — это не атаки.",
            "az": f"Faervol ünvanlı paketləri bloklayıb: daxil olan {R['ufw_in']}"
                  + _top(R["top_in"], "ən çox").replace("порт", "port")
                  + f", çıxan {R['ufw_out']}"
                  + _top(R["top_out"], "ən çox").replace("порт", "port")
                  + f". Xidməti yayım paketləri və bağlanmış əlaqələrin qalıqları: "
                    f"{R['ufw_noise']} — bunlar hücum deyil."})
        out.append({
            "ru": f"Входов по SSH: удачных {R['ssh_ok']}, неудачных {R['ssh_fail']}.",
            "az": f"SSH girişləri: uğurlu {R['ssh_ok']}, uğursuz {R['ssh_fail']}."})
    if R["f2b"]:
        ips = ", ".join(f"{ip} ×{n}" for ip, n in R["ips"].most_common(3))
        bans = ", ".join(ip for ip, _n in R["banned"].most_common(3))
        out.append({
            "ru": f"fail2ban: неудачных попыток входа {R['found']}"
                  + (f" (с адресов: {ips})" if ips else "")
                  + f", заблокировано адресов: {R['ban']}"
                  + (f" ({bans})" if bans else "") + ".",
            "az": f"fail2ban: uğursuz giriş cəhdləri {R['found']}"
                  + (f" (ünvanlar: {ips})" if ips else "")
                  + f", bloklanmış ünvanlar: {R['ban']}"
                  + (f" ({bans})" if bans else "") + "."})
    else:
        out.append({"ru": "fail2ban: журнал не найден.",
                    "az": "fail2ban: jurnal tapılmadı."})
    return out


def write_heartbeat():
    try:
        with open(HEARTBEAT, "w") as f:
            f.write(now().isoformat(timespec="seconds"))
    except Exception as e:
        log.warning("heartbeat write failed: %s", e)


def check_startup_gap():
    if not os.path.exists(HEARTBEAT):
        return
    try:
        with open(HEARTBEAT) as f:
            last = to_aware(f.read().strip())
        n = now()
        gap = (n - last).total_seconds()
        if gap > GAP_SEC:
            log.info("GAP detected: server down from %s to %s (%.0f sec)",
                     last.isoformat(), n.isoformat(), gap)
    except Exception as e:
        log.warning("gap check failed: %s", e)


def run():
    signal.signal(signal.SIGTERM, _on_term)
    signal.signal(signal.SIGINT, _on_term)
    check_startup_gap()
    log.info("START interval=%ss targets=%d device_scan=%s",
             INTERVAL_SEC, len(TARGETS), DEVICE_SCAN)
    if DEVICE_SCAN:
        threading.Thread(target=device_scanner, daemon=True).start()
    if UPNP_POLL:
        threading.Thread(target=upnp_poller, daemon=True).start()
    if BURST_PROBE:
        threading.Thread(target=burst_prober, daemon=True).start()
    if SYS_STATS:
        threading.Thread(target=sys_sampler, daemon=True).start()
    if BCAST_WATCH:
        threading.Thread(target=bcast_watcher, daemon=True).start()
    f, cur_day = None, None
    try:
        while not _stop:
            t0 = time.time()
            write_heartbeat()
            stamp = now()
            if stamp.date() != cur_day:           # новые сутки — новый файл
                if f:
                    f.close()
                cur_day = stamp.date()
                purge_old(cur_day)
                f = open(day_file(cur_day), "a", buffering=1, encoding="utf-8")
            rec = {"ts": stamp.isoformat(timespec="milliseconds"),
                   "data": sample_all()}
            dev = current_devices()
            if dev is not None:
                rec["ndev"] = dev
            rec.update(take_extras())     # devs / upnp / burst / sys, раз в минуту
            f.write(json.dumps(rec) + "\n")
            f.flush()
            os.fsync(f.fileno())
            time.sleep(max(0, INTERVAL_SEC - (time.time() - t0)))
    finally:
        if f:
            f.close()
    log.info("STOP")
    _pool.shutdown(wait=False, cancel_futures=True)


# ============================================================
#  АНАЛИЗ
# ============================================================

def to_aware(iso):
    dt = datetime.fromisoformat(iso)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=TZ)
    return dt.astimezone(TZ)


def classify(data, rdns_trusted=True):
    """Состояние сети по одному замеру.

    blackout — ни один внешний ресурс недоступен;
    dns      — по IP связь есть, но DNS роутера не отвечает либо имена
               не разрешаются;
    partial  — недоступны два и более внешних ресурса, но не все;
    gwmute   — интернет работает, а роутер на локальные запросы не отвечает;
    ok       — всё в порядке.

    rdns_trusted=False — DNS роутера ещё ни разу не ответил (возможно,
    он выключен), поэтому его молчание отклонением не считается.
    """
    gw_ok = False
    gw_seen = False
    gw_rtt = None
    rdns = None
    dns_try = dns_lost = ctl_try = ctl_lost = 0
    ext_total = ext_ok = ip_total = ip_ok = name_total = name_ok = 0
    ext_rtts = []
    for n, d in data.items():
        ok = bool(d.get("ok"))
        if n == "gw_dns":
            rdns = ok
            dns_try = d.get("tries", 1)
            dns_lost = d.get("lost", 0 if ok else 1)
        elif n.startswith("ctl_"):
            ctl_try += d.get("tries", 1)
            ctl_lost += d.get("lost", 0 if ok else 1)
        elif n.startswith("gw_"):
            gw_seen = True
            if ok:
                gw_ok = True
                r = d.get("rtt")
                if r is not None and (gw_rtt is None or r < gw_rtt):
                    gw_rtt = r
        else:
            ext_total += 1
            is_ip = _is_ip(str(d.get("host", "")))
            if is_ip:
                ip_total += 1
            else:
                name_total += 1
            if ok:
                ext_ok += 1
                if is_ip:
                    ip_ok += 1
                else:
                    name_ok += 1
                if d.get("rtt") is not None:
                    ext_rtts.append(d["rtt"])
    if not gw_seen:
        gw_ok = True
    if ext_total and ext_ok == 0:
        state = "blackout"
    elif ip_ok > 0 and ((rdns is False and rdns_trusted)
                        or (name_total and name_ok == 0)):
        state = "dns"
    elif ext_total - ext_ok >= 2:
        state = "partial"
    elif not gw_ok:
        state = "gwmute"
    else:
        state = "ok"
    return {
        "state": state, "gw_ok": gw_ok, "gw_rtt": gw_rtt, "rdns": rdns,
        "dns_try": dns_try, "dns_lost": dns_lost,
        "ctl_try": ctl_try, "ctl_lost": ctl_lost,
        "ext_rtt": statistics.median(ext_rtts) if ext_rtts else None,
    }


def _stat():
    return {"n": 0, "bad": 0, "sec": 0.0, "black_sec": 0.0,
            "rtt": array("f"), "ext": array("f"),
            "dns_try": 0, "dns_lost": 0, "ctl_try": 0, "ctl_lost": 0,
            "dnsc_try": 0, "dnsc_lost": 0,   # DNS роутера там, где есть контроль
            "join": 0, "left": 0, "scans": 0,          # смена состава устройств
            "rx_bits": 0.0, "tx_bits": 0.0, "tr_sec": 0.0,   # трафик по UPnP
            "b_n": 0, "b_lost": 0,                      # серии быстрых проб
            "b_p50": array("f"), "b_max": array("f"),
            "cpu_sum": 0.0, "mem_sum": 0.0, "sys_n": 0,      # сервер
            "cpu_max": 0.0, "mem_max": 0.0,
            "bc_n": 0, "bc_sec": 0.0, "bc_max": 0.0,         # широковещательные
            "dev_sum": 0, "dev_n": 0, "dev_max": 0, "outages": 0}


def bucket_of(dev):
    for i, (lo, hi) in enumerate(DEVICE_BUCKETS):
        if dev >= lo and (hi is None or dev <= hi):
            return i
    return len(DEVICE_BUCKETS) - 1


def bucket_label(i):
    lo, hi = DEVICE_BUCKETS[i]
    return f"{lo}+" if hi is None else f"{lo}–{hi}"


class Analyzer:
    """Потоковый разбор лога: память не зависит от длины периода."""

    def __init__(self):
        self.first = self.last = None
        self.prev = None
        self.gaps = []
        self.total = _stat()
        self.hour = defaultdict(_stat)
        self.wd = defaultdict(_stat)
        self.day = defaultdict(_stat)
        self.bucket = defaultdict(_stat)
        self.tl = defaultdict(_stat)      # 5-минутные интервалы для графиков
        self.events = []
        self.cur = None
        self.pre = deque(maxlen=60)       # RTT роутера за ~5 минут до события
        self.last_dev = None
        self.rdns_n = self.rdns_ok = 0     # DNS роутера: замеров / успешных
        self.upnp_n = 0                    # опросов роутера по UPnP
        self.up_prev = None
        self.wan_resets = []               # (когда, сколько держалось до этого)
        self.ip_changes = []
        self.wan_down_polls = 0
        self.devtab = {}                   # mac → сведения об устройстве
        self.dv_prev, self.dv_ts, self.dv_scans = {}, None, 0
        self.drops = []                    # (когда, пропало, из скольких, вернулось)
        self.dv_pending = []               # отключения, ждущие проверки на возврат
        self.sys_first = self.sys_last = None    # (когда, запись) о сервере
        self.n_const = None                # постоянных устройств (вычтены из числа)
        self.bc_pps = array("f")           # широковещательных пакетов/с по минутам
        self.storms = []                   # всплески широковещательного трафика
        self.arpdups = []                  # (когда, ip, mac, сколько ответов)
        self.mac_ip = {}                   # mac → последний известный ip

    @property
    def has_rdns(self):
        return self.rdns_ok > 0

    def feed(self, ts, data, dev, rec=None):
        self._extras(ts, rec)
        c = classify(data, self.rdns_ok > 0)
        if c["rdns"] is not None:
            self.rdns_n += 1
            self.rdns_ok += 1 if c["rdns"] else 0
        c["ts"] = ts
        c["dev"] = dev
        if self.first is None:
            self.first = ts
        self.last = ts
        if self.prev is not None:
            dt = (ts - self.prev["ts"]).total_seconds()
            if dt > GAP_SEC:
                self.gaps.append((self.prev["ts"], ts, dt))
                self._account(self.prev, INTERVAL_SEC, True)
            else:
                self._account(self.prev, dt if dt > 0 else INTERVAL_SEC, False)
        self.prev = c

    # ---------- дополнительные данные из замера ----------

    def _extras(self, ts, rec):
        if not rec:
            return
        spots = (self.total, self.tl[tl_key(ts)])
        y = rec.get("sys")
        if y and y.get("cpu") is not None:
            if self.sys_first is None:
                self.sys_first = (ts, y)
            self.sys_last = (ts, y)
            for s in spots:
                s["cpu_sum"] += y["cpu"]
                s["mem_sum"] += y.get("mem", 0.0)
                s["sys_n"] += 1
                s["cpu_max"] = max(s["cpu_max"], y["cpu"])
                s["mem_max"] = max(s["mem_max"], y.get("mem", 0.0))
        bc = rec.get("bc")
        if bc and bc.get("sec"):
            self._bcast(ts, bc, spots)
        for ip, (mac, n) in (rec.get("arpdup") or {}).items():
            self.arpdups.append((ts, ip, mac, n))
        b = rec.get("burst")
        if b:
            for s in spots:
                s["b_n"] += b.get("n", 0)
                s["b_lost"] += b.get("lost", 0)
                if b.get("p50") is not None:
                    s["b_p50"].append(b["p50"])
                    s["b_max"].append(b.get("max", b["p50"]))
        u = rec.get("upnp")
        if u:
            self._upnp(ts, u, spots)
        devs = rec.get("devs")
        if devs and USE_DEVICE_COUNT:
            self._devs(ts, devs, spots)

    def _bcast(self, ts, bc, spots):
        sec = bc["sec"]
        pps = bc.get("n", 0) / sec
        self.bc_pps.append(pps)
        for s in spots:
            s["bc_n"] += bc.get("n", 0)
            s["bc_sec"] += sec
            s["bc_max"] = max(s["bc_max"], pps)
        if pps < STORM_PPS:
            return
        start = ts - timedelta(seconds=sec)
        top = bc.get("top") or []
        st = self.storms[-1] if self.storms else None
        if st and (start - st["end"]).total_seconds() <= 2 * BCAST_SEC:
            st["end"] = ts
            if pps > st["pps"]:
                st["pps"], st["top"] = pps, top
        else:
            self.storms.append({"start": start, "end": ts, "pps": pps, "top": top})

    def _upnp(self, ts, u, spots):
        self.upnp_n += 1
        p = self.up_prev
        self.up_prev = dict(u, ts=ts)
        if u.get("st") and u["st"] != "Connected":
            self.wan_down_polls += 1
        if not p:
            return
        dt = (ts - p["ts"]).total_seconds()
        if not 0 < dt <= 7200:
            return
        # время соединения стало меньше, чем было: соединение переустановлено
        reset = (u.get("up") is not None and p.get("up") is not None
                 and u["up"] + 30 < p["up"] + dt)
        reset = reset and u["up"] < p["up"]
        if reset:
            self.wan_resets.append((ts, p["up"]))
        if u.get("ip") and p.get("ip") and u["ip"] != p["ip"]:
            self.ip_changes.append((ts, p["ip"], u["ip"]))
        if reset or dt > 300:
            return                        # счётчики байт несопоставимы
        got = False
        for key, dst in (("rx", "rx_bits"), ("tx", "tx_bits")):
            if u.get(key) is None or p.get(key) is None:
                continue
            d = u[key] - p[key]
            if d < 0:
                d += 2 ** 32             # 32-битный счётчик перешёл через ноль
            if d * 8 / dt > 1.5e9:       # неправдоподобно — пропускаем
                continue
            got = True
            for s in spots:
                s[dst] += d * 8
        if got:
            for s in spots:
                s["tr_sec"] += dt

    def _devs(self, ts, devs, spots):
        cur = {mac: ip for ip, mac in devs.items()}
        fresh = (self.dv_ts is None
                 or (ts - self.dv_ts).total_seconds() > 300)
        self.dv_scans += 1
        for mac, ip in cur.items():
            d = self.devtab.get(mac)
            if d is None:
                d = self.devtab[mac] = {"ip": ip, "n": 0, "last": None,
                                        "miss": 0, "abs": []}
            if d["miss"] >= 2 and d["last"] is not None and not fresh:
                d["abs"].append((d["last"], ts))
            d["miss"] = 0
            d["n"] += 1
            d["last"] = ts
            d["ip"] = ip
        for mac, d in self.devtab.items():
            if mac in cur:
                continue
            if fresh:
                d["miss"], d["last"] = 0, None   # через перерыв не считаем
            elif d["last"] is not None:
                d["miss"] += 1
        if fresh:
            self.dv_pending = []
        for pd in self.dv_pending[:]:
            pd["back"] |= pd["macs"] & cur.keys()
            pd["wait"] -= 1
            if pd["wait"] <= 0:
                self.dv_pending.remove(pd)
                if len(pd["back"]) >= DROP_BACK_SHARE * len(pd["macs"]):
                    self.drops.append((pd["ts"], len(pd["macs"]), pd["tot"],
                                       len(pd["back"])))
        if not fresh:
            gone = self.dv_prev.keys() - cur.keys()
            joined = len(cur.keys() - self.dv_prev.keys())
            for s in spots:
                s["join"] += joined
                s["left"] += len(gone)
                s["scans"] += 1
            if len(gone) >= max(DROP_MIN, DROP_SHARE * len(self.dv_prev)):
                self.dv_pending.append({"ts": ts, "macs": set(gone), "back": set(),
                                        "tot": len(self.dv_prev),
                                        "wait": DROP_BACK_SCANS})
        self.dv_prev, self.dv_ts = cur, ts

    def finish(self):
        if self.prev is not None:
            self._account(self.prev, INTERVAL_SEC, True)
            self.prev = None

    def _account(self, c, dt, gap_after):
        ts, state, dev = c["ts"], c["state"], c["dev"]
        if dev is not None:
            self.last_dev = dev
        groups = [self.total, self.hour[ts.hour], self.wd[ts.weekday()],
                  self.day[ts.date()], self.tl[tl_key(ts)]]
        if dev is not None:
            groups.append(self.bucket[bucket_of(dev)])
        for s in groups:
            s["n"] += 1
            s["sec"] += dt
            if state != "ok":
                s["bad"] += 1
            if state == "blackout":
                s["black_sec"] += dt
            if c["gw_rtt"] is not None:
                s["rtt"].append(c["gw_rtt"])
            if c["ext_rtt"] is not None:
                s["ext"].append(c["ext_rtt"])
            if state != "blackout":      # при обрыве DNS молчит закономерно
                s["dns_try"] += c["dns_try"]
                s["dns_lost"] += c["dns_lost"]
                s["ctl_try"] += c["ctl_try"]
                s["ctl_lost"] += c["ctl_lost"]
                if c["ctl_try"]:
                    s["dnsc_try"] += c["dns_try"]
                    s["dnsc_lost"] += c["dns_lost"]
            if dev is not None:
                s["dev_sum"] += dev
                s["dev_n"] += 1
                s["dev_max"] = max(s["dev_max"], dev)

        end_of_sample = ts + timedelta(seconds=dt)
        if state != "ok":
            if self.cur is None:
                self.cur = {"start": ts, "n": 0, "gw_down": 0,
                            "sec": defaultdict(float), "rtts": [],
                            "pre": [x for x in self.pre if x is not None],
                            "dev": self.last_dev, "pending": None,
                            "ctl_try": 0, "ctl_lost": 0}
            e = self.cur
            e["pending"] = None
            e["n"] += 1
            e["sec"][state] += dt
            e["ctl_try"] += c["ctl_try"]
            e["ctl_lost"] += c["ctl_lost"]
            if not c["gw_ok"]:
                e["gw_down"] += 1
            if c["gw_rtt"] is not None:
                e["rtts"].append(c["gw_rtt"])
            if dev is not None:
                e["dev"] = max(e["dev"] or 0, dev)
        else:
            self.pre.append(c["gw_rtt"])
            e = self.cur
            if e is not None:
                if e["pending"] is None:
                    e["pending"] = ts
                if (end_of_sample - e["pending"]).total_seconds() >= MERGE_SEC:
                    self._close(e["pending"])
        if gap_after and self.cur is not None:
            self._close(self.cur["pending"] or end_of_sample)

    def _close(self, end):
        e = self.cur
        self.cur = None
        e["end"] = end
        e["dur"] = (end - e["start"]).total_seconds()
        black = e["sec"].get("blackout", 0.0)
        if black >= OUTAGE_MIN_SEC:
            e["kind"] = "outage"
        elif black > 0:
            e["kind"] = "blip"
        else:
            e["kind"] = max(("dns", "partial", "gwmute"),
                            key=lambda k: e["sec"].get(k, 0.0))
        self.events.append(e)


# ============================================================
#  ОТЧЁТ
# ============================================================

WD_NAMES = ["Пн", "Вт", "Ср", "Чт", "Пт", "Сб", "Вс"]


def fmt_dt(dt):
    return dt.strftime("%d.%m.%y %H:%M:%S")


DUR_UNITS = {"ru": ("сут", "ч", "мин", "сек"),
             "az": ("gün", "saat", "dəq", "san")}


def fmt_dur(sec, lang="ru"):
    ud, uh, um, us = DUR_UNITS[lang]
    sec = int(round(sec))
    d, sec = divmod(sec, 86400)
    h, sec = divmod(sec, 3600)
    m, s = divmod(sec, 60)
    parts = []
    if d: parts.append(f"{d} {ud}")
    if h: parts.append(f"{h} {uh}")
    if m: parts.append(f"{m} {um}")
    if (s and not d) or not parts: parts.append(f"{s} {us}")
    return " ".join(parts)


def both(fn):
    """Одно и то же значение на двух языках HTML-отчёта."""
    return {"ru": fn("ru"), "az": fn("az")}


def plural(n, one, few, many):
    n10, n100 = n % 10, n % 100
    if n10 == 1 and n100 != 11:
        w = one
    elif 2 <= n10 <= 4 and not 12 <= n100 <= 14:
        w = few
    else:
        w = many
    return f"{n} {w}"


def pct(a, b):
    return 100.0 * a / b if b else 0.0


def quantile(arr, q):
    if not arr:
        return None
    xs = sorted(arr)
    return xs[min(len(xs) - 1, int(q * len(xs)))]


def ms(x):
    return "—" if x is None else f"{x:.0f}"


def table(headers, rows):
    w = [len(h) for h in headers]
    for r in rows:
        for i, c in enumerate(r):
            w[i] = max(w[i], len(c))
    line = lambda r: "  " + "  ".join(
        c.ljust(w[i]) if i == 0 else c.rjust(w[i]) for i, c in enumerate(r))
    return [line(headers), "  " + "  ".join("-" * x for x in w)] + [line(r) for r in rows]


def slow_share(s, thr):
    """Доля замеров (в %), где задержка наружу не ниже порога thr."""
    if thr is None or not s["ext"]:
        return 0.0
    return pct(sum(1 for x in s["ext"] if x >= thr), len(s["ext"]))


def stat_row(label, s, with_dev, thr=None, with_dns=False, with_ctl=False):
    row = [label, str(s["n"]), f"{pct(s['bad'], s['n']):.2f}",
           f"{pct(s['black_sec'], s['sec']):.2f}",
           ms(quantile(s["rtt"], 0.5)), ms(quantile(s["rtt"], 0.95)),
           ms(quantile(s["ext"], 0.5)), ms(quantile(s["ext"], 0.95)),
           f"{slow_share(s, thr):.2f}"]
    if with_dns:
        row.append(f"{pct(s['dns_lost'], s['dns_try']):.2f}" if s["dns_try"] else "—")
    if with_ctl:
        row.append(f"{pct(s['ctl_lost'], s['ctl_try']):.2f}" if s["ctl_try"] else "—")
    if with_dev:
        row.append(f"{s['dev_sum'] / s['dev_n']:.0f}" if s["dev_n"] else "—")
    row.append(str(s["outages"]))
    return row


def outage_verdict(e, base):
    """Что можно утверждать о причине полного обрыва. base — обычная
    (медианная за весь период) задержка ответа роутера по локальной сети."""
    share_down = e["gw_down"] / e["n"] if e["n"] else 0
    around = e["pre"][-24:] + e["rtts"]
    rtt = statistics.median(around) if around else None
    slow = (rtt is not None and base is not None
            and rtt >= max(3 * base, base + 20))
    if share_down >= 0.5:
        return ("router",
                "роутер не отвечал и по локальной сети — он завис "
                "или перезагрузился. Проверить: время работы (uptime) "
                "и журнал в интерфейсе роутера",
                "router lokal şəbəkədə də cavab vermirdi — donub və ya "
                "yenidən yüklənib. Yoxlamaq lazımdır: routerin interfeysində "
                "iş vaxtı (uptime) və jurnal")
    if slow or e["gw_down"] > 0:
        why, why_az = [], []
        if slow:
            why.append(f"отвечал по локальной сети за {rtt:.0f} мс "
                       f"при обычных {base:.0f} мс")
            why_az.append(f"lokal şəbəkədə {rtt:.0f} ms gecikmə ilə cavab "
                          f"verirdi (adətən {base:.0f} ms)")
        if e["gw_down"] > 0:
            why.append(f"не ответил на {e['gw_down']} из {e['n']} локальных запросов")
            why_az.append(f"{e['n']} lokal sorğudan {e['gw_down']} dənəsi "
                          "cavabsız qaldı")
        return ("router_load",
                "роутер " + ", ".join(why) + " — признак перегрузки роутера",
                "router " + ", ".join(why_az)
                + " — routerin həddən artıq yüklənməsinin əlaməti")
    return ("unknown",
            "роутер отвечал по локальной сети нормально, трафик "
            "наружу не шёл — роутер (NAT/WAN) или провайдер, "
            "этим замером не различить",
            "router lokal şəbəkədə normal cavab verirdi, lakin trafik xaricə "
            "getmirdi — router (NAT/WAN) və ya provayder; bu ölçmə ilə ayırd "
            "etmək mümkün deyil")


VM_OUI = ("005056", "000c29", "000569", "001c14")      # VMware


def mac_fmt(m):
    return ":".join(m[i:i + 2] for i in range(0, 12, 2))


def dev_label(mac, ip, lang="ru"):
    tag = ""
    if ip == GATEWAY:
        tag = {"ru": ", главный роутер", "az": ", əsas router"}[lang]
    elif mac[:6] in VM_OUI:
        tag = {"ru": ", виртуальная машина", "az": ", virtual maşın"}[lang]
    return f"{ip} ({mac_fmt(mac)}{tag})"


def mac_label(A, mac, lang="ru"):
    """Подпись устройства по MAC: с адресом, если он встречался в подсчётах."""
    ip = getattr(A, "mac_ip", {}).get(mac)
    return dev_label(mac, ip, lang) if ip else mac_fmt(mac)


def fmt_bytes(n, lang="ru"):
    units = {"ru": ("МБ", "ГБ"), "az": ("MB", "GB")}[lang]
    if n >= 1024 ** 3:
        return f"{n / 1024 ** 3:.1f} {units[1]}".replace(".", ",")
    return f"{n / 1024 ** 2:.0f} {units[0]}"


def server_summary(A):
    """Состояние сервера: диск с рекомендацией и прогнозом по росту лога."""
    if A.sys_last is None:
        return None
    ts, y = A.sys_last
    total, free = y.get("disk_total", 0), y.get("disk_free", 0)
    if not total:
        return None
    used = total - free
    pct_used = 100.0 * used / total
    level = ("crit" if pct_used >= DISK_CRIT_PCT else
             "warn" if pct_used >= DISK_WARN_PCT else "ok")
    state = {"ok": {"ru": "места достаточно", "az": "yer kifayətdir"},
             "warn": {"ru": "место заканчивается", "az": "yer azalır"},
             "crit": {"ru": "диск почти заполнен",
                      "az": "disk demək olar ki, dolub"}}[level]
    rec = {"ok": {"ru": "Действий не требуется.",
                  "az": "Heç bir tədbir tələb olunmur."},
           "warn": {"ru": "В ближайшие недели стоит почистить диск или "
                          "расширить его.",
                    "az": "Yaxın həftələrdə diski təmizləmək və ya "
                          "genişləndirmək lazımdır."},
           "crit": {"ru": "Нужно почистить или расширить диск сейчас, иначе "
                          "сервер и сбор данных остановятся.",
                    "az": "Diski indi təmizləmək və ya genişləndirmək lazımdır, "
                          "əks halda server və məlumat toplanması dayanacaq."}}[level]
    out = {"total": total, "free": free, "used": used, "pct": round(pct_used, 1),
           "level": level, "state": state, "rec": rec, "log": None,
           "line": both(lambda lg: (
               f"Занято {fmt_bytes(used)} из {fmt_bytes(total)} "
               f"({pct_used:.0f}%), свободно {fmt_bytes(free)}" if lg == "ru" else
               f"{fmt_bytes(total, 'az')}-dan {fmt_bytes(used, 'az')} tutulub "
               f"({pct_used:.0f}%), {fmt_bytes(free, 'az')} boşdur"))}
    t0, y0 = A.sys_first
    span = (ts - t0).total_seconds()
    grow = y.get("log", 0) - y0.get("log", 0)
    if span >= 3600 and grow > 0:
        per_day = grow / span * 86400
        cap = per_day * RETAIN_DAYS              # сколько займёт лог за весь срок
        fits = cap - y.get("log", 0) < free
        out["log"] = {
            "ru": f"Лог диагностики занимает {fmt_bytes(y['log'])} и растёт "
                  f"примерно на {fmt_bytes(per_day)} в сутки. Хранятся последние "
                  f"{RETAIN_DAYS} дней, поэтому он займёт не больше "
                  f"≈{fmt_bytes(cap)}"
                  + (" — места достаточно." if fits else
                     " — столько свободного места нет: нужно уменьшить срок "
                     "хранения (RETAIN_DAYS)."),
            "az": f"Diaqnostika jurnalı {fmt_bytes(y['log'], 'az')} yer tutur və "
                  f"sutkada təxminən {fmt_bytes(per_day, 'az')} artır. Son "
                  f"{RETAIN_DAYS} gün saxlanılır, ona görə də o, təxminən "
                  f"{fmt_bytes(cap, 'az')}-dan çox yer tutmayacaq"
                  + (" — yer kifayətdir." if fits else
                     " — bu qədər boş yer yoxdur: saxlama müddətini azaltmaq "
                     "lazımdır (RETAIN_DAYS).")}
    return out


def extra_findings(A):
    """Итоги дополнительных проверок в виде, общем для текста и HTML."""
    mute = [(e["start"] - timedelta(minutes=5), e["end"] + timedelta(minutes=15))
            for e in A.events if e.get("gw_down", 0) > 0]
    resets = [{"ts": ts, "up": up, "reboot": any(a <= ts <= b for a, b in mute)}
              for ts, up in A.wan_resets]
    infra, n_infra = [], 0
    if A.dv_scans >= INFRA_MIN_SCANS:
        for mac, d in A.devtab.items():
            if d["n"] < INFRA_SHARE * A.dv_scans:
                continue
            n_infra += 1
            gone = list(d["abs"])
            if d["miss"] >= 2 and d["last"] is not None:
                gone.append((d["last"], None))
            for st, en in gone:
                infra.append({"mac": mac, "ip": d["ip"], "start": st, "end": en})
    infra.sort(key=lambda x: x["start"])
    return {"resets": resets, "infra": infra, "n_infra": n_infra,
            "drops": A.drops, "ip_changes": A.ip_changes}


def render(A):
    L = []
    T = A.total
    base = quantile(T["rtt"], 0.5)
    with_dev = T["dev_n"] > 0
    with_dns = A.has_rdns
    with_ctl = T["ctl_try"] > 0
    ext_base = quantile(T["ext"], 0.5)
    thr = (max(SLOW_FACTOR * ext_base, ext_base + SLOW_MIN_MS)
           if ext_base is not None else None)

    outages = [e for e in A.events if e["kind"] == "outage"]
    blips = [e for e in A.events if e["kind"] == "blip"]
    longer = lambda k: [e for e in A.events
                        if e["kind"] == k and e["dur"] >= OUTAGE_MIN_SEC]
    dns_ev, part_ev, mute_ev = longer("dns"), longer("partial"), longer("gwmute")
    for e in outages:
        e["verdict"], e["text"], e["text_az"] = outage_verdict(e, base)
        st = e["start"]
        groups = [T, A.hour[st.hour], A.wd[st.weekday()], A.day[st.date()]]
        if e["dev"] is not None and with_dev:
            groups.append(A.bucket[bucket_of(e["dev"])])
        for s in groups:
            s["outages"] += 1
    n_router = sum(1 for e in outages if e["verdict"] == "router")
    n_load = sum(1 for e in outages if e["verdict"] == "router_load")
    n_unknown = sum(1 for e in outages if e["verdict"] == "unknown")

    # ---------- шапка ----------
    L.append("ОТЧЁТ NETDIAG")
    L.append(f"Период: с {fmt_dt(A.first)} по {fmt_dt(A.last)}")
    L.append(f"Чистое время наблюдения: {fmt_dur(T['sec'])}, замеров: {T['n']}.")
    L.append("")
    L.append("КАК ИЗМЕРЯЛОСЬ")
    L.append(f"  Сервер подключён к роутеру {GATEWAY} проводом. Каждые {INTERVAL_SEC} сек:")
    L.append(f"    - TCP-подключение к роутеру ({GATEWAY}:80 и :443) — отвечает ли")
    L.append("      он по локальной сети и с какой задержкой;")
    if A.has_rdns:
        L.append(f"    - DNS-запрос к роутеру ({GATEWAY}:53) — работает ли его DNS;")
        if with_ctl:
            L.append("    - тот же DNS-запрос напрямую к 8.8.8.8, мимо DNS роутера —")
            L.append("      контроль: исправен ли при этом сам канал;")
    L.append("    - TCP-подключение к 6 внешним ресурсам (8.8.8.8, 1.1.1.1, 9.9.9.9,")
    L.append("      google.com, cloudflare.com, github.com) — идёт ли трафик наружу.")
    if with_dev:
        L += wrap(f"Раз в {DEVICE_SCAN_SEC} сек сервер опрашивал по ARP сеть "
                  f"{LAN_NET}. Постоянных устройств (серверы, виртуальные машины, "
                  f"роутеры, камеры — отвечают почти всегда): {A.n_const}; они из "
                  "подсчёта исключены. «Устр. людей» в таблицах — устройства "
                  "людей, видимые в этой сети.", 76, "  ", "  ")
        if HIDDEN_SUBNETS:
            L += wrap(f"ВАЖНО: большинство устройств людей подключено через "
                      f"вложенные роутеры (подсеть {', '.join(HIDDEN_SUBNETS)}) и "
                      "серверу не видно — каждый такой роутер виден как одно "
                      "устройство. Видимое число — малая часть: за период в "
                      f"основной сети было не больше {T['dev_max']} устройств "
                      "людей одновременно.", 76, "  ", "  ")
    else:
        L.append("  Числа устройств в этих данных нет — нагрузка оценивается по")
        L.append("  времени суток.")
    L.append("")

    if A.gaps:
        L.append("ПЕРЕРЫВЫ В НАБЛЮДЕНИИ (сервер не работал, сбоями не считаются)")
        for st, en, dt in A.gaps:
            L.append(f"  с {fmt_dt(st)} по {fmt_dt(en)} ({fmt_dur(dt)})")
        L.append("")

    # ---------- итог ----------
    L.append("ИТОГ")
    black_total = sum(e["sec"]["blackout"] for e in outages)
    L.append(f"  Полных обрывов интернета (от {OUTAGE_MIN_SEC} сек): {len(outages)}"
             + (f", суммарно {fmt_dur(black_total)}." if outages else "."))
    if outages:
        L.append(f"    роутер не отвечал и по локальной сети:           {n_router}")
        L.append(f"    роутер отвечал с задержкой/перебоями (перегрузка): {n_load}")
        L.append(f"    роутер отвечал нормально (роутер или провайдер):  {n_unknown}")
    L.append(f"  Коротких обрывов (до {OUTAGE_MIN_SEC} сек): {len(blips)}.")
    if A.has_rdns:
        L.append(f"  Отказов DNS роутера при работающем интернете: {len(dns_ev)}"
                 + (f", суммарно {fmt_dur(sum(e['dur'] for e in dns_ev))}." if dns_ev else "."))
    else:
        L.append(f"  Сбоев разрешения имён при работающем интернете: {len(dns_ev)}"
                 + (f", суммарно {fmt_dur(sum(e['dur'] for e in dns_ev))}." if dns_ev else "."))
    L.append(f"  Частичных потерь связи: {len(part_ev)}"
             + (f", суммарно {fmt_dur(sum(e['dur'] for e in part_ev))}." if part_ev else "."))
    L.append(f"  Роутер молчал по локальной сети при работающем интернете: {len(mute_ev)}"
             + (f", суммарно {fmt_dur(sum(e['dur'] for e in mute_ev))}." if mute_ev else "."))
    L.append("")
    L.append(f"  Интернет был доступен {100 - pct(T['black_sec'], T['sec']):.3f}% времени.")
    L.append(f"  Замеров с любыми отклонениями: {pct(T['bad'], T['n']):.2f}%.")
    L += wrap(f"Ответ роутера по локальной сети: обычно {ms(base)} мс, "
              f"в 5% худших замеров от {ms(quantile(T['rtt'], 0.95))} мс, "
              f"максимум {ms(max(T['rtt']) if T['rtt'] else None)} мс.", 76, "  ", "    ")
    L += wrap(f"Задержка до внешних ресурсов: обычно {ms(ext_base)} мс, "
              f"в 5% худших замеров от {ms(quantile(T['ext'], 0.95))} мс, "
              f"максимум {ms(max(T['ext']) if T['ext'] else None)} мс.", 76, "  ", "    ")
    if thr is not None:
        n_slow = sum(1 for x in T["ext"] if x >= thr)
        L += wrap(f"Медленных замеров (задержка наружу от {thr:.0f} мс): "
                  f"{n_slow} из {len(T['ext'])} ({pct(n_slow, len(T['ext'])):.2f}%).",
                  76, "  ", "    ")
    if with_dns:
        L += wrap(f"DNS роутера: без ответа {T['dns_lost']} из {T['dns_try']} "
                  f"запросов ({pct(T['dns_lost'], T['dns_try']):.2f}%).", 76, "  ", "    ")
    if with_ctl:
        L += wrap(f"Контрольный DNS (8.8.8.8 напрямую): без ответа {T['ctl_lost']} "
                  f"из {T['ctl_try']} запросов "
                  f"({pct(T['ctl_lost'], T['ctl_try']):.2f}%).", 76, "  ", "    ")
    if A.rdns_n and not A.rdns_ok:
        L.append(f"  DNS роутера ({GATEWAY}:53) не ответил ни разу — вероятно, он")
        L.append("  выключен; эта проверка в отчёте не учитывается.")
    L.append("")

    head = ["", "замеров", "отклон.,%", "обрыв,%", "роутер,мс", "95%,мс",
            "наружу,мс", "95%,мс", "медл.,%"]
    if with_dns:
        head.append("DNS пот.,%")
    if with_ctl:
        head.append("контр.,%")
    if with_dev:
        head.append("устр. людей")
    head.append("обрывов")
    legend = [
        "  отклон. — доля замеров с любым отклонением; обрыв — доля времени без",
        "  интернета; роутер — обычная задержка ответа роутера по локальной сети",
        "  и граница 5% худших замеров; наружу — то же до внешних ресурсов;",
        "  медл. — доля медленных замеров; DNS пот. — доля DNS-запросов к",
        "  роутеру, оставшихся без ответа; контр. — то же для запросов напрямую",
        "  к 8.8.8.8; устр. людей — в среднем видимых устройств людей в",
        "  основной сети (без постоянных); обрывов — число полных обрывов.",
    ]

    # ---------- дополнительные проверки ----------
    F = A.findings = extra_findings(A)
    X = []
    if A.upnp_n:
        X.append(f"  Роутер по UPnP опрошен {A.upnp_n} раз.")
        X.append(f"    Переустановок соединения с провайдером: {len(F['resets'])}")
        for r in F["resets"][:MAX_EVENTS_LISTED]:
            X += wrap(f"{fmt_dt(r['ts'])} (до этого держалось {fmt_dur(r['up'])}) — "
                      + ("роутер пропадал из локальной сети: перезагрузка роутера"
                         if r["reboot"] else
                         "роутер по локальной сети отвечал: переподключилась линия"),
                      76, "      ", "        ")
        if F["ip_changes"]:
            X.append(f"    Смен внешнего адреса: {len(F['ip_changes'])}")
        if A.wan_down_polls:
            X.append(f"    Опросов, когда роутер сообщал «нет соединения»: {A.wan_down_polls}")
        if T["tr_sec"]:
            X.append(f"    Трафик в среднем: к нам {T['rx_bits'] / T['tr_sec'] / 1e6:.1f} Мбит/с, "
                     f"от нас {T['tx_bits'] / T['tr_sec'] / 1e6:.1f} Мбит/с.")
    if T["b_n"]:
        X += wrap(f"Серии быстрых проб ({BURST_COUNT} подключений подряд раз в "
                  f"{BURST_SEC} сек): потеряно {T['b_lost']} из {T['b_n']} "
                  f"({pct(T['b_lost'], T['b_n']):.2f}%); худшая задержка "
                  f"{ms(max(T['b_max']) if T['b_max'] else None)} мс.", 76, "  ", "    ")
    if A.dv_scans:
        X.append(f"  Состав устройств: замечено разных — {len(A.devtab)}, "
                 f"постоянных — {F['n_infra']}.")
        X.append(f"    Постоянные устройства пропадали из сети: {len(F['infra'])}")
        for i in F["infra"][:MAX_EVENTS_LISTED]:
            till = (f"по {fmt_dt(i['end'])} ({fmt_dur((i['end'] - i['start']).total_seconds())})"
                    if i["end"] else "и до конца периода не вернулось")
            X += wrap(f"{dev_label(i['mac'], i['ip'])}: с {fmt_dt(i['start'])} {till}",
                      76, "      ", "        ")
        X.append(f"    Массовых отключений с возвратом устройств: {len(F['drops'])}")
        for ts, left, tot, back in F["drops"][:MAX_EVENTS_LISTED]:
            X.append(f"      {fmt_dt(ts)}: пропало {left} из {tot}, "
                     f"вернулось {back} за {DROP_BACK_SCANS} мин")
    if A.bc_pps:
        for st in A.storms:
            a = st["start"] - timedelta(seconds=60)
            b = st["end"] + timedelta(seconds=60)
            st["hit"] = any(e["start"] <= b and e["end"] >= a for e in A.events
                            if e["kind"] in ("outage", "blip", "dns", "partial",
                                             "gwmute"))
        n_hit = sum(1 for st in A.storms if st["hit"])
        X += wrap(f"Широковещательные и групповые пакеты в основной сети "
                  f"(сервер только слушает): обычно {quantile(A.bc_pps, 0.5):.0f} "
                  f"в секунду, максимум {max(A.bc_pps):.0f} в секунду (в среднем "
                  f"за минуту). Всплесков от {STORM_PPS} в секунду — признак петли "
                  f"или шторма: {len(A.storms)}"
                  + (f", из них совпали со сбоями: {n_hit}." if A.storms else "."),
                  76, "  ", "    ")
        for st in A.storms[:MAX_EVENTS_LISTED]:
            who = (f"; больше всех слал {mac_label(A, st['top'][0][0])}"
                   if st["top"] else "")
            X += wrap(f"с {fmt_dt(st['start'])} по {fmt_dt(st['end'])}: до "
                      f"{st['pps']:.0f} пакетов в секунду{who}; "
                      + ("в это время был сбой." if st["hit"] else
                         "сбоев в это время не было."), 76, "      ", "        ")
    if A.dv_scans:
        X += wrap(f"Многократные ответы на один ARP-запрос (от {ARP_DUP_MIN}; "
                  f"признак петли): {len(A.arpdups)}.", 76, "  ", "    ")
        for ts, ip, mac, n in A.arpdups[:MAX_EVENTS_LISTED]:
            X += wrap(f"{fmt_dt(ts)}: {dev_label(mac, ip)} — "
                      f"{plural(n, 'ответ', 'ответа', 'ответов')}",
                      76, "      ", "        ")
    SV = A.server = server_summary(A)
    if T["sys_n"]:
        L.append("СЕРВЕР ДИАГНОСТИКИ")
        L.append(f"  Процессор: в среднем {T['cpu_sum'] / T['sys_n']:.0f}%, "
                 f"максимум {T['cpu_max']:.0f}%.")
        L.append(f"  Память: в среднем {T['mem_sum'] / T['sys_n']:.0f}%, "
                 f"максимум {T['mem_max']:.0f}%.")
        if SV:
            L += wrap(f"Диск: {SV['line']['ru'][0].lower()}{SV['line']['ru'][1:]} — "
                      f"{SV['state']['ru']}. {SV['rec']['ru']}", 76, "  ", "    ")
            if SV["log"]:
                L += wrap(SV["log"]["ru"], 76, "  ", "    ")
        L.append("")
    SEC = getattr(A, "security", None)
    A.sec_lines = security_lines(SEC)
    if A.sec_lines:
        L.append("БЕЗОПАСНОСТЬ СЕРВЕРА (за период отчёта)")
        for ln in A.sec_lines:
            L += wrap(ln["ru"], 76, "  ", "    ")
        L.append("")
    if X:
        L.append("ДОПОЛНИТЕЛЬНЫЕ ПРОВЕРКИ")
        L += X
        L.append("")

    # Таблицы по числу устройств нет: большая часть устройств не видна
    # (за вложенными роутерами), и неполное число не годится как мера нагрузки.
    # ---------- по часам ----------
    L.append("ПО ЧАСАМ СУТОК")
    rows = [stat_row(f"{h:02d}:00", A.hour[h], with_dev, thr, with_dns, with_ctl)
            for h in range(24) if A.hour[h]["n"]]
    L += table(["час"] + head[1:], rows)
    L += legend
    L.append("")

    L.append("ПО ДНЯМ НЕДЕЛИ")
    rows = [stat_row(WD_NAMES[d], A.wd[d], with_dev, thr, with_dns, with_ctl)
            for d in range(7) if A.wd[d]["n"]]
    L += table(["день"] + head[1:], rows)
    L.append("")

    if len(A.day) > 1:
        L.append("ПО ДАТАМ")
        rows = []
        for d in sorted(A.day):
            s = A.day[d]
            r = [f"{d.strftime('%d.%m.%y')} {WD_NAMES[d.weekday()]}",
                 f"{pct(s['bad'], s['n']):.2f}", str(s["outages"]),
                 fmt_dur(s["black_sec"]) if s["black_sec"] else "—"]
            if with_dev:
                r.append(str(s["dev_max"]) if s["dev_n"] else "—")
            rows.append(r)
        h2 = ["дата", "отклон.,%", "обрывов", "без интернета"]
        if with_dev:
            h2.append("макс. устр. людей")
        L += table(h2, rows)
        L.append("")

    # ---------- список событий ----------
    def dev_txt(e):
        return (f", устройств людей в основной сети: {e['dev']}"
                if e["dev"] is not None and with_dev else "")

    if outages:
        L.append("ПОЛНЫЕ ОБРЫВЫ ИНТЕРНЕТА")
        for e in outages[:MAX_EVENTS_LISTED]:
            L.append(f"  {fmt_dt(e['start'])} — {fmt_dt(e['end'])} "
                     f"({fmt_dur(e['dur'])}, из них без интернета "
                     f"{fmt_dur(e['sec']['blackout'])}{dev_txt(e)})")
            L += wrap(e["text"][0].upper() + e["text"][1:] + ".", 76, "    ", "    ")
        if len(outages) > MAX_EVENTS_LISTED:
            L.append(f"  ... и ещё {len(outages) - MAX_EVENTS_LISTED}.")
        L.append("")

    other = [("ОТКАЗЫ DNS РОУТЕРА (интернет по IP работал)" if A.has_rdns
              else "СБОИ РАЗРЕШЕНИЯ ИМЁН (интернет по IP работал)", dns_ev),
             ("ЧАСТИЧНЫЕ ПОТЕРИ СВЯЗИ (недоступна часть внешних ресурсов)", part_ev),
             ("РОУТЕР МОЛЧАЛ ПО ЛОКАЛЬНОЙ СЕТИ (интернет работал)", mute_ev)]
    for title, evs in other:
        if not evs:
            continue
        L.append(title)
        for e in evs[:MAX_EVENTS_LISTED]:
            L.append(f"  {fmt_dt(e['start'])} — {fmt_dt(e['end'])} "
                     f"({fmt_dur(e['dur'])}{dev_txt(e)})")
            if evs is dns_ev and e["ctl_try"]:
                L.append("    Контрольный DNS в это время "
                         + ("отвечал — отказ на стороне роутера."
                            if e["ctl_lost"] == 0 else
                            f"тоже терял запросы ({e['ctl_lost']} из {e['ctl_try']})."))
        if len(evs) > MAX_EVENTS_LISTED:
            L.append(f"  ... и ещё {len(evs) - MAX_EVENTS_LISTED}.")
        L.append("")

    # ---------- выводы ----------
    L.append("ЧТО ИЗ ЭТОГО СЛЕДУЕТ")
    C, CA = [], []                    # выводы: по-русски и по-азербайджански

    def say(ru, az):
        C.append(ru)
        CA.append(az)

    if (not A.events and T["bad"] == 0
            and not (F["resets"] or F["infra"] or F["drops"])):
        say("По проводу сбоев не зафиксировано. Если жалобы в этот период "
            "были, их причина в беспроводной части сети, которую этот "
            "замер не видит.",
            "Kabel üzrə nasazlıq qeydə alınmayıb. Əgər bu dövrdə şikayətlər "
            "olubsa, səbəb şəbəkənin simsiz hissəsindədir — bu ölçmə onu görmür.")
    dns_sure = [e for e in dns_ev
                if A.has_rdns and e["ctl_try"] and e["ctl_lost"] == 0]
    dns_chan = [e for e in dns_ev if e["ctl_try"] and e["ctl_lost"] > 0]
    dns_open = [e for e in dns_ev if not e["ctl_try"]]
    certain = n_router + len(mute_ev) + len(dns_sure)
    if certain:
        bits, bits_az = [], []
        if n_router:
            bits.append(f"{n_router} — обрывы, при которых роутер не отвечал "
                        "и по локальной сети")
            bits_az.append(f"{n_router} — routerin lokal şəbəkədə də cavab "
                           "vermədiyi kəsilmələr")
        if dns_sure:
            bits.append(f"{len(dns_sure)} — отказы DNS роутера, при которых "
                        "контрольный DNS-запрос мимо роутера проходил "
                        + ("(для устройств, получающих DNS от роутера, это "
                           "выглядит как пропавший интернет)"
                           if CLIENTS_USE_ROUTER_DNS else
                           "(устройства академии получают DNS 8.8.8.8 и роутер "
                           "обходят, людей это не задевает; это показатель "
                           "состояния самого роутера)"))
            bits_az.append(f"{len(dns_sure)} — routerin DNS-i cavab vermədiyi, "
                           "lakin routerdən yan keçən nəzarət DNS sorğusunun "
                           "keçdiyi hallar "
                           + ("(DNS-i routerdən alan cihazlar üçün bu, "
                              "internetin itməsi kimi görünür)"
                              if CLIENTS_USE_ROUTER_DNS else
                              "(akademiyanın cihazları DNS kimi 8.8.8.8 alır və "
                              "routerin DNS-indən istifadə etmir, insanlara bu "
                              "təsir etmir; bu, routerin öz vəziyyətinin "
                              "göstəricisidir)"))
        if mute_ev:
            bits.append(f"{len(mute_ev)} — роутер переставал отвечать на локальные "
                        "запросы при работающем интернете")
            bits_az.append(f"{len(mute_ev)} — internet işləyərkən router lokal "
                           "sorğulara cavab verməyi dayandırıb")
        say(f"Событий, которые относятся к роутеру однозначно: {certain} ("
            + "; ".join(bits) + ").",
            f"Birmənalı olaraq routerə aid hadisələr: {certain} ("
            + "; ".join(bits_az) + ").")
    if dns_chan:
        say(f"Отказов DNS, при которых не отвечал и контрольный запрос "
            f"мимо роутера: {len(dns_chan)}. В эти моменты сбоил канал "
            "целиком, а не только DNS роутера: причина в роутере как "
            "маршрутизаторе или у провайдера.",
            f"Routerdən yan keçən nəzarət sorğusunun da cavabsız qaldığı DNS "
            f"nasazlıqları: {len(dns_chan)}. Bu anlarda təkcə routerin DNS-i "
            "deyil, bütün kanal nasaz idi: səbəb ya marşrutlaşdırıcı kimi "
            "routerdə, ya da provayderdədir.")
    if dns_open:
        say(f"Отказов DNS роутера без контрольного замера: {len(dns_open)}. "
            "Канал по IP в это время работал, но роутер пересылает "
            "DNS-запросы серверу провайдера, поэтому по этим случаям "
            "нельзя исключить, что не отвечал он, а не роутер.",
            f"Nəzarət ölçməsi olmadan qeydə alınan router DNS nasazlıqları: "
            f"{len(dns_open)}. Bu vaxt IP üzrə kanal işləyirdi, lakin router "
            "DNS sorğularını provayderin serverinə ötürür, ona görə də bu "
            "hallarda cavab verməyənin router deyil, həmin server olduğunu "
            "istisna etmək olmaz.")
    if with_ctl and T["dnsc_try"]:
        # сравниваем только те замеры, где работали обе проверки
        d_r = pct(T["dnsc_lost"], T["dnsc_try"])
        d_c = pct(T["ctl_lost"], T["ctl_try"])
        scope = (f"За время, когда работали обе проверки "
                 f"({T['dnsc_try']} запросов к роутеру и {T['ctl_try']} мимо него), ")
        scope_az = (f"Hər iki yoxlamanın işlədiyi müddətdə (routerə "
                    f"{T['dnsc_try']} sorğu, ondan yan keçərək {T['ctl_try']} sorğu) ")
        if d_r >= 0.3 and d_r >= 3 * max(d_c, 0.05):
            say(scope + f"DNS роутера не ответил на {d_r:.2f}% запросов, "
                f"а запрос мимо роутера — на {d_c:.2f}%. Канал исправен, "
                "потери возникают в роутере или у DNS-сервера, которому он "
                "пересылает запросы.",
                scope_az + f"cavabsız qalan sorğuların payı: routerin DNS-i "
                f"üzrə {d_r:.2f}%, routerdən yan keçən sorğular üzrə "
                f"{d_c:.2f}%. Kanal sazdır, itkilər routerdə və ya onun "
                "sorğuları ötürdüyü DNS serverində yaranır.")
        elif d_c >= 0.3:
            say(scope + f"без ответа остались {d_r:.2f}% запросов к DNS "
                f"роутера и {d_c:.2f}% запросов мимо него. Теряются и те, "
                "и другие: причина в канале, а не в DNS роутера.",
                scope_az + f"cavabsız qalan sorğuların payı: routerin DNS-i "
                f"üzrə {d_r:.2f}%, ondan yan keçən sorğular üzrə {d_c:.2f}%. "
                "Hər ikisi itir: səbəb routerin DNS-ində deyil, kanaldadır.")
        else:
            say(scope + f"потери малы и одинаковы: {d_r:.2f}% у DNS роутера "
                f"и {d_c:.2f}% мимо него. Часы с высокой нагрузкой в это "
                "сравнение могли ещё не попасть.",
                scope_az + f"itkilər azdır və eynidir: routerin DNS-i üzrə "
                f"{d_r:.2f}%, ondan yan keçərək {d_c:.2f}%. Yüksək yüklənmə "
                "saatları hələ bu müqayisəyə düşməmiş ola bilər.")
    if n_load:
        say(f"Ещё {plural(n_load, 'обрыв сопровождался', 'обрыва сопровождались', 'обрывов сопровождались')} "
            "замедлением или перебоями "
            "ответа роутера по локальной сети. Это признак перегрузки "
            "роутера, но не строгое доказательство.",
            f"Daha {n_load} kəsilmə routerin lokal şəbəkədə ləng və ya "
            "fasilələrlə cavab verməsi ilə müşayiət olunub. Bu, routerin "
            "həddən artıq yüklənməsinin əlamətidir, lakin qəti sübut deyil.")

    if A.storms:
        n_hit = sum(1 for st in A.storms if st["hit"])
        say(f"Всплесков широковещательного трафика (петля или шторм в локальной "
            f"сети): {len(A.storms)}, из них совпали со сбоями: {n_hit}. Это "
            "происходит внутри сети академии, провайдер к этому отношения не имеет."
            + (" Сбои во время всплесков объясняются ими." if n_hit else ""),
            f"Yayım trafikinin sıçrayışları (lokal şəbəkədə ilgək və ya fırtına): "
            f"{len(A.storms)}, onlardan nasazlıqlarla üst-üstə düşən: {n_hit}. Bu, "
            "akademiyanın şəbəkəsinin daxilində baş verir, provayderin buna "
            "aidiyyəti yoxdur."
            + (" Sıçrayışlar zamanı nasazlıqlar onlarla izah olunur." if n_hit else ""))

    # зависимость от нагрузки
    MIN_N = 720                      # не меньше часа наблюдений в группе
    lo = hi = None
    filled = []                      # число устройств неполное — сравниваем по часам
    if len(filled) >= 2:
        lo, hi = A.bucket[filled[0]], A.bucket[filled[-1]]
        lo_name = f"при {bucket_label(filled[0])} устройствах"
        hi_name = f"при {bucket_label(filled[-1])} устройствах"
        lo_az = f"{bucket_label(filled[0])} cihaz olduqda"
        hi_az = f"{bucket_label(filled[-1])} cihaz olduqda"
    else:
        work, off = _stat(), _stat()
        for h in range(24):
            dst = work if WORK_HOURS[0] <= h < WORK_HOURS[1] else off
            for k in ("n", "bad", "sec", "black_sec", "outages",
                      "dns_try", "dns_lost", "ctl_try", "ctl_lost",
                      "dnsc_try", "dnsc_lost"):
                dst[k] += A.hour[h][k]
            dst["rtt"].extend(A.hour[h]["rtt"])
            dst["ext"].extend(A.hour[h]["ext"])
        if work["n"] >= MIN_N and off["n"] >= MIN_N:
            lo, hi = off, work
            lo_name = "в остальное время"
            hi_name = f"с {WORK_HOURS[0]:02d}:00 до {WORK_HOURS[1]:02d}:00"
            lo_az = "qalan vaxtda"
            hi_az = f"{WORK_HOURS[0]:02d}:00–{WORK_HOURS[1]:02d}:00 arasında"
        else:
            say(f"Для сравнения нагрузки нужны данные и за рабочие часы "
                f"({WORK_HOURS[0]:02d}:00–{WORK_HOURS[1]:02d}:00), и за "
                f"нерабочие — не меньше часа каждого. Пока их недостаточно.",
                f"Yüklənməni müqayisə etmək üçün həm iş saatları "
                f"({WORK_HOURS[0]:02d}:00–{WORK_HOURS[1]:02d}:00), həm də "
                f"qeyri-iş saatları üzrə ən azı bir saatlıq məlumat lazımdır. "
                f"Hələlik kifayət deyil.")
    if lo is not None:
        p_lo, p_hi = pct(lo["bad"], lo["n"]), pct(hi["bad"], hi["n"])
        r_lo, r_hi = quantile(lo["rtt"], 0.5), quantile(hi["rtt"], 0.5)
        facts = (f"доля замеров с отклонениями {hi_name} — {p_hi:.2f}%, "
                 f"{lo_name} — {p_lo:.2f}%; полных обрывов {hi['outages']} "
                 f"против {lo['outages']}")
        facts_az = (f"kənarlaşma olan ölçmələrin payı {hi_az} — {p_hi:.2f}%, "
                    f"{lo_az} — {p_lo:.2f}%; tam kəsilmələrin sayı: "
                    f"{hi['outages']} və {lo['outages']}")
        if p_hi >= 0.3 and p_hi >= 3 * max(p_lo, 0.01):
            say("Сбои зависят от нагрузки: " + facts + ". Провайдер не знает, "
                "сколько устройств в локальной сети, поэтому такая "
                "зависимость указывает на оборудование внутри сети.",
                "Nasazlıqlar yüklənmədən asılıdır: " + facts_az + ". Provayder "
                "lokal şəbəkədə neçə cihaz olduğunu bilmir, ona görə də belə "
                "asılılıq şəbəkə daxilindəki avadanlığa işarə edir.")
        else:
            say("Зависимости сбоев от нагрузки не видно: " + facts + ". "
                "Эти данные не подтверждают, что роутер не справляется "
                "с нагрузкой.",
                "Nasazlıqların yüklənmədən asılılığı görünmür: " + facts_az
                + ". Bu məlumatlar routerin yüklənmənin öhdəsindən gəlmədiyini "
                "təsdiqləmir.")
        if r_lo and r_hi and r_hi >= max(2 * r_lo, r_lo + 5):
            say(f"Роутер под нагрузкой отвечает медленнее: обычная задержка "
                f"по локальной сети {r_hi:.0f} мс {hi_name} против "
                f"{r_lo:.0f} мс {lo_name}.",
                f"Yüklənmə zamanı router daha ləng cavab verir: lokal şəbəkədə "
                f"adi gecikmə {hi_az} {r_hi:.0f} ms, {lo_az} {r_lo:.0f} ms.")
        s_lo, s_hi = slow_share(lo, thr), slow_share(hi, thr)
        if s_hi >= 0.5 and s_hi >= 3 * max(s_lo, 0.05):
            say(f"Под нагрузкой интернет замедляется: медленных замеров "
                f"{s_hi:.2f}% {hi_name} против {s_lo:.2f}% {lo_name}.",
                f"Yüklənmə zamanı internet ləngiyir: ləng ölçmələrin payı "
                f"{hi_az} {s_hi:.2f}%, {lo_az} {s_lo:.2f}%.")
        if with_dns and lo["dns_try"] >= MIN_N and hi["dns_try"] >= MIN_N:
            d_lo = pct(lo["dns_lost"], lo["dns_try"])
            d_hi = pct(hi["dns_lost"], hi["dns_try"])
            if d_hi >= 0.5 and d_hi >= 3 * max(d_lo, 0.05):
                say(f"DNS роутера под нагрузкой теряет запросы чаще: "
                    f"{d_hi:.2f}% {hi_name} против {d_lo:.2f}% {lo_name}.",
                    f"Yüklənmə zamanı routerin DNS-i sorğuları daha tez-tez "
                    f"itirir: {hi_az} {d_hi:.2f}%, {lo_az} {d_lo:.2f}%.")
            else:
                say(f"Потери DNS роутера от нагрузки не зависят: "
                    f"{d_hi:.2f}% {hi_name} и {d_lo:.2f}% {lo_name}.",
                    f"Routerin DNS itkiləri yüklənmədən asılı deyil: "
                    f"{hi_az} {d_hi:.2f}%, {lo_az} {d_lo:.2f}%.")
    if F["resets"]:
        nr = sum(1 for r in F["resets"] if r["reboot"])
        nw = len(F["resets"]) - nr
        say(f"Счётчик соединения роутера с провайдером обнулялся "
            f"{plural(len(F['resets']), 'раз', 'раза', 'раз')}: {nr} — вместе с пропаданием роутера из "
            f"локальной сети (перезагрузка роутера), {nw} — при отвечающем "
            "роутере (переподключение линии провайдера).",
            f"Routerin provayderlə əlaqə sayğacı {len(F['resets'])} dəfə "
            f"sıfırlanıb: {nr} dəfə router lokal şəbəkədən itməklə birlikdə "
            f"(routerin yenidən yüklənməsi), {nw} dəfə router cavab verərkən "
            "(provayder xəttinin yenidən qoşulması).")
    if F["infra"]:
        say(f"Постоянные устройства сети пропадали "
            f"{plural(len(F['infra']), 'раз', 'раза', 'раз')} "
            "(список в событиях). Если среди них точки доступа, в это время "
            "их зона оставалась без Wi-Fi.",
            f"Şəbəkənin daimi cihazları {len(F['infra'])} dəfə itib (siyahı "
            "hadisələrdədir). Onların arasında giriş nöqtələri varsa, həmin "
            "vaxt onların əhatə zonası Wi-Fi-sız qalıb.")
    if F["drops"]:
        say(f"Массовых отключений устройств: {len(F['drops'])}. Много устройств "
            "одновременно пропало и вскоре вернулось — признак того, что "
            "точка доступа сбросила клиентов.",
            f"Cihazların kütləvi ayrılması: {len(F['drops'])}. Bir çox cihazın "
            "eyni anda itib tezliklə qayıtması giriş nöqtəsinin müştəriləri "
            "atmasının əlamətidir.")
    if T["b_n"] and pct(T["b_lost"], T["b_n"]) >= 0.5:
        bl = pct(T["b_lost"], T["b_n"])
        say(f"В сериях быстрых проб потеряно {bl:.2f}% подключений: есть "
            "короткие замирания, которые обычный замер раз в "
            f"{INTERVAL_SEC} секунд не ловит.",
            f"Sürətli yoxlama seriyalarında itən qoşulmaların payı {bl:.2f}%: "
            f"{INTERVAL_SEC} saniyədə bir aparılan adi ölçmənin tutmadığı "
            "qısa donmalar var.")
    if SEC and SEC["syslog_stale"]:
        when = fmt_dt(SEC["syslog_last"])[:8] if SEC["syslog_last"] else None
        say("Системные журналы сервера "
            + (f"не пополняются с {when}" if when else "не ведутся")
            + ": блокировки файрвола и входы по SSH нигде не записываются в "
            "файлы. Стоит включить службу rsyslog.",
            "Serverin sistem jurnalları "
            + (f"{when} tarixindən yenilənmir" if when else "aparılmır")
            + ": faervol bloklamaları və SSH girişləri fayllara yazılmır. "
            "rsyslog xidmətini işə salmaq lazımdır.")
    if SEC and SEC["ban"]:
        bans = ", ".join(ip for ip, _n in SEC["banned"].most_common(5))
        say(f"fail2ban заблокировал адресов за подбор пароля: {SEC['ban']} ({bans}).",
            f"fail2ban parol seçmə cəhdinə görə bloklanan ünvanlar: {SEC['ban']} ({bans}).")
    if SV and SV["level"] != "ok":
        say(f"Диск сервера: {SV['state']['ru']} ({SV['pct']:.0f}% занято). "
            + SV["rec"]["ru"],
            f"Serverin diski: {SV['state']['az']} ({SV['pct']:.0f}% tutulub). "
            + SV["rec"]["az"])
    if T["sys_n"] and (T["cpu_sum"] / T["sys_n"] >= 70 or T["mem_sum"] / T["sys_n"] >= 85):
        say(f"Сервер диагностики сам загружен: процессор в среднем "
            f"{T['cpu_sum'] / T['sys_n']:.0f}%, память {T['mem_sum'] / T['sys_n']:.0f}%. "
            "Замеры задержек в такие периоды могут быть завышены.",
            f"Diaqnostika serverinin özü yüklənib: prosessor orta hesabla "
            f"{T['cpu_sum'] / T['sys_n']:.0f}%, yaddaş {T['mem_sum'] / T['sys_n']:.0f}%. "
            "Belə dövrlərdə gecikmə ölçmələri şişirdilmiş ola bilər.")
    if n_unknown:
        say(f"{plural(n_unknown, 'обрыв', 'обрыва', 'обрывов')} этим замером нельзя отнести ни к роутеру, "
            "ни к провайдеру: роутер отвечал нормально, а трафик наружу не "
            "шёл. Различить можно двумя способами: запросить у провайдера "
            "журнал состояния линии за указанные выше времена либо в момент "
            "сбоя посмотреть статус WAN в интерфейсе роутера.",
            f"{n_unknown} kəsilməni bu ölçmə ilə nə routerə, nə də provayderə "
            "aid etmək mümkün deyil: router normal cavab verirdi, lakin "
            "trafik xaricə getmirdi. Ayırd etməyin iki yolu var: provayderdən "
            "yuxarıda göstərilən vaxtlar üzrə xəttin vəziyyət jurnalını "
            "istəmək və ya nasazlıq anında routerin interfeysində WAN "
            "statusuna baxmaq.")
    if not C:
        say("Отклонения единичные; оснований для выводов о причине нет.",
            "Kənarlaşmalar təkdir; səbəb barədə nəticə çıxarmağa əsas yoxdur.")
    A.conclusions = C
    A.conclusions_az = CA
    for i, c in enumerate(C, 1):
        L += wrap(f"{i}. {c}", 76, "  ", "     ")
    L.append("")

    L.append("ЧЕГО ЭТОТ ОТЧЁТ НЕ ПОКАЗЫВАЕТ")
    L += wrap("- Качество Wi-Fi по комнатам: сервер подключён проводом. Для этого "
              "нужен такой же замер с устройства, подключённого по Wi-Fi.", 76, "  ", "    ")
    if HIDDEN_SUBNETS:
        L += wrap(f"- Устройства и сбои за дополнительным роутером (подсеть "
                  f"{', '.join(HIDDEN_SUBNETS)}): сервер стоит в основной сети и "
                  "видит только её.", 76, "  ", "    ")
    L += wrap(f"- Замирания короче {INTERVAL_SEC} секунд между сериями быстрых проб.",
              76, "  ", "    ")
    L += wrap("- Скорость: проверяется доступность и задержка, а не пропускная "
              "способность.", 76, "  ", "    ")
    return "\n".join(L) + "\n"


def wrap(text, width, first, rest):
    out, line = [], first
    for word in text.split():
        if len(line) + len(word) + 1 > width and line.strip():
            out.append(line.rstrip())
            line = rest
        line += word + " "
    out.append(line.rstrip())
    return out


# ============================================================
#  HTML-ОТЧЁТ С ГРАФИКАМИ
# ============================================================

TL_STEP_SEC = 300                      # базовый шаг временной шкалы
TL_STEPS_MIN = [5, 10, 15, 30, 60, 120, 180, 360, 720, 1440]
TL_MAX_POINTS = 200
TICK_STEPS_MIN = [15, 30, 60, 120, 180, 360, 720, 1440, 2880, 10080]


def tl_key(ts):
    """Номер 5-минутного интервала по местному времени."""
    return int((ts.timestamp() + ts.utcoffset().total_seconds()) // TL_STEP_SEC)


def _tl_time(sec):
    """Обратно из местных «секунд от эпохи» в наивное местное время."""
    return datetime(1970, 1, 1) + timedelta(seconds=sec)


def _merge(stats):
    m = _stat()
    for s in stats:
        for k in ("n", "bad", "sec", "black_sec", "dns_try", "dns_lost",
                  "ctl_try", "ctl_lost", "dev_sum", "dev_n",
                  "join", "left", "scans", "rx_bits", "tx_bits", "tr_sec",
                  "b_n", "b_lost", "cpu_sum", "mem_sum", "sys_n",
                  "bc_n", "bc_sec"):
            m[k] += s[k]
        m["bc_max"] = max(m["bc_max"], s["bc_max"])
        for k in ("rtt", "ext", "b_p50", "b_max"):
            m[k].extend(s[k])
    return m


def _r(x, nd=2):
    return None if x is None else round(x, nd)


def build_timeline(A):
    """Сводит 5-минутные интервалы в шкалу не длиннее TL_MAX_POINTS точек."""
    keys = sorted(A.tl)
    k0, k1 = keys[0], keys[-1]
    span_min = (k1 - k0 + 1) * TL_STEP_SEC / 60
    step_min = next((m for m in TL_STEPS_MIN if span_min / m <= TL_MAX_POINTS),
                    TL_STEPS_MIN[-1])
    per = step_min * 60 // TL_STEP_SEC             # 5-минуток в одной точке
    b0 = k0 // per
    nb = k1 // per - b0 + 1
    multi_day = span_min > 24 * 60
    points = []
    for i in range(nb):
        base = (b0 + i) * per
        m = _merge(A.tl[k] for k in range(base, base + per) if k in A.tl)
        t = _tl_time(base * TL_STEP_SEC)
        t2 = t + timedelta(minutes=step_min)
        label = (t.strftime("%d.%m %H:%M") if multi_day else t.strftime("%H:%M")) \
            + "–" + t2.strftime("%H:%M")
        if m["n"] == 0:
            points.append({"label": label, "n": 0})
            continue
        points.append({
            "label": label, "n": m["n"],
            "bad": _r(pct(m["bad"], m["n"])),
            "black": _r(pct(m["black_sec"], m["sec"])),
            "dns": _r(pct(m["dns_lost"], m["dns_try"])) if m["dns_try"] else None,
            "ctl": _r(pct(m["ctl_lost"], m["ctl_try"])) if m["ctl_try"] else None,
            "rm": _r(quantile(m["rtt"], 0.5), 1), "r95": _r(quantile(m["rtt"], 0.95), 1),
            "em": _r(quantile(m["ext"], 0.5), 1), "e95": _r(quantile(m["ext"], 0.95), 1),
            "dev": _r(m["dev_sum"] / m["dev_n"], 1) if m["dev_n"] else None,
            "join": _r(m["join"] / m["scans"], 2) if m["scans"] else None,
            "left": _r(m["left"] / m["scans"], 2) if m["scans"] else None,
            "rx": _r(m["rx_bits"] / m["tr_sec"] / 1e6, 2) if m["tr_sec"] else None,
            "tx": _r(m["tx_bits"] / m["tr_sec"] / 1e6, 2) if m["tr_sec"] else None,
            "bp50": _r(quantile(m["b_p50"], 0.5), 1),
            "bmax": _r(max(m["b_max"]), 1) if m["b_max"] else None,
            "cpu": _r(m["cpu_sum"] / m["sys_n"], 1) if m["sys_n"] else None,
            "mem": _r(m["mem_sum"] / m["sys_n"], 1) if m["sys_n"] else None,
            "bc": _r(m["bc_n"] / m["bc_sec"], 1) if m["bc_sec"] else None,
            "bcmax": _r(m["bc_max"], 1) if m["bc_sec"] else None,
        })

    start_sec = b0 * per * TL_STEP_SEC
    width_sec = nb * step_min * 60

    def pos(ts):                                   # положение на шкале, 0..nb
        local = ts.timestamp() + ts.utcoffset().total_seconds()
        return max(0.0, min(nb, (local - start_sec) / (step_min * 60)))

    tick_min = next((m for m in TICK_STEPS_MIN
                     if m >= step_min and width_sec / 60 / m <= 12),
                    TICK_STEPS_MIN[-1])
    ticks = []
    first = -(-start_sec // (tick_min * 60)) * tick_min * 60
    t = first
    while t <= start_sec + width_sec:
        d = _tl_time(t)
        if tick_min >= 1440:
            lab = d.strftime("%d.%m")
        elif multi_day and d.hour == 0 and d.minute == 0:
            lab = d.strftime("%d.%m")
        else:
            lab = d.strftime("%H:%M")
        ticks.append({"x": (t - start_sec) / (step_min * 60), "label": lab})
        t += tick_min * 60
    return points, ticks, pos, step_min


# ---------- короткий отчёт для руководства ----------
# Две части: сеть (что с ней не так) и сервер диагностики. В каждой —
# несколько фраз простым языком и один график. Всё подробное — в
# report-full.txt.

def _times(r):
    n = int(round(r))
    return f"{n} раза" if 2 <= n % 10 <= 4 and not 12 <= n % 100 <= 14 else f"{n} раз"


def _net_x(cidr):
    return cidr.split("/")[0].rsplit(".", 1)[0] + ".x"


def _day_night(A):
    """Статистика за часы занятий и за остальное время."""
    work, off = _stat(), _stat()
    for h in range(24):
        dst = work if WORK_HOURS[0] <= h < WORK_HOURS[1] else off
        for k in ("n", "bad", "dns_try", "dns_lost"):
            dst[k] += A.hour[h][k]
    return work, off


def brief(A):
    """Выводы для короткого отчёта: {"net": {...}, "srv": {...}}, каждая
    фраза — {"ru": ..., "az": ...}. Вызывать после render(A)."""
    T = A.total
    outages = [e for e in A.events if e["kind"] == "outage"]
    n_out = len(outages)
    black = sum(e["sec"]["blackout"] for e in outages)
    by_router = [e for e in outages if e.get("verdict") == "router"]
    net, bad_net = [], False

    # 1. обрывы
    if n_out:
        bad_net = True
        ru = (f"Интернет полностью пропадал {plural(n_out, 'раз', 'раза', 'раз')}, "
              f"всего на {fmt_dur(black)}.")
        az = (f"İnternet {n_out} dəfə tamamilə itib, cəmi "
              f"{fmt_dur(black, 'az')}.")
        if by_router:
            t = by_router[-1]["start"]
            last = t.strftime("%d.%m в %H:%M")
            last_az = t.strftime("%d.%m, saat %H:%M")
            if len(by_router) == n_out:
                ru += (" Виноват основной роутер: он сам пропадал из сети"
                       f" (последний раз — {last}).")
                az += (" Səbəb əsas routerdir: o, özü şəbəkədən itib"
                       f" (sonuncu dəfə — {last_az}).")
            else:
                ru += (f" Из них {len(by_router)} — по вине основного роутера: "
                       f"он сам пропадал из сети (последний раз — {last}).")
                az += (f" Onlardan {len(by_router)} — əsas routerin "
                       f"günahından: o, özü şəbəkədən itib (sonuncu dəfə — {last_az}).")
        net.append({"ru": ru, "az": az})
    else:
        net.append({"ru": "Полностью интернет не пропадал.",
                    "az": "İnternet tamamilə itməyib."})

    # 2. зависимость от нагрузки
    work, off = _day_night(A)
    if work["n"] >= 720 and off["n"] >= 720:
        hours = f"{WORK_HOURS[0]}:00–{WORK_HOURS[1]}:00"
        p_hi, p_lo = pct(work["bad"], work["n"]), pct(off["bad"], off["n"])
        d_hi = pct(work["dns_lost"], work["dns_try"]) if work["dns_try"] else 0
        d_lo = pct(off["dns_lost"], off["dns_try"]) if off["dns_try"] else 0
        err = p_hi >= 0.3 and p_hi >= 2 * max(p_lo, 0.05)
        dns = A.has_rdns and d_hi >= 0.5 and d_hi >= 3 * max(d_lo, 0.05)
        if err or dns:
            bad_net = True
            ru = f"Днём ({hours}), когда в академии люди, сеть работает хуже: "
            az = f"Gündüz ({hours}), akademiyada insanlar olanda, şəbəkə pis işləyir: "
            bits, bits_az = [], []
            if err:
                r = p_hi / max(p_lo, 0.05)
                bits.append(f"ошибок в {_times(r)} больше, чем ночью "
                            f"({p_hi:.1f}% замеров против {p_lo:.1f}%)")
                bits_az.append(f"səhvlər gecədən {r:.0f} dəfə çoxdur "
                               f"({p_hi:.1f}% ölçmə, gecə {p_lo:.1f}%)")
            if dns:
                r2 = d_hi / max(d_lo, 0.05)
                bits.append(f"основной роутер не справляется с нагрузкой и не "
                            f"отвечает на запросы в {_times(r2)} чаще, чем ночью")
                bits_az.append(f"əsas router yüklənməyə tab gətirmir və sorğulara "
                               f"gecədən {r2:.0f} dəfə daha tez-tez cavab vermir")
            net.append({"ru": ru + "; ".join(bits) + ".",
                        "az": az + "; ".join(bits_az) + "."})

    # 3. петли и штормы
    if A.storms:
        bad_net = True
        n_hit = sum(1 for st in A.storms if st.get("hit"))
        ru = (f"В сети случались «штормы» — лавина служебных пакетов, которая "
              f"забивает сеть: {plural(len(A.storms), 'раз', 'раза', 'раз')}"
              + (f" (во время сбоев — {n_hit})." if n_hit else "."))
        az = (f"Şəbəkədə «fırtınalar» olub — şəbəkəni tıxayan xidməti paket "
              f"axını: {len(A.storms)} dəfə"
              + (f" (nasazlıqlar zamanı — {n_hit})." if n_hit else "."))
        net.append({"ru": ru, "az": az})

    # 4. как собрана сеть
    if HIDDEN_SUBNETS:
        bad_net = True
        nets = ", ".join([_net_x(LAN_NET)] + [_net_x(x) for x in HIDDEN_SUBNETS])
        net.append({
            "ru": "Сеть собрана неправильно: под одним Wi-Fi работают разные "
                  f"сети ({nets}) — роутер стоит за роутером. Поэтому в разных "
                  "комнатах интернет разный, а большинство подключённых "
                  "устройств сеть даже не видит.",
            "az": "Şəbəkə səhv qurulub: bir Wi-Fi altında müxtəlif şəbəkələr "
                  f"işləyir ({nets}) — router routerin arxasında dayanır. Ona "
                  "görə də müxtəlif otaqlarda internet fərqlidir, qoşulmuş "
                  "cihazların əksəriyyətini isə şəbəkə heç görmür."})

    net_head = ({"ru": "Сеть академии работает нестабильно",
                 "az": "Akademiyanın şəbəkəsi qeyri-sabit işləyir"} if bad_net else
                {"ru": "Серьёзных проблем в сети не найдено",
                 "az": "Şəbəkədə ciddi problem tapılmayıb"})

    # ---------- сервер ----------
    srv, bad_srv = [], False
    if T["sys_n"]:
        cpu, cpu_m = T["cpu_sum"] / T["sys_n"], T["cpu_max"]
        mem, mem_m = T["mem_sum"] / T["sys_n"], T["mem_max"]
        heavy = cpu >= 50 or mem >= 85
        bad_srv |= heavy
        srv.append({
            "ru": ("Сервер загружен" if heavy else "Нагрузка небольшая")
                  + f": процессор в среднем {cpu:.0f}% (максимум {cpu_m:.0f}%), "
                  f"память {mem:.0f}% (максимум {mem_m:.0f}%).",
            "az": ("Server yüklənib" if heavy else "Yüklənmə azdır")
                  + f": prosessor orta hesabla {cpu:.0f}% (maksimum {cpu_m:.0f}%), "
                  f"yaddaş {mem:.0f}% (maksimum {mem_m:.0f}%)."})
    SV = getattr(A, "server", None) or server_summary(A)
    if SV:
        bad_srv |= SV["level"] != "ok"
        srv.append({
            "ru": f"Диск: свободно {fmt_bytes(SV['free'])} из "
                  f"{fmt_bytes(SV['total'])} — {SV['state']['ru']}. "
                  + ("" if SV["level"] == "ok" else SV["rec"]["ru"]),
            "az": f"Disk: {fmt_bytes(SV['total'], 'az')}-dan "
                  f"{fmt_bytes(SV['free'], 'az')} boşdur — {SV['state']['az']}. "
                  + ("" if SV["level"] == "ok" else SV["rec"]["az"])})
    R = getattr(A, "security", None)
    if R:
        hits = R["ufw_in"] + R["ssh_fail"] + R["found"]
        bad_srv |= R["ban"] > 0
        if hits == 0:
            ru = ("Атак не было: попыток подключиться к серверу снаружи — 0, "
                  "неудачных входов — 0.")
            az = ("Hücum olmayıb: serverə kənardan qoşulma cəhdi — 0, "
                  "uğursuz giriş — 0.")
        else:
            ru = (f"Были попытки проникнуть на сервер: заблокировано подключений "
                  f"{R['ufw_in']}, неудачных входов {R['ssh_fail']}, "
                  f"заблокировано адресов {R['ban']}.")
            az = (f"Serverə daxil olmaq cəhdləri olub: bloklanmış qoşulmalar "
                  f"{R['ufw_in']}, uğursuz girişlər {R['ssh_fail']}, "
                  f"bloklanmış ünvanlar {R['ban']}.")
        if R.get("syslog_stale"):
            bad_srv = True
            ru += " Журналы сервера не пишутся — проверить rsyslog."
            az += " Serverin jurnalları yazılmır — rsyslog-u yoxlamaq lazımdır."
        srv.append({"ru": ru, "az": az})
    if not srv:
        srv.append({"ru": "Данных о сервере за этот период нет.",
                    "az": "Bu dövr üçün server haqqında məlumat yoxdur."})
    srv_head = ({"ru": "Сервер диагностики требует внимания",
                 "az": "Diaqnostika serveri diqqət tələb edir"} if bad_srv else
                {"ru": "Сервер диагностики работает нормально",
                 "az": "Diaqnostika serveri normal işləyir"})
    return {"net": {"head": net_head, "lines": net},
            "srv": {"head": srv_head, "lines": srv}}


def render_brief(A, B):
    L = ["ОТЧЁТ NETDIAG",
         f"{A.first:%d.%m.%y %H:%M} — {A.last:%d.%m.%y %H:%M}",
         ""]
    for part in ("net", "srv"):
        L.append(B[part]["head"]["ru"].upper())
        for ln in B[part]["lines"]:
            L += wrap("• " + ln["ru"], 76, "  ", "    ")
        L.append("")
    L.append("Подробный технический отчёт: report-full.txt")
    return "\n".join(L) + "\n"


def render_html(A, B):
    points, ticks, pos, step_min = build_timeline(A)
    # ошибки: доля запросов к роутеру без ответа (лучше всего видна нагрузка);
    # если DNS роутера не проверялся — доля замеров с отклонениями
    key = "dns" if A.has_rdns else "bad"
    net_pts = [{"l": p["label"], "v": p.get(key), "e": p.get("bad"),
                "o": bool(p.get("black"))}
               if p["n"] else {"l": p["label"]} for p in points]
    srv_pts = [{"l": p["label"], "a": p.get("cpu"), "b": p.get("mem")}
               if p["n"] else {"l": p["label"]} for p in points]
    data = {
        "period": {"ru": f"{A.first:%d.%m.%y %H:%M} — {A.last:%d.%m.%y %H:%M}",
                   "az": f"{A.first:%d.%m.%y %H:%M} — {A.last:%d.%m.%y %H:%M}"},
        "net": B["net"], "srv": B["srv"], "ticks": ticks, "rdns": A.has_rdns,
        "netPts": net_pts,
        "srvPts": srv_pts if A.total["sys_n"] else None,
    }
    blob = json.dumps(data, ensure_ascii=False).replace("</", "<\\/")
    return HTML_TEMPLATE.replace("__DATA__", blob)


HTML_TEMPLATE = r"""<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NetDiag — отчёт</title>
<style>
:root {
  color-scheme: light;
  --page: #f4f3f0; --surface: #fcfcfb; --border: #e3e1db;
  --text: #0b0b0b; --text2: #52514e; --muted: #8a8880; --grid: #e9e7e1;
  --s1: #2a78d6; --s2: #eb6834; --bad: #d03b3b; --ok: #2f8f4e;
}
@media (prefers-color-scheme: dark) {
  :root {
    color-scheme: dark;
    --page: #111110; --surface: #1a1a19; --border: #33322f;
    --text: #f0efec; --text2: #c3c2b7; --muted: #8a8880; --grid: #2a2a28;
    --s1: #3987e5; --s2: #d95926; --bad: #e05252; --ok: #4fb46d;
  }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--page); color: var(--text);
  font: 15px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
main { max-width: 980px; margin: 0 auto; padding: 24px 16px 40px; }
.top { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
h1 { font-size: 20px; margin: 0; }
.period { color: var(--muted); margin: 2px 0 20px; font-size: 13px; }
.langs { display: flex; gap: 6px; }
.langs button { padding: 2px; border: 2px solid transparent; border-radius: 6px;
  background: none; cursor: pointer; line-height: 0; opacity: .55; }
.langs button svg { width: 30px; height: 20px; border-radius: 3px;
  box-shadow: 0 0 0 1px var(--border); }
.langs button[aria-pressed="true"] { border-color: var(--text); opacity: 1; }
section { background: var(--surface); border: 1px solid var(--border);
  border-radius: 12px; padding: 18px 18px 10px; margin-bottom: 16px; position: relative; }
h2 { font-size: 19px; margin: 0 0 10px; display: flex; align-items: center; gap: 10px; }
h2 i { width: 12px; height: 12px; border-radius: 50%; flex: none; }
h2.bad i { background: var(--bad); } h2.ok i { background: var(--ok); }
ul { margin: 0 0 14px; padding-left: 20px; }
li { margin: 4px 0; max-width: 820px; }
.legend { display: flex; flex-wrap: wrap; gap: 4px 18px; font-size: 12px;
  color: var(--text2); margin-bottom: 4px; }
.legend i { width: 12px; height: 10px; border-radius: 2px; display: inline-block;
  vertical-align: -1px; margin-right: 6px; }
svg.chart { display: block; width: 100%; height: auto; overflow: visible; }
svg.chart text { fill: var(--muted); font-size: 11px; font-variant-numeric: tabular-nums; }
.tip { position: absolute; pointer-events: none; background: var(--surface);
  border: 1px solid var(--border); border-radius: 8px; padding: 6px 9px; font-size: 12px;
  box-shadow: 0 4px 14px rgba(0,0,0,.14); white-space: nowrap; display: none; z-index: 5; }
.tip .t { color: var(--text2); }
.foot { font-size: 12px; } .foot a { color: var(--muted); }
</style>
</head>
<body>
<main>
  <div class="top">
    <h1>NetDiag</h1>
    <div class="langs">
      <button data-lang="ru" aria-label="Русский"><svg viewBox="0 0 3 2"><rect width="3" height="2" fill="#fff"/><rect y=".667" width="3" height=".667" fill="#0039a6"/><rect y="1.333" width="3" height=".667" fill="#d52b1e"/></svg></button>
      <button data-lang="az" aria-label="Azərbaycan"><svg viewBox="0 0 3 2"><rect width="3" height="2" fill="#509e2f"/><rect width="3" height="1.333" fill="#ef3340"/><rect width="3" height=".667" fill="#00b5e2"/><circle cx="1.42" cy="1" r=".3" fill="#fff"/><circle cx="1.49" cy="1" r=".24" fill="#ef3340"/><polygon fill="#fff" points="1.78,0.88 1.80,0.95 1.87,0.94 1.82,0.99 1.86,1.05 1.79,1.03 1.76,1.10 1.73,1.03 1.66,1.05 1.70,0.99 1.65,0.94 1.72,0.95"/></svg></button>
    </div>
  </div>
  <div class="period" id="period"></div>
  <section id="net"><h2></h2><ul></ul>
    <div class="legend"><span><i style="background:var(--s1)"></i><b data-t="errLeg"></b></span>
      <span><i style="background:var(--bad)"></i><b data-t="outLeg"></b></span></div>
    <div class="plot"></div><div class="tip"></div></section>
  <section id="srv"><h2></h2><ul></ul>
    <div class="legend"><span><i style="background:var(--s1)"></i><b data-t="cpu"></b></span>
      <span><i style="background:var(--s2)"></i><b data-t="mem"></b></span></div>
    <div class="plot"></div><div class="tip"></div></section>
  <div class="foot"><a href="report-full.txt" target="_blank" data-t="foot"></a></div>
</main>
<script>
(function () {
  var D = __DATA__;
  var UI = {
    ru: { errLeg: "Роутер не ответил, % запросов", errLeg2: "Ошибки, % замеров",
          bad: "Замеров с ошибками", outLeg: "Интернет пропадал",
          cpu: "Процессор, %", mem: "Память, %", noData: "нет данных",
          foot: "Подробный технический отчёт" },
    az: { errLeg: "Router cavab vermədi, sorğuların %-i", errLeg2: "Səhvlər, ölçmələrin %-i",
          bad: "Səhvli ölçmələr", outLeg: "İnternet itib",
          cpu: "Prosessor, %", mem: "Yaddaş, %", noData: "məlumat yoxdur",
          foot: "Ətraflı texniki hesabat" }
  };
  var lang = "ru";
  try { lang = localStorage.getItem("netdiag-lang") || "ru"; } catch (e) {}
  if (!UI[lang]) lang = "ru";
  var NS = "http://www.w3.org/2000/svg";
  function el(n, a, p) { var e = document.createElementNS(NS, n);
    for (var k in a) e.setAttribute(k, a[k]); if (p) p.appendChild(e); return e; }
  function nice(v) { var c = [1, 2, 4, 8, 12, 20, 40, 60, 80, 100]; for (var i = 0; i < c.length; i++) if (v <= c[i]) return c[i]; return Math.ceil(v / 100) * 100; }

  function chart(sec, pts, opt) {
    var box = sec.querySelector(".plot"), tip = sec.querySelector(".tip");
    box.textContent = "";
    if (!pts) { sec.querySelector(".legend").style.display = "none"; return; }
    var W = Math.max(320, box.clientWidth), H = opt.h, m = { l: 36, r: 8, t: 8, b: 22 };
    var pw = W - m.l - m.r, ph = H - m.t - m.b, N = pts.length;
    var mx = opt.floor;
    pts.forEach(function (p) { opt.keys.forEach(function (k) { if (p[k] != null && p[k] > mx) mx = p[k]; }); });
    mx = nice(mx);
    var svg = el("svg", { "class": "chart", viewBox: "0 0 " + W + " " + H }, box);
    function X(i) { return m.l + i / N * pw; }
    function Y(v) { return m.t + ph - v / mx * ph; }
    for (var g = 0; g <= 4; g++) {
      var v = mx * g / 4, y = Y(v);
      el("line", { x1: m.l, x2: W - m.r, y1: y, y2: y, stroke: "var(--grid)" }, svg);
      var t = el("text", { x: m.l - 6, y: y + 4, "text-anchor": "end" }, svg);
      t.textContent = (Math.round(v * 10) / 10) + "";
    }
    var step = Math.max(1, Math.ceil(D.ticks.length / Math.max(2, Math.floor(pw / 70))));
    D.ticks.forEach(function (tk, i) {
      if (i % step) return;
      var t = el("text", { x: X(tk.x), y: H - 6, "text-anchor": "middle" }, svg);
      t.textContent = tk.label;
    });
    if (opt.bars) {
      var bw = Math.max(1, pw / N - (pw / N > 4 ? 1 : 0));
      pts.forEach(function (p, i) {
        if (p.o) el("rect", { x: X(i), y: m.t, width: Math.max(2, pw / N), height: ph,
          fill: "var(--bad)", opacity: .22 }, svg);
        if (p.v == null || p.v <= 0) return;
        el("rect", { x: X(i), y: Y(p.v), width: bw, height: Y(0) - Y(p.v),
          fill: p.o ? "var(--bad)" : "var(--s1)" }, svg);
      });
    } else {
      opt.keys.forEach(function (k, j) {
        var d = "", open = false;
        pts.forEach(function (p, i) {
          if (p[k] == null) { open = false; return; }
          d += (open ? "L" : "M") + (X(i + .5)).toFixed(1) + " " + Y(p[k]).toFixed(1); open = true;
        });
        el("path", { d: d, fill: "none", stroke: j ? "var(--s2)" : "var(--s1)",
          "stroke-width": 2, "stroke-linejoin": "round" }, svg);
      });
    }
    var hair = el("line", { y1: m.t, y2: m.t + ph, stroke: "var(--muted)", visibility: "hidden" }, svg);
    var hit = el("rect", { x: m.l, y: m.t, width: pw, height: ph, fill: "transparent" }, svg);
    hit.addEventListener("pointermove", function (ev) {
      var r = svg.getBoundingClientRect(), sx = W / r.width;
      var i = Math.floor(((ev.clientX - r.left) * sx - m.l) / pw * N);
      if (i < 0 || i >= N) return;
      var p = pts[i], x = X(i + .5);
      hair.setAttribute("x1", x); hair.setAttribute("x2", x); hair.setAttribute("visibility", "visible");
      tip.innerHTML = "";
      var t = document.createElement("div"); t.className = "t"; t.textContent = p.l; tip.appendChild(t);
      opt.rows(p).forEach(function (s) { var d = document.createElement("div"); d.textContent = s; tip.appendChild(d); });
      tip.style.display = "block";
      var cr = sec.getBoundingClientRect(), px = r.left - cr.left + x / sx, left = px + 12;
      if (left + tip.offsetWidth > cr.width - 8) left = px - tip.offsetWidth - 12;
      tip.style.left = Math.max(4, left) + "px";
      tip.style.top = (box.getBoundingClientRect().top - cr.top) + "px";
    });
    hit.addEventListener("pointerleave", function () { hair.setAttribute("visibility", "hidden"); tip.style.display = "none"; });
  }
  function f(v) { return v == null ? "—" : (Math.round(v * 10) / 10) + "%"; }
  function part(id, P) {
    var s = document.getElementById(id), h = s.querySelector("h2"), ul = s.querySelector("ul");
    var bad = /нестабильно|неправильно|внимания|qeyri-sabit|diqqət/.test(P.head.ru + P.head.az);
    h.className = bad ? "bad" : "ok"; h.innerHTML = "<i></i>";
    h.appendChild(document.createTextNode(P.head[lang]));
    ul.textContent = "";
    P.lines.forEach(function (ln) { var li = document.createElement("li"); li.textContent = ln[lang]; ul.appendChild(li); });
  }
  function draw() {
    var U = UI[lang];
    chart(document.getElementById("net"), D.netPts, { h: 220, bars: true, keys: ["v"], floor: 1,
      rows: function (p) {
        if (p.v == null && p.e == null) return [U.noData];
        var r = D.rdns ? [U.errLeg + ": " + f(p.v), U.bad + ": " + f(p.e)] : [U.errLeg2 + ": " + f(p.e)];
        return r.concat(p.o ? [U.outLeg] : []); } });
    chart(document.getElementById("srv"), D.srvPts, { h: 180, keys: ["a", "b"], floor: 20,
      rows: function (p) { return p.a == null ? [U.noData] : [U.cpu + ": " + f(p.a), U.mem + ": " + f(p.b)]; } });
  }
  function render() {
    document.documentElement.lang = lang;
    document.getElementById("period").textContent = D.period[lang];
    part("net", D.net); part("srv", D.srv);
    document.querySelectorAll("[data-t]").forEach(function (e) {
      var k = e.getAttribute("data-t"); if (k === "errLeg" && !D.rdns) k = "errLeg2";
      e.textContent = UI[lang][k]; });
    document.querySelectorAll(".langs button").forEach(function (b) {
      b.setAttribute("aria-pressed", b.getAttribute("data-lang") === lang ? "true" : "false"); });
    draw();
  }
  document.querySelectorAll(".langs button").forEach(function (b) {
    b.addEventListener("click", function () { lang = b.getAttribute("data-lang");
      try { localStorage.setItem("netdiag-lang", lang); } catch (e) {} render(); });
  });
  render();
  var tm; window.addEventListener("resize", function () { clearTimeout(tm); tm = setTimeout(draw, 120); });
})();
</script>
</body>
</html>
"""


def _report_files(since, until):
    """Файлы лога, которые могут пересекаться с периодом отчёта."""
    for d, path in data_files():
        try:                               # файлы целиком вне периода не читаем
            if d is None:
                d_last = datetime.fromtimestamp(os.path.getmtime(path), TZ).date()
                if since and d_last < since.date():
                    continue
            elif (since and d < since.date()) or (until and d > until.date()):
                continue
        except OSError:
            continue
        yield path


def constant_devices(since, until):
    """MAC-адреса, отвечавшие не реже чем в INFRA_SHARE подсчётов за период:
    серверы, виртуальные машины, роутеры, камеры. None — подсчётов мало."""
    seen, scans = Counter(), 0
    for path in _report_files(since, until):
        try:
            f = open(path, encoding="utf-8")
        except OSError:
            continue
        with f:
            for line in f:
                if '"devs"' not in line:
                    continue
                try:
                    r = json.loads(line)
                    ts = to_aware(r["ts"])
                    devs = r["devs"]
                except Exception:
                    continue
                if (since and ts < since) or (until and ts >= until):
                    continue
                scans += 1
                seen.update(set(devs.values()))
    if scans < INFRA_MIN_SCANS:
        return None
    return {m for m, n in seen.items() if n >= INFRA_SHARE * scans}


def _write(path, text):
    """Запись целиком: веб-сервер никогда не отдаст наполовину записанный файл."""
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, path)


def build_report(since=None, until=None):
    A = Analyzer()
    const = constant_devices(since, until) if USE_DEVICE_COUNT else None
    A.n_const = len(const) if const is not None else None
    people = None                          # видимых устройств людей
    for d, path in data_files():
        try:                               # файлы целиком вне периода не читаем
            if d is None:
                d_last = datetime.fromtimestamp(os.path.getmtime(path), TZ).date()
                if since and d_last < since.date():
                    continue
            elif (since and d < since.date()) or (until and d > until.date()):
                continue
            f = open(path, encoding="utf-8")
        except OSError:
            continue
        with f:
            for line in f:
                try:
                    r = json.loads(line)
                    ts = to_aware(r["ts"])
                    data = r["data"]
                except Exception:
                    continue
                if (since and ts < since) or (until and ts >= until):
                    continue
                devs = r.get("devs")
                if devs:
                    for ip, mac in devs.items():
                        A.mac_ip[mac] = ip
                    if const is not None:
                        people = sum(1 for m in devs.values() if m not in const)
                dev = (people if const is not None and r.get("ndev") is not None
                       else None)
                A.feed(ts, data, dev, r)
    A.finish()
    if A.first is not None:
        try:
            A.security = security_summary(A.first, A.last)
        except Exception as e:             # журналы сервера не должны ломать отчёт
            A.security = None
            log.warning("security summary failed: %s", e)
    if A.first is None:
        txt = "Отчёт пуст: нет данных.\n"
        _write(OUT_REPORT, txt)
        return txt
    _write(OUT_FULL, render(A))            # подробный: для разбора, не для руководства
    B = brief(A)
    txt = render_brief(A, B)
    _write(OUT_REPORT, txt)
    try:
        _write(OUT_HTML, render_html(A, B))
    except Exception as e:                     # графики не должны ломать отчёт
        log.warning("html report failed: %s", e)
    log.info("report written: %s", OUT_REPORT)
    return txt


# ---- отдача отчёта по HTTP ----

SERVE_FILES = {"/": (OUT_HTML, "text/html; charset=utf-8"),
               "/report.html": (OUT_HTML, "text/html; charset=utf-8"),
               "/report-full.txt": (OUT_FULL, "text/plain; charset=utf-8"),
               "/report.txt": (OUT_REPORT, "text/plain; charset=utf-8")}

WAIT_PAGE = ("<!doctype html><meta charset=utf-8><title>NetDiag</title>"
             "<p style='font:16px system-ui;margin:40px'>Отчёт строится, "
             "обновите страницу через пару минут.</p>").encode()


def report_server():
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class H(BaseHTTPRequestHandler):
        def _send(self, body):
            path = self.path.split("?", 1)[0]
            item = SERVE_FILES.get(path)
            if item is None:
                self.send_error(404)
                return
            fn, ctype = item
            try:
                with open(fn, "rb") as f:
                    data = f.read()
            except OSError:
                data, ctype = WAIT_PAGE, "text/html; charset=utf-8"
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-cache")
            self.send_header("X-Robots-Tag", "noindex")
            self.end_headers()
            if body:
                self.wfile.write(data)

        def do_GET(self):
            self._send(True)

        def do_HEAD(self):
            self._send(False)

        def log_message(self, *a):         # без записи каждого запроса
            pass

    srv = ThreadingHTTPServer((REPORT_HTTP_BIND, REPORT_HTTP_PORT), H)
    srv.daemon_threads = True
    log.info("report http: %s:%s", REPORT_HTTP_BIND, REPORT_HTTP_PORT)
    srv.serve_forever()


def serve():
    """Контейнер netdiag-report: отдаёт отчёт и перестраивает его по расписанию."""
    signal.signal(signal.SIGTERM, _on_term)
    signal.signal(signal.SIGINT, _on_term)
    try:
        os.nice(10)                        # уступаем процессор всему остальному
    except OSError:
        pass
    threading.Thread(target=report_server, daemon=True).start()
    while not _stop:
        t0 = time.time()
        try:
            build_report((now() - timedelta(days=REPORT_DAYS)).replace(
                hour=0, minute=0, second=0, microsecond=0))
            log.info("scheduled report built in %.0f s", time.time() - t0)
        except Exception as e:
            log.warning("scheduled report failed: %s", e)
        while not _stop and time.time() - t0 < REPORT_EVERY_MIN * 60:
            time.sleep(1)


def _parse_day(s):
    return datetime.strptime(s, "%Y-%m-%d").replace(tzinfo=TZ)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "report":
        args = sys.argv[2:]
        since = until = None
        try:
            if "--since" in args:
                since = _parse_day(args[args.index("--since") + 1])
            if "--until" in args:
                until = _parse_day(args[args.index("--until") + 1])
            if "--days" in args:
                n = int(args[args.index("--days") + 1])
                since = (now() - timedelta(days=n)).replace(
                    hour=0, minute=0, second=0, microsecond=0)
        except (IndexError, ValueError):
            sys.exit("Формат: report [--days N | --all] "
                     "[--since ГГГГ-ММ-ДД] [--until ГГГГ-ММ-ДД]")
        if since is None and until is None and "--all" not in args:
            since = (now() - timedelta(days=REPORT_DAYS)).replace(
                hour=0, minute=0, second=0, microsecond=0)
        sys.stdout.write(build_report(since, until))
    elif len(sys.argv) > 1 and sys.argv[1] == "serve":
        serve()
    else:
        run()
