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
import ipaddress
import json
import logging
import os
import random
import signal
import socket
import statistics
import struct
import sys
import threading
import time
from array import array
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutTimeout
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

TZ = ZoneInfo("Asia/Baku")

# ==== КОНФИГ ====
GATEWAY = "192.168.0.1"          # главный роутер
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
DNS_TRIES      = 2       # попыток DNS-запроса за замер (как у обычного клиента)
SLOW_FACTOR    = 3       # «медленный» замер: задержка наружу в 3+ раза выше
SLOW_MIN_MS    = 100     # обычной и не меньше чем на 100 мс
CYCLE_BUDGET   = 3.5     # предел на весь цикл (зависший DNS не тормозит замеры)
OUTAGE_MIN_SEC = 30      # от какой длительности событие попадает в список
MERGE_SEC      = 30      # события с паузой короче этой склеиваются в одно
GAP_SEC        = 60      # пауза между замерами дольше этой = сервер не работал

# Подсчёт устройств по ARP выключен: с проводного сервера видна лишь малая
# часть Wi-Fi-клиентов (на замере 10.10.26 — 7 из 40+), цифра вводит в
# заблуждение. USE_DEVICE_COUNT=False — отчёт игнорирует уже записанные "dev".
DEVICE_SCAN        = False
USE_DEVICE_COUNT   = False
DEVICE_SCAN_SEC    = 60  # как часто считать устройства
DEVICE_SETTLE_SEC  = 12  # сколько ждать ответов после рассылки
DEVICE_BUCKETS     = [(0, 20), (21, 40), (41, 60), (61, 80), (81, None)]

WORK_HOURS = (9, 21)     # используется, только если нет данных о числе устройств
MAX_EVENTS_LISTED = 150

WORK_DIR   = os.environ.get("NETDIAG_DATA", "/data")
OUT_JSONL  = f"{WORK_DIR}/netdiag.jsonl"
OUT_REPORT = f"{WORK_DIR}/report.txt"
OUT_HTML   = f"{WORK_DIR}/report.html"
HEARTBEAT  = f"{WORK_DIR}/heartbeat"
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


# ---- подсчёт устройств в локальной сети ----

_dev = {"n": None, "t": 0.0}


def _arp_count():
    net = ipaddress.ip_network(LAN_NET)
    n = 0
    with open("/proc/net/arp") as f:
        next(f, None)
        for line in f:
            p = line.split()
            if len(p) < 4 or p[2] == "0x0" or p[3] == "00:00:00:00:00:00":
                continue
            try:
                if ipaddress.ip_address(p[0]) in net:
                    n += 1
            except ValueError:
                pass
    return n


def device_scanner():
    """Раз в DEVICE_SCAN_SEC шлёт по одному пустому UDP-пакету на каждый адрес
    сети (порт 9, discard). Это заставляет ядро выполнить ARP-запрос; кто
    ответил — тот в сети. Затем считаем живые записи ARP-таблицы."""
    try:
        hosts = [str(h) for h in ipaddress.ip_network(LAN_NET).hosts()]
    except Exception as e:
        log.warning("device scan disabled: bad LAN_NET (%s)", e)
        return
    if len(hosts) > 1024 or not os.path.exists("/proc/net/arp"):
        log.warning("device scan disabled (net too large or no /proc/net/arp)")
        return
    warned = False
    while not _stop:
        t0 = time.time()
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setblocking(False)
            for h in hosts:
                try:
                    s.sendto(b"\x00", (h, 9))
                except OSError:
                    pass
                time.sleep(0.005)
            s.close()
            time.sleep(DEVICE_SETTLE_SEC)
            n = _arp_count()
            _dev["n"] = n
            _dev["t"] = time.time()
            if n <= 1 and not warned:
                log.warning("device scan sees %d devices — проверь LAN_NET", n)
                warned = True
        except Exception as e:
            log.warning("device scan failed: %s", e)
        while not _stop and time.time() - t0 < DEVICE_SCAN_SEC:
            time.sleep(1)


def current_devices():
    if (_dev["n"] is None or _dev["n"] <= 1
            or time.time() - _dev["t"] > DEVICE_SCAN_SEC * 3):
        return None
    return _dev["n"]


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
    with open(OUT_JSONL, "a", buffering=1, encoding="utf-8") as f:
        while not _stop:
            t0 = time.time()
            write_heartbeat()
            rec = {"ts": now().isoformat(timespec="milliseconds"),
                   "data": sample_all()}
            dev = current_devices()
            if dev is not None:
                rec["dev"] = dev
            f.write(json.dumps(rec) + "\n")
            f.flush()
            os.fsync(f.fileno())
            time.sleep(max(0, INTERVAL_SEC - (time.time() - t0)))
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

    @property
    def has_rdns(self):
        return self.rdns_ok > 0

    def feed(self, ts, data, dev):
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


def fmt_dur(sec):
    sec = int(round(sec))
    d, sec = divmod(sec, 86400)
    h, sec = divmod(sec, 3600)
    m, s = divmod(sec, 60)
    parts = []
    if d: parts.append(f"{d} сут")
    if h: parts.append(f"{h} ч")
    if m: parts.append(f"{m} мин")
    if (s and not d) or not parts: parts.append(f"{s} сек")
    return " ".join(parts)


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
        return "router", ("роутер не отвечал и по локальной сети — "
                          "неисправность на стороне роутера")
    if slow or e["gw_down"] > 0:
        why = []
        if slow:
            why.append(f"отвечал по локальной сети за {rtt:.0f} мс "
                       f"при обычных {base:.0f} мс")
        if e["gw_down"] > 0:
            why.append(f"не ответил на {e['gw_down']} из {e['n']} локальных запросов")
        return "router_load", ("роутер " + ", ".join(why) +
                               " — признак перегрузки роутера")
    return "unknown", ("роутер отвечал по локальной сети нормально, трафик "
                       "наружу не шёл — роутер (NAT/WAN) или провайдер, "
                       "этим замером не различить")


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
        e["verdict"], e["text"] = outage_verdict(e, base)
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
        L.append(f"  Раз в {DEVICE_SCAN_SEC} сек считалось число устройств в сети {LAN_NET}")
        L.append("  (по ответам на ARP; в число входят и сами роутеры).")
    else:
        L.append("  Число устройств с сервера достоверно не определяется (Wi-Fi-клиенты")
        L.append("  ему почти не видны) — нагрузка оценивается по времени суток.")
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
        head.append("устройств")
    head.append("обрывов")
    legend = [
        "  отклон. — доля замеров с любым отклонением; обрыв — доля времени без",
        "  интернета; роутер — обычная задержка ответа роутера по локальной сети",
        "  и граница 5% худших замеров; наружу — то же до внешних ресурсов;",
        "  медл. — доля медленных замеров; DNS пот. — доля DNS-запросов к",
        "  роутеру, оставшихся без ответа; контр. — то же для запросов напрямую",
        "  к 8.8.8.8; обрывов — число полных обрывов.",
    ]

    # ---------- по числу устройств ----------
    if with_dev:
        L.append("ЗАВИСИМОСТЬ ОТ ЧИСЛА УСТРОЙСТВ В СЕТИ")
        rows = [stat_row(bucket_label(i), A.bucket[i], True, thr, with_dns, with_ctl)
                for i in range(len(DEVICE_BUCKETS)) if A.bucket[i]["n"]]
        L += table(["устройств"] + head[1:], rows)
        L += legend
        L.append("")

    # ---------- по часам ----------
    L.append("ПО ЧАСАМ СУТОК")
    rows = [stat_row(f"{h:02d}:00", A.hour[h], with_dev, thr, with_dns, with_ctl)
            for h in range(24) if A.hour[h]["n"]]
    L += table(["час"] + head[1:], rows)
    if not with_dev:
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
            h2.append("макс. устройств")
        L += table(h2, rows)
        L.append("")

    # ---------- список событий ----------
    def dev_txt(e):
        return f", устройств в сети: {e['dev']}" if e["dev"] is not None and with_dev else ""

    if outages:
        L.append("ПОЛНЫЕ ОБРЫВЫ ИНТЕРНЕТА")
        for e in outages[:MAX_EVENTS_LISTED]:
            L.append(f"  {fmt_dt(e['start'])} — {fmt_dt(e['end'])} "
                     f"({fmt_dur(e['dur'])}{dev_txt(e)})")
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
    C = []
    if not A.events and T["bad"] == 0:
        C.append("По проводу сбоев не зафиксировано. Если жалобы в этот период "
                 "были, их причина в беспроводной части сети, которую этот "
                 "замер не видит.")
    dns_sure = [e for e in dns_ev
                if A.has_rdns and e["ctl_try"] and e["ctl_lost"] == 0]
    dns_open = [e for e in dns_ev if e not in dns_sure]
    certain = n_router + len(mute_ev) + len(dns_sure)
    if certain:
        bits = []
        if n_router:
            bits.append(f"{n_router} — обрывы, при которых роутер не отвечал "
                        "и по локальной сети")
        if dns_sure:
            bits.append(f"{len(dns_sure)} — отказы DNS роутера, при которых "
                        "контрольный DNS-запрос мимо роутера проходил "
                        "(для устройств, получающих DNS от роутера, это выглядит "
                        "как пропавший интернет)")
        if mute_ev:
            bits.append(f"{len(mute_ev)} — роутер переставал отвечать на локальные "
                        "запросы при работающем интернете")
        C.append(f"Событий, которые относятся к роутеру однозначно: {certain} ("
                 + "; ".join(bits) + ").")
    if dns_open:
        C.append(f"Отказов DNS роутера без контрольного замера: {len(dns_open)}. "
                 "Канал по IP в это время работал, но роутер пересылает "
                 "DNS-запросы серверу провайдера, поэтому по этим случаям "
                 "нельзя исключить, что не отвечал он, а не роутер.")
    if with_ctl and T["dns_try"]:
        d_r = pct(T["dns_lost"], T["dns_try"])
        d_c = pct(T["ctl_lost"], T["ctl_try"])
        if d_r >= 0.3 and d_r >= 3 * max(d_c, 0.05):
            C.append(f"DNS роутера теряет запросы ({d_r:.2f}%), а тот же запрос "
                     f"мимо роутера проходит ({d_c:.2f}% потерь). Канал исправен, "
                     "потери возникают в роутере или у DNS-сервера, которому он "
                     "пересылает запросы.")
        elif d_c >= 0.3:
            C.append(f"DNS-запросы теряются и через роутер ({d_r:.2f}%), и мимо "
                     f"него ({d_c:.2f}%): причина в канале, а не в DNS роутера.")
    if n_load:
        C.append(f"Ещё {plural(n_load, 'обрыв сопровождался', 'обрыва сопровождались', 'обрывов сопровождались')} "
                 "замедлением или перебоями "
                 "ответа роутера по локальной сети. Это признак перегрузки "
                 "роутера, но не строгое доказательство.")

    # зависимость от нагрузки
    MIN_N = 720                      # не меньше часа наблюдений в группе
    lo = hi = None
    if with_dev:
        filled = [i for i in range(len(DEVICE_BUCKETS)) if A.bucket[i]["n"] >= MIN_N]
        if len(filled) >= 2:
            lo, hi = A.bucket[filled[0]], A.bucket[filled[-1]]
            lo_name = f"при {bucket_label(filled[0])} устройствах"
            hi_name = f"при {bucket_label(filled[-1])} устройствах"
        else:
            C.append("Данных о числе устройств пока недостаточно для сравнения "
                     "(нужен хотя бы час наблюдений при малой и при большой "
                     "нагрузке).")

    else:
        work, off = _stat(), _stat()
        for h in range(24):
            dst = work if WORK_HOURS[0] <= h < WORK_HOURS[1] else off
            for k in ("n", "bad", "sec", "black_sec", "outages",
                      "dns_try", "dns_lost", "ctl_try", "ctl_lost"):
                dst[k] += A.hour[h][k]
            dst["rtt"].extend(A.hour[h]["rtt"])
            dst["ext"].extend(A.hour[h]["ext"])
        if work["n"] >= MIN_N and off["n"] >= MIN_N:
            lo, hi = off, work
            lo_name = "в остальное время"
            hi_name = f"с {WORK_HOURS[0]:02d}:00 до {WORK_HOURS[1]:02d}:00"
        else:
            C.append(f"Для сравнения нагрузки нужны данные и за рабочие часы "
                     f"({WORK_HOURS[0]:02d}:00–{WORK_HOURS[1]:02d}:00), и за "
                     f"нерабочие — не меньше часа каждого. Пока их недостаточно.")
    if lo is not None:
        p_lo, p_hi = pct(lo["bad"], lo["n"]), pct(hi["bad"], hi["n"])
        r_lo, r_hi = quantile(lo["rtt"], 0.5), quantile(hi["rtt"], 0.5)
        facts = (f"доля замеров с отклонениями {hi_name} — {p_hi:.2f}%, "
                 f"{lo_name} — {p_lo:.2f}%; полных обрывов {hi['outages']} "
                 f"против {lo['outages']}")
        if p_hi >= 0.3 and p_hi >= 3 * max(p_lo, 0.01):
            C.append("Сбои зависят от нагрузки: " + facts + ". Провайдер не знает, "
                     "сколько устройств в локальной сети, поэтому такая "
                     "зависимость указывает на оборудование внутри сети.")
        else:
            C.append("Зависимости сбоев от нагрузки не видно: " + facts + ". "
                     "Эти данные не подтверждают, что роутер не справляется "
                     "с нагрузкой.")
        if r_lo and r_hi and r_hi >= max(2 * r_lo, r_lo + 5):
            C.append(f"Роутер под нагрузкой отвечает медленнее: обычная задержка "
                     f"по локальной сети {r_hi:.0f} мс {hi_name} против "
                     f"{r_lo:.0f} мс {lo_name}.")
        s_lo, s_hi = slow_share(lo, thr), slow_share(hi, thr)
        if s_hi >= 0.5 and s_hi >= 3 * max(s_lo, 0.05):
            C.append(f"Под нагрузкой интернет замедляется: медленных замеров "
                     f"{s_hi:.2f}% {hi_name} против {s_lo:.2f}% {lo_name}.")
        if with_dns and lo["dns_try"] >= MIN_N and hi["dns_try"] >= MIN_N:
            d_lo = pct(lo["dns_lost"], lo["dns_try"])
            d_hi = pct(hi["dns_lost"], hi["dns_try"])
            if d_hi >= 0.5 and d_hi >= 3 * max(d_lo, 0.05):
                C.append(f"DNS роутера под нагрузкой теряет запросы чаще: "
                         f"{d_hi:.2f}% {hi_name} против {d_lo:.2f}% {lo_name}.")
            else:
                C.append(f"Потери DNS роутера от нагрузки не зависят: "
                         f"{d_hi:.2f}% {hi_name} и {d_lo:.2f}% {lo_name}.")
    if n_unknown:
        C.append(f"{plural(n_unknown, 'обрыв', 'обрыва', 'обрывов')} этим замером нельзя отнести ни к роутеру, "
                 "ни к провайдеру: роутер отвечал нормально, а трафик наружу не "
                 "шёл. Различить можно двумя способами: запросить у провайдера "
                 "журнал состояния линии за указанные выше времена либо в момент "
                 "сбоя посмотреть статус WAN в интерфейсе роутера.")
    if not C:
        C.append("Отклонения единичные; оснований для выводов о причине нет.")
    for i, c in enumerate(C, 1):
        L += wrap(f"{i}. {c}", 76, "  ", "     ")
    L.append("")

    L.append("ЧЕГО ЭТОТ ОТЧЁТ НЕ ПОКАЗЫВАЕТ")
    L += wrap("- Качество Wi-Fi по комнатам: сервер подключён проводом. Для этого "
              "нужен такой же замер с устройства, подключённого по Wi-Fi.", 76, "  ", "    ")
    L += wrap(f"- Замирания короче {INTERVAL_SEC} секунд: они попадают между замерами.",
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
                  "ctl_try", "ctl_lost"):
            m[k] += s[k]
        m["rtt"].extend(s["rtt"])
        m["ext"].extend(s["ext"])
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


EVENT_KINDS = {
    "outage": "Полный обрыв интернета",
    "dns": "Отказ DNS роутера",
    "partial": "Частичная потеря связи",
    "gwmute": "Роутер молчал по локальной сети",
}


def render_html(A, text_report):
    import html as _html
    T = A.total
    points, ticks, pos, step_min = build_timeline(A)
    ext_base = quantile(T["ext"], 0.5)
    thr = (max(SLOW_FACTOR * ext_base, ext_base + SLOW_MIN_MS)
           if ext_base is not None else None)

    events = []
    for e in A.events:
        if e["kind"] not in EVENT_KINDS:
            continue
        if e["kind"] != "outage" and e["dur"] < OUTAGE_MIN_SEC:
            continue
        note = e.get("text", "") or {
            "dns": "Интернет по IP в это время работал",
            "partial": "Недоступна часть внешних ресурсов",
            "gwmute": "Интернет в это время работал",
        }.get(e["kind"], "")
        if e["kind"] == "dns" and e["ctl_try"]:
            note = ("Контрольный DNS в это время отвечал — отказ на стороне роутера"
                    if e["ctl_lost"] == 0 else
                    f"Контрольный DNS тоже терял запросы ({e['ctl_lost']} из {e['ctl_try']})")
        events.append({
            "a": round(pos(e["start"]), 3), "b": round(pos(e["end"]), 3),
            "start": fmt_dt(e["start"]), "dur": fmt_dur(e["dur"]),
            "kind": EVENT_KINDS[e["kind"]],
            "note": (note[:1].upper() + note[1:]) if note else "",
        })
    gaps = [{"a": round(pos(st), 3), "b": round(pos(en), 3),
             "start": fmt_dt(st), "dur": fmt_dur(dt)} for st, en, dt in A.gaps]

    outages = [e for e in A.events if e["kind"] == "outage"]
    blips = sum(1 for e in A.events if e["kind"] == "blip")
    tiles = [
        {"k": "Полных обрывов интернета", "v": str(len(outages)),
         "s": ("суммарно " + fmt_dur(sum(e["sec"]["blackout"] for e in outages))
               if outages else f"коротких (до {OUTAGE_MIN_SEC} сек): {blips}")},
        {"k": "Интернет был доступен",
         "v": f"{100 - pct(T['black_sec'], T['sec']):.2f}%".replace(".", ","),
         "s": "времени наблюдения"},
        {"k": "Замеров с отклонениями",
         "v": f"{pct(T['bad'], T['n']):.2f}%".replace(".", ","),
         "s": f"из {T['n']}"},
    ]
    if A.has_rdns:
        tiles.append({
            "k": "DNS роутера: без ответа",
            "v": f"{pct(T['dns_lost'], T['dns_try']):.2f}%".replace(".", ","),
            "s": (f"контроль мимо роутера: "
                  f"{pct(T['ctl_lost'], T['ctl_try']):.2f}%".replace(".", ",")
                  if T["ctl_try"] else f"{T['dns_lost']} из {T['dns_try']} запросов")})
    if thr is not None:
        n_slow = sum(1 for x in T["ext"] if x >= thr)
        tiles.append({"k": "Медленных замеров",
                      "v": f"{pct(n_slow, len(T['ext'])):.2f}%".replace(".", ","),
                      "s": f"задержка наружу от {thr:.0f} мс"})

    charts = []
    if A.has_rdns:
        series = [{"key": "dns", "name": f"DNS роутера ({GATEWAY})", "c": 1}]
        if T["ctl_try"]:
            series.append({"key": "ctl", "name": "Контроль: 8.8.8.8 мимо роутера", "c": 2})
        charts.append({"title": "DNS-запросы без ответа", "unit": "%", "type": "line",
                       "floor": 1, "series": series,
                       "note": "Доля запросов, на которые не пришёл ответ. Рост "
                               "у роутера при ровном контроле указывает на роутер."})
    charts.append({"title": "Замеры с отклонениями", "unit": "%", "type": "bar",
                   "floor": 1,
                   "series": [{"key": "bad", "name": "Замеры с отклонениями", "c": 1}],
                   "note": "Доля замеров, в которых что-то не ответило: внешние "
                           "ресурсы, DNS роутера или сам роутер."})
    charts.append({"title": "Ответ роутера по локальной сети", "unit": "мс",
                   "type": "line", "floor": 10,
                   "series": [{"key": "rm", "name": "Обычная задержка", "c": 1},
                              {"key": "r95", "name": "5% худших замеров", "c": 2}],
                   "note": "Время TCP-подключения к роутеру. Рост в часы занятий "
                           "— признак нагрузки на роутер."})
    charts.append({"title": "Задержка до внешних ресурсов", "unit": "мс",
                   "type": "line", "floor": 50,
                   "series": [{"key": "em", "name": "Обычная задержка", "c": 1},
                              {"key": "e95", "name": "5% худших замеров", "c": 2}],
                   "note": "Время TCP-подключения к внешним серверам через роутер."})

    data = {
        "period": f"с {fmt_dt(A.first)} по {fmt_dt(A.last)}",
        "observed": fmt_dur(T["sec"]), "samples": T["n"],
        "step": (f"{step_min} мин" if step_min < 60 else f"{step_min // 60} ч"),
        "points": points, "ticks": ticks, "events": events, "gaps": gaps,
        "tiles": tiles, "charts": charts,
    }
    blob = json.dumps(data, ensure_ascii=False).replace("</", "<\\/")
    return (HTML_TEMPLATE
            .replace("__DATA__", blob)
            .replace("__TEXT__", _html.escape(text_report)))


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
  --s1: #2a78d6; --s2: #eb6834; --critical: #d03b3b; --gap: #8a8880;
}
@media (prefers-color-scheme: dark) {
  :root {
    color-scheme: dark;
    --page: #111110; --surface: #1a1a19; --border: #33322f;
    --text: #f0efec; --text2: #c3c2b7; --muted: #8a8880; --grid: #2a2a28;
    --s1: #3987e5; --s2: #d95926; --critical: #d03b3b; --gap: #8a8880;
  }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--page); color: var(--text);
  font: 14px/1.45 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
main { max-width: 1100px; margin: 0 auto; padding: 24px 16px 48px; }
h1 { font-size: 22px; margin: 0 0 4px; }
h2 { font-size: 15px; margin: 0; }
.sub { color: var(--text2); margin: 0 0 20px; }
.tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
  gap: 12px; margin-bottom: 16px; }
.tile, .card { background: var(--surface); border: 1px solid var(--border);
  border-radius: 10px; }
.tile { padding: 12px 14px; }
.tile .k { color: var(--text2); font-size: 12px; }
.tile .v { font-size: 26px; font-weight: 600; font-variant-numeric: tabular-nums;
  margin: 2px 0; }
.tile .s { color: var(--muted); font-size: 12px; }
.key { display: flex; flex-wrap: wrap; gap: 6px 18px; color: var(--text2);
  font-size: 12px; margin: 0 2px 16px; }
.key span { display: inline-flex; align-items: center; gap: 6px; }
.sw { width: 14px; height: 10px; border-radius: 2px; display: inline-block; }
.sw.ev { background: var(--critical); opacity: .28; }
.sw.gp { background: var(--gap); opacity: .28; }
.card { padding: 14px 14px 8px; margin-bottom: 14px; position: relative; }
.note { color: var(--text2); font-size: 12px; margin: 2px 0 8px; max-width: 760px; }
.legend { display: flex; flex-wrap: wrap; gap: 4px 16px; font-size: 12px;
  color: var(--text2); margin-bottom: 4px; }
.legend i { width: 14px; height: 3px; border-radius: 2px; display: inline-block;
  vertical-align: middle; margin-right: 6px; }
svg { display: block; width: 100%; height: auto; overflow: visible; }
svg text { fill: var(--muted); font-size: 11px; font-variant-numeric: tabular-nums; }
.tip { position: absolute; pointer-events: none; background: var(--surface);
  border: 1px solid var(--border); border-radius: 8px; padding: 8px 10px;
  font-size: 12px; box-shadow: 0 4px 14px rgba(0,0,0,.14); white-space: nowrap;
  display: none; z-index: 5; }
.tip b { font-variant-numeric: tabular-nums; }
.tip .t { color: var(--text2); margin-bottom: 4px; }
.tip .r { display: flex; align-items: center; gap: 6px; }
.tip .r i { width: 10px; height: 3px; border-radius: 2px; display: inline-block; }
.tip .n { color: var(--muted); margin-top: 4px; }
table { border-collapse: collapse; width: 100%; font-size: 13px; }
th, td { text-align: left; padding: 6px 10px 6px 0; border-bottom: 1px solid var(--border);
  vertical-align: top; }
th { color: var(--text2); font-weight: 500; font-size: 12px; }
td.num { white-space: nowrap; font-variant-numeric: tabular-nums; }
.scroll { overflow-x: auto; }
details { margin-top: 14px; }
summary { cursor: pointer; color: var(--text2); }
pre { background: var(--surface); border: 1px solid var(--border); border-radius: 10px;
  padding: 14px; overflow-x: auto; font-size: 12px; line-height: 1.4; }
.empty { color: var(--text2); padding: 4px 0 8px; }
</style>
</head>
<body>
<main>
  <h1>NetDiag — отчёт</h1>
  <p class="sub" id="sub"></p>
  <div class="tiles" id="tiles"></div>
  <div class="key">
    <span><i class="sw ev"></i>красная полоса — событие из списка ниже</span>
    <span><i class="sw gp"></i>серая полоса — сервер не работал, замеров нет</span>
    <span id="stepnote"></span>
  </div>
  <div id="charts"></div>
  <div class="card">
    <h2>События</h2>
    <div class="note">Сбои длительностью от 30 секунд. На графиках отмечены красными полосами.</div>
    <div class="scroll" id="events"></div>
  </div>
  <details>
    <summary>Полный текстовый отчёт с таблицами по часам</summary>
    <pre>__TEXT__</pre>
  </details>
</main>
<script type="application/json" id="data">__DATA__</script>
<script>
(function () {
  var D = JSON.parse(document.getElementById('data').textContent);
  var NS = 'http://www.w3.org/2000/svg';
  var N = D.points.length;
  function el(tag, attrs, parent) {
    var e = document.createElementNS(NS, tag);
    for (var k in attrs) e.setAttribute(k, attrs[k]);
    if (parent) parent.appendChild(e);
    return e;
  }
  function h(tag, cls, text, parent) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    if (parent) parent.appendChild(e);
    return e;
  }
  function fmt(v, unit) {
    if (v == null) return '—';
    var s = (unit === '%' ? v.toFixed(2) : (v < 10 ? v.toFixed(1) : v.toFixed(0)));
    return s.replace('.', ',') + ' ' + unit;
  }
  function nice(m) {
    var p = Math.pow(10, Math.floor(Math.log10(m))), f = m / p;
    var n = f <= 1 ? 1 : f <= 2 ? 2 : f <= 2.5 ? 2.5 : f <= 5 ? 5 : 10;
    return n * p;
  }

  document.getElementById('sub').textContent =
    'Период: ' + D.period + ' · наблюдение ' + D.observed + ' · замеров: ' + D.samples;
  document.getElementById('stepnote').textContent = 'одна точка графика = ' + D.step;
  var tiles = document.getElementById('tiles');
  D.tiles.forEach(function (t) {
    var d = h('div', 'tile', null, tiles);
    h('div', 'k', t.k, d); h('div', 'v', t.v, d); h('div', 's', t.s, d);
  });

  var ev = document.getElementById('events');
  if (!D.events.length) {
    h('div', 'empty', 'Событий за период нет.', ev);
  } else {
    var tb = h('table', null, null, ev), tr = h('tr', null, null, tb);
    ['Начало', 'Длительность', 'Что произошло', 'Что наблюдалось'].forEach(function (x) { h('th', null, x, tr); });
    D.events.forEach(function (e) {
      var r = h('tr', null, null, tb);
      h('td', 'num', e.start, r); h('td', 'num', e.dur, r);
      h('td', null, e.kind, r); h('td', null, e.note, r);
    });
  }

  var host = document.getElementById('charts');
  var cards = D.charts.map(function (c) {
    var card = h('div', 'card', null, host);
    h('h2', null, c.title + ', ' + c.unit, card);
    h('div', 'note', c.note, card);
    if (c.series.length > 1) {
      var lg = h('div', 'legend', null, card);
      c.series.forEach(function (s) {
        var sp = h('span', null, null, lg), i = h('i', null, null, sp);
        i.style.background = 'var(--s' + s.c + ')';
        sp.appendChild(document.createTextNode(s.name));
      });
    }
    var box = h('div', null, null, card);
    var tip = h('div', 'tip', null, card);
    return { c: c, card: card, box: box, tip: tip };
  });

  function draw(o) {
    var c = o.c, W = Math.max(320, o.box.clientWidth), H = 190;
    var m = { l: 46, r: 10, t: 8, b: 22 }, pw = W - m.l - m.r, ph = H - m.t - m.b;
    o.box.textContent = '';
    var svg = el('svg', { viewBox: '0 0 ' + W + ' ' + H, role: 'img', 'aria-label': c.title }, o.box);
    var max = c.floor;
    D.points.forEach(function (p) { c.series.forEach(function (s) { if (p[s.key] != null && p[s.key] > max) max = p[s.key]; }); });
    var step = nice(max / 4); max = step * 4;
    var X = function (i) { return m.l + i / N * pw; };
    var Y = function (v) { return m.t + ph - v / max * ph; };

    for (var g = 0; g <= 4; g++) {
      var v = max * g / 4, y = Y(v);
      el('line', { x1: m.l, x2: m.l + pw, y1: y, y2: y, stroke: 'var(--grid)', 'stroke-width': 1 }, svg);
      var t = el('text', { x: m.l - 6, y: y + 4, 'text-anchor': 'end' }, svg);
      t.textContent = String(+v.toFixed(3)).replace('.', ',');
    }
    D.ticks.forEach(function (k) {
      var x = X(k.x);
      el('line', { x1: x, x2: x, y1: m.t + ph, y2: m.t + ph + 4, stroke: 'var(--grid)' }, svg);
      var t = el('text', { x: x, y: H - 6, 'text-anchor': 'middle' }, svg); t.textContent = k.label;
    });
    function band(a, b, color) {
      var x1 = X(a), w = Math.max(2, X(b) - x1);
      el('rect', { x: x1, y: m.t, width: w, height: ph, fill: color, opacity: .2 }, svg);
    }
    D.gaps.forEach(function (gp) { band(gp.a, gp.b, 'var(--gap)'); });
    D.events.forEach(function (e) { band(e.a, e.b, 'var(--critical)'); });

    c.series.forEach(function (s) {
      var col = 'var(--s' + s.c + ')';
      if (c.type === 'bar') {
        var bw = Math.max(1, pw / N - 2);
        D.points.forEach(function (p, i) {
          var v = p[s.key]; if (v == null || v <= 0) return;
          var y = Y(v), hh = Math.max(1.5, m.t + ph - y);
          el('rect', { x: X(i + .5) - bw / 2, y: m.t + ph - hh, width: bw, height: hh, rx: Math.min(2, bw / 2), fill: col }, svg);
        });
        return;
      }
      var d = '', open = false;
      D.points.forEach(function (p, i) {
        var v = p[s.key];
        if (v == null) { open = false; return; }
        d += (open ? 'L' : 'M') + X(i + .5).toFixed(1) + ' ' + Y(v).toFixed(1);
        open = true;
        var prev = i > 0 ? D.points[i - 1][s.key] : null, next = i < N - 1 ? D.points[i + 1][s.key] : null;
        if (prev == null && next == null) el('circle', { cx: X(i + .5), cy: Y(v), r: 2.5, fill: col }, svg);
      });
      el('path', { d: d, fill: 'none', stroke: col, 'stroke-width': 2, 'stroke-linejoin': 'round', 'stroke-linecap': 'round' }, svg);
    });

    var hair = el('line', { y1: m.t, y2: m.t + ph, stroke: 'var(--muted)', 'stroke-width': 1, visibility: 'hidden' }, svg);
    var hit = el('rect', { x: m.l, y: m.t, width: pw, height: ph, fill: 'transparent' }, svg);
    function move(evt) {
      var r = svg.getBoundingClientRect(), sx = W / r.width;
      var i = Math.floor(((evt.clientX - r.left) * sx - m.l) / pw * N);
      if (i < 0 || i >= N) return leave();
      var p = D.points[i], x = X(i + .5);
      hair.setAttribute('x1', x); hair.setAttribute('x2', x); hair.setAttribute('visibility', 'visible');
      var tip = o.tip; tip.textContent = '';
      h('div', 't', p.label, tip);
      if (!p.n) { h('div', null, 'замеров нет', tip); }
      else {
        c.series.forEach(function (s) {
          var row = h('div', 'r', null, tip), sw = h('i', null, null, row);
          sw.style.background = 'var(--s' + s.c + ')';
          h('b', null, fmt(p[s.key], c.unit), row);
          row.appendChild(document.createTextNode(s.name));
        });
        h('div', 'n', 'замеров: ' + p.n, tip);
      }
      tip.style.display = 'block';
      var cr = o.card.getBoundingClientRect(), px = r.left - cr.left + x / sx;
      var left = px + 12;
      if (left + tip.offsetWidth > cr.width - 8) left = px - tip.offsetWidth - 12;
      tip.style.left = Math.max(4, left) + 'px';
      tip.style.top = (r.top - cr.top + 8) + 'px';
    }
    function leave() { hair.setAttribute('visibility', 'hidden'); o.tip.style.display = 'none'; }
    hit.addEventListener('pointermove', move);
    hit.addEventListener('pointerleave', leave);
  }
  function drawAll() { cards.forEach(draw); }
  drawAll();
  var tm; window.addEventListener('resize', function () { clearTimeout(tm); tm = setTimeout(drawAll, 120); });
})();
</script>
</body>
</html>
"""


def build_report(since=None, until=None):
    A = Analyzer()
    if os.path.exists(OUT_JSONL):
        with open(OUT_JSONL, encoding="utf-8") as f:
            for line in f:
                try:
                    r = json.loads(line)
                    ts = to_aware(r["ts"])
                    data = r["data"]
                except Exception:
                    continue
                if (since and ts < since) or (until and ts >= until):
                    continue
                A.feed(ts, data, r.get("dev") if USE_DEVICE_COUNT else None)
    A.finish()
    txt = render(A) if A.first is not None else "Отчёт пуст: нет данных.\n"
    with open(OUT_REPORT, "w", encoding="utf-8") as f:
        f.write(txt)
    if A.first is not None:
        try:
            with open(OUT_HTML, "w", encoding="utf-8") as f:
                f.write(render_html(A, txt))
        except Exception as e:                 # графики не должны ломать отчёт
            log.warning("html report failed: %s", e)
    log.info("report written: %s", OUT_REPORT)
    return txt


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
        except (IndexError, ValueError):
            sys.exit("Формат: report [--since ГГГГ-ММ-ДД] [--until ГГГГ-ММ-ДД]")
        sys.stdout.write(build_report(since, until))
    else:
        run()
