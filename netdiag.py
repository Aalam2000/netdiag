#!/usr/bin/env python3
"""
NetDiag — мониторинг роутера и интернета с проводного сервера.

Режимы:
    python netdiag.py                    — сбор данных (бесконечно)
    python netdiag.py report             — отчёт по всем накопленным данным
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
EXTERNAL_TARGETS = [
    ("dns_google",   "tcp", "8.8.8.8",        53),
    ("dns_cf",       "tcp", "1.1.1.1",        53),
    ("dns_quad9",    "tcp", "9.9.9.9",        53),
    ("https_google", "tcp", "google.com",     443),
    ("https_cf",     "tcp", "cloudflare.com", 443),
    ("https_github", "tcp", "github.com",     443),
]
TARGETS = LOCAL_TARGETS + ROUTER_DNS_TARGETS + EXTERNAL_TARGETS
DNS_PROBE_NAME = "google.com"    # какое имя спрашиваем у DNS роутера

INTERVAL_SEC   = 5       # период опроса
TCP_TIMEOUT    = 2.0     # таймаут одной проверки
CYCLE_BUDGET   = 3.5     # предел на весь цикл (зависший DNS не тормозит замеры)
OUTAGE_MIN_SEC = 30      # от какой длительности событие попадает в список
MERGE_SEC      = 30      # события с паузой короче этой склеиваются в одно
GAP_SEC        = 60      # пауза между замерами дольше этой = сервер не работал

DEVICE_SCAN        = True
DEVICE_SCAN_SEC    = 60  # как часто считать устройства
DEVICE_SETTLE_SEC  = 12  # сколько ждать ответов после рассылки
DEVICE_BUCKETS     = [(0, 20), (21, 40), (41, 60), (61, 80), (81, None)]

WORK_HOURS = (9, 21)     # используется, только если нет данных о числе устройств
MAX_EVENTS_LISTED = 150

WORK_DIR   = os.environ.get("NETDIAG_DATA", "/data")
OUT_JSONL  = f"{WORK_DIR}/netdiag.jsonl"
OUT_REPORT = f"{WORK_DIR}/report.txt"
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


def dns_check(host, port, name=DNS_PROBE_NAME, timeout=TCP_TIMEOUT):
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
    ext_total = ext_ok = ip_total = ip_ok = name_total = name_ok = 0
    ext_rtts = []
    for n, d in data.items():
        ok = bool(d.get("ok"))
        if n == "gw_dns":
            rdns = ok
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
        "ext_rtt": statistics.median(ext_rtts) if ext_rtts else None,
    }


def _stat():
    return {"n": 0, "bad": 0, "sec": 0.0, "black_sec": 0.0,
            "rtt": array("f"), "dev_sum": 0, "dev_n": 0, "dev_max": 0,
            "outages": 0}


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
        self.ext_rtt = array("f")
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
        if c["ext_rtt"] is not None:
            self.ext_rtt.append(c["ext_rtt"])
        groups = [self.total, self.hour[ts.hour], self.wd[ts.weekday()],
                  self.day[ts.date()]]
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
                            "dev": self.last_dev, "pending": None}
            e = self.cur
            e["pending"] = None
            e["n"] += 1
            e["sec"][state] += dt
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


def stat_row(label, s, with_dev):
    row = [label, str(s["n"]), f"{pct(s['bad'], s['n']):.2f}",
           f"{pct(s['black_sec'], s['sec']):.2f}",
           ms(quantile(s["rtt"], 0.5)), ms(quantile(s["rtt"], 0.95))]
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
    L.append("    - TCP-подключение к 6 внешним ресурсам (8.8.8.8, 1.1.1.1, 9.9.9.9,")
    L.append("      google.com, cloudflare.com, github.com) — идёт ли трафик наружу.")
    if with_dev:
        L.append(f"  Раз в {DEVICE_SCAN_SEC} сек считалось число устройств в сети {LAN_NET}")
        L.append("  (по ответам на ARP; в число входят и сами роутеры).")
    else:
        L.append("  Число устройств в сети в этих данных не записано (старая версия")
        L.append("  сборщика) — нагрузка оценивается только по времени суток.")
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
    L += wrap(f"Задержка до внешних ресурсов: обычно {ms(quantile(A.ext_rtt, 0.5))} мс, "
              f"в 5% худших замеров от {ms(quantile(A.ext_rtt, 0.95))} мс.", 76, "  ", "    ")
    if A.rdns_n and not A.rdns_ok:
        L.append(f"  DNS роутера ({GATEWAY}:53) не ответил ни разу — вероятно, он")
        L.append("  выключен; эта проверка в отчёте не учитывается.")
    L.append("")

    head = ["", "замеров", "отклон.,%", "обрыв,%", "роутер,мс", "95%,мс"]
    if with_dev:
        head.append("устройств")
    head.append("обрывов")
    legend = [
        "  отклон. — доля замеров с любым отклонением; обрыв — доля времени без",
        "  интернета; роутер — обычная задержка ответа роутера по локальной сети",
        "  и граница 5% худших замеров; обрывов — число полных обрывов.",
    ]

    # ---------- по числу устройств ----------
    if with_dev:
        L.append("ЗАВИСИМОСТЬ ОТ ЧИСЛА УСТРОЙСТВ В СЕТИ")
        rows = [stat_row(bucket_label(i), A.bucket[i], True)
                for i in range(len(DEVICE_BUCKETS)) if A.bucket[i]["n"]]
        L += table(["устройств"] + head[1:], rows)
        L += legend
        L.append("")

    # ---------- по часам ----------
    L.append("ПО ЧАСАМ СУТОК")
    rows = [stat_row(f"{h:02d}:00", A.hour[h], with_dev)
            for h in range(24) if A.hour[h]["n"]]
    L += table(["час"] + head[1:], rows)
    if not with_dev:
        L += legend
    L.append("")

    L.append("ПО ДНЯМ НЕДЕЛИ")
    rows = [stat_row(WD_NAMES[d], A.wd[d], with_dev)
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
    certain = n_router + len(mute_ev) + (len(dns_ev) if A.has_rdns else 0)
    if certain:
        bits = []
        if n_router:
            bits.append(f"{n_router} — обрывы, при которых роутер не отвечал "
                        "и по локальной сети")
        if A.has_rdns and dns_ev:
            bits.append(f"{len(dns_ev)} — отказы DNS роутера при исправном канале "
                        "(для устройств, получающих DNS от роутера, это выглядит "
                        "как пропавший интернет)")
        if mute_ev:
            bits.append(f"{len(mute_ev)} — роутер переставал отвечать на локальные "
                        "запросы при работающем интернете")
        C.append(f"Событий, которые относятся к роутеру однозначно: {certain} ("
                 + "; ".join(bits) + "). Провайдер на эти проверки не влияет: "
                 "они не выходят за пределы локальной сети.")
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
            for k in ("n", "bad", "sec", "black_sec", "outages"):
                dst[k] += A.hour[h][k]
            dst["rtt"].extend(A.hour[h]["rtt"])
        if work["n"] >= MIN_N and off["n"] >= MIN_N:
            lo, hi = off, work
            lo_name = "в остальное время"
            hi_name = f"с {WORK_HOURS[0]:02d}:00 до {WORK_HOURS[1]:02d}:00"
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
                     "с числом устройств.")
        if r_lo and r_hi and r_hi >= max(2 * r_lo, r_lo + 5):
            C.append(f"Роутер под нагрузкой отвечает медленнее: обычная задержка "
                     f"по локальной сети {r_hi:.0f} мс {hi_name} против "
                     f"{r_lo:.0f} мс {lo_name}.")
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
                A.feed(ts, data, r.get("dev"))
    A.finish()
    txt = render(A) if A.first is not None else "Отчёт пуст: нет данных.\n"
    with open(OUT_REPORT, "w", encoding="utf-8") as f:
        f.write(txt)
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
