#!/usr/bin/env python3
import socket, time, json, statistics, os, signal, logging, sys
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict
from zoneinfo import ZoneInfo

TZ = ZoneInfo("Asia/Baku")

def now():
    return datetime.now(TZ)

# ==== КОНФИГ ====
# Локальные цели — проверяем доступность роутера (шлюза)
LOCAL_TARGETS = [
    ("gw_80",  "192.168.0.1", 80),
    ("gw_443", "192.168.0.1", 443),
]
# Внешние цели — проверяем доступность интернета
EXTERNAL_TARGETS = [
    ("dns_google",  "8.8.8.8",       53),
    ("dns_cf",      "1.1.1.1",       53),
    ("dns_quad9",   "9.9.9.9",       53),
    ("https_google","google.com",   443),
    ("https_cf",    "cloudflare.com",443),
    ("https_github","github.com",   443),
]
TARGETS = LOCAL_TARGETS + EXTERNAL_TARGETS
INTERVAL_SEC = 5
TCP_TIMEOUT  = 2.0
OUTAGE_MIN_SEC = 30
WORK_DIR     = "/data"
OUT_JSONL    = f"{WORK_DIR}/netdiag.jsonl"
OUT_REPORT   = f"{WORK_DIR}/report.txt"
HEARTBEAT    = f"{WORK_DIR}/heartbeat"
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
    global _stop; _stop = True
    log.info("SIGTERM received")
signal.signal(signal.SIGTERM, _on_term)
signal.signal(signal.SIGINT, _on_term)


def tcp_check(host, port, timeout=TCP_TIMEOUT):
    t0 = time.perf_counter()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        rtt = (time.perf_counter() - t0) * 1000
        return {"ok": True, "rtt": rtt, "err": None}
    except socket.timeout:
        return {"ok": False, "rtt": None, "err": "timeout"}
    except ConnectionRefusedError:
        return {"ok": False, "rtt": None, "err": "refused"}
    except Exception as e:
        return {"ok": False, "rtt": None, "err": type(e).__name__}
    finally:
        s.close()


def sample_all():
    res = {}
    with ThreadPoolExecutor(max_workers=len(TARGETS)) as ex:
        futs = {ex.submit(tcp_check, h, p): (n, h, p) for n, h, p in TARGETS}
        for f, (n, h, p) in futs.items():
            d = f.result()
            d["host"] = h; d["port"] = p
            res[n] = d
    return res


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
            raw = f.read().strip()
        last = datetime.fromisoformat(raw)
        n = now()
        if last.tzinfo is None:
            last = last.replace(tzinfo=TZ)
        gap = (n - last).total_seconds()
        if gap > INTERVAL_SEC * 3:
            log.info("GAP detected: server down from %s to %s (%.0f sec)",
                     last.isoformat(), n.isoformat(), gap)
    except Exception as e:
        log.warning("gap check failed: %s", e)


def run():
    check_startup_gap()
    log.info("START interval=%ss", INTERVAL_SEC)
    with open(OUT_JSONL, "a", buffering=1) as f:
        while not _stop:
            t0 = time.time()
            write_heartbeat()
            f.write(json.dumps({
                "ts": now().isoformat(timespec="milliseconds"),
                "data": sample_all()
            }) + "\n")
            f.flush()
            os.fsync(f.fileno())
            time.sleep(max(0, INTERVAL_SEC - (time.time() - t0)))
    log.info("STOP -> building report")
    build_report()


def fmt_dt(iso):
    dt = datetime.fromisoformat(iso)
    if dt.tzinfo is not None:
        dt = dt.astimezone(TZ)
    return dt.strftime("%d.%m.%y %H:%M:%S")


def fmt_dur(sec):
    sec = int(sec)
    h = sec // 3600
    m = (sec % 3600) // 60
    s = sec % 60
    parts = []
    if h: parts.append(f"{h} ч")
    if m: parts.append(f"{m} мин")
    if s or not parts: parts.append(f"{s} сек")
    return " ".join(parts)


def to_aware(iso):
    dt = datetime.fromisoformat(iso)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=TZ)
    return dt


def build_report():
    recs = []
    with open(OUT_JSONL) as f:
        for line in f:
            try: recs.append(json.loads(line))
            except: pass

    if not recs:
        with open(OUT_REPORT, "w", encoding="utf-8") as f:
            f.write("Отчёт пуст: нет данных.\n")
        return

    t_start = recs[0]["ts"]
    t_end   = recs[-1]["ts"]

    # --- паузы (сервер был выключен) ---
    gaps = []
    prev_ts = None
    for r in recs:
        try: cur = to_aware(r["ts"])
        except: continue
        if prev_ts:
            dt = (cur - prev_ts).total_seconds()
            if dt > INTERVAL_SEC * 3:
                gaps.append((prev_ts.isoformat(), cur.isoformat(), dt))
        prev_ts = cur

    # --- инциденты по каждой цели ---
    per = defaultdict(lambda: {"outages": [], "last_ok": True,
                               "start": None, "rtts_all": []})
    # --- "роутер недоступен" (обе gw-цели down) ---
    gw_down = {"last_ok": True, "start": None, "outages": []}
    # --- "интернет недоступен" (все внешние цели down) ---
    net_down = {"last_ok": True, "start": None, "outages": []}

    for r in recs:
        ts = r["ts"]
        data = r["data"]

        # обновляем per-цели
        for n, d in data.items():
            s = per[n]
            if d["ok"]:
                if d.get("rtt") is not None:
                    s["rtts_all"].append(d["rtt"])
                if not s["last_ok"]:
                    s["outages"].append((s["start"], ts)); s["start"] = None
                s["last_ok"] = True
            else:
                if s["last_ok"]: s["start"] = ts
                s["last_ok"] = False

        # состояние шлюза — обе локальные цели
        gw_local = [data.get(n) for n, _, _ in LOCAL_TARGETS]
        gw_ok = any(d and d.get("ok") for d in gw_local)

        # состояние интернета — хотя бы одна внешняя цель
        ext_local = [data.get(n) for n, _, _ in EXTERNAL_TARGETS]
        ext_ok = any(d and d.get("ok") for d in ext_local)

        # шлюз упал
        if not gw_ok:
            if gw_down["last_ok"]:
                gw_down["start"] = ts
            gw_down["last_ok"] = False
        else:
            if not gw_down["last_ok"]:
                gw_down["outages"].append((gw_down["start"], ts))
                gw_down["start"] = None
            gw_down["last_ok"] = True

        # интернет упал
        if not ext_ok:
            if net_down["last_ok"]:
                net_down["start"] = ts
            net_down["last_ok"] = False
        else:
            if not net_down["last_ok"]:
                net_down["outages"].append((net_down["start"], ts))
                net_down["start"] = None
            net_down["last_ok"] = True

    # закрыть незакрытые
    for s in per.values():
        if not s["last_ok"] and s["start"]:
            s["outages"].append((s["start"], t_end))
    for d in (gw_down, net_down):
        if not d["last_ok"] and d["start"]:
            d["outages"].append((d["start"], t_end))

    def long_only(lst):
        out = []
        for st, en in lst:
            try:
                dt = (to_aware(en) - to_aware(st)).total_seconds()
            except: dt = 0
            if dt >= OUTAGE_MIN_SEC:
                out.append((st, en, dt))
        return out

    gw_long  = long_only(gw_down["outages"])
    net_long = long_only(net_down["outages"])
    per_long = {n: long_only(s["outages"]) for n, s in per.items()}

    # --- классификация каждого сбоя ---
    # Собираем все инциденты "что-то не работало" (объединяем по времени).
    # Классифицируем: если внутри интервала шлюз был down — виновник роутер,
    # если шлюз был ok, а интернета нет — виновник провайдер.
    events = []
    # по всем внешним целям — объединяем как один "интернет упал" = net_long
    for st, en, dt in net_long:
        # определяем состояние шлюза в этом интервале
        gw_bad = False
        for gst, gen, _ in gw_long:
            # пересечение интервалов
            if to_aware(gst) <= to_aware(en) and to_aware(st) <= to_aware(gen):
                gw_bad = True; break
        events.append({
            "start": st, "end": en, "dur": dt,
            "cause": "router" if gw_bad else "provider",
        })
    # отдельно: если шлюз падал, но интернет по нашим данным был жив —
    # это тоже инцидент (роутер глючит, но интернет через него шёл).
    for gst, gen, dt in gw_long:
        inside_net = False
        for st, en, _ in net_long:
            if to_aware(st) <= to_aware(gst) and to_aware(gen) <= to_aware(en):
                inside_net = True; break
        if not inside_net:
            events.append({
                "start": gst, "end": gen, "dur": dt,
                "cause": "router",
            })
    # сортировка по времени
    events.sort(key=lambda e: to_aware(e["start"]))

    # --- RTT статистика ---
    all_rtts = []
    for s in per.values():
        all_rtts.extend(s["rtts_all"])
    avg_rtt = statistics.mean(all_rtts) if all_rtts else 0
    max_rtt = max(all_rtts) if all_rtts else 0
    max_rtt_ts = None
    if all_rtts:
        for r in recs:
            for n, d in r["data"].items():
                if d["ok"] and d.get("rtt") == max_rtt:
                    max_rtt_ts = r["ts"]; break
            if max_rtt_ts: break

    # --- формируем отчёт ---
    L = []
    L.append(f"Отчет за интервал с {fmt_dt(t_start)} по {fmt_dt(t_end)}")
    L.append("")
    L.append("Диагностика проводилась методом TCP-подключения:")
    L.append("  Шлюз/роутер:      192.168.0.1:80, 192.168.0.1:443")
    L.append("  Внешние ресурсы:  8.8.8.8:53, 1.1.1.1:53, 9.9.9.9:53,")
    L.append("                    google.com:443, cloudflare.com:443, github.com:443")
    L.append(f"Проверка выполнялась каждые {INTERVAL_SEC} секунд.")
    L.append("Сервер подключён проводом к роутеру 192.168.0.1.")
    L.append("")

    if gaps:
        L.append("Внимание: в период наблюдения сервер был недоступен:")
        for st, en, dt in gaps:
            L.append(f"  с {fmt_dt(st)} по {fmt_dt(en)} ({fmt_dur(dt)}) — диагностика не проводилась.")
        L.append("")

    if not events:
        L.append("Сбоев в работе сети и интернета за период наблюдения не зафиксировано.")
    else:
        L.append(f"За период наблюдения зафиксировано {len(events)} сбоев:")
        L.append("")
        total_dur = 0
        for e in events:
            total_dur += e["dur"]
            cause = ("проблема роутера TP-Link (192.168.0.1 не отвечал)"
                     if e["cause"] == "router"
                     else "проблема на стороне провайдера (роутер был доступен, интернет отсутствовал)")
            L.append(f"  Сбой с {fmt_dt(e['start'])} по {fmt_dt(e['end'])} ({fmt_dur(e['dur'])})")
            L.append(f"    Причина: {cause}.")
        L.append("")
        n_router = sum(1 for e in events if e["cause"] == "router")
        n_prov   = sum(1 for e in events if e["cause"] == "provider")
        L.append(f"Всего сбоев: {len(events)}. "
                 f"Общая длительность: {fmt_dur(total_dur)}.")
        L.append(f"  Из них по вине роутера TP-Link: {n_router}.")
        L.append(f"  Из них по вине провайдера:      {n_prov}.")

    L.append("")
    L.append(f"Средняя задержка до внешних ресурсов: {avg_rtt:.0f} мс.")
    L.append(f"Максимальная задержка: {max_rtt:.0f} мс" +
             (f" (зафиксирована {fmt_dt(max_rtt_ts)})." if max_rtt_ts else "."))

    txt = "\n".join(L)
    with open(OUT_REPORT, "w", encoding="utf-8") as f:
        f.write(txt)
    log.info("report written: %s", OUT_REPORT)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "report":
        build_report()
        print(open(OUT_REPORT, encoding="utf-8").read())
    else:
        run()