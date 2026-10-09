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
TARGETS = [
    ("dns_google",  "8.8.8.8",       53),
    ("dns_cf",      "1.1.1.1",       53),
    ("dns_quad9",   "9.9.9.9",       53),
    ("https_google","google.com",   443),
    ("https_cf",    "cloudflare.com",443),
    ("https_github","github.com",   443),
]
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

    per = defaultdict(lambda: {"outages": [], "last_ok": True,
                               "start": None, "rtts_all": []})
    all_down = {"last_ok": True, "start": None, "outages": []}

    for r in recs:
        ts = r["ts"]
        ok_any = False
        any_down = False
        for n, d in r["data"].items():
            s = per[n]
            if d["ok"]:
                ok_any = True
                if d.get("rtt") is not None:
                    s["rtts_all"].append(d["rtt"])
                if not s["last_ok"]:
                    s["outages"].append((s["start"], ts)); s["start"] = None
                s["last_ok"] = True
            else:
                any_down = True
                if s["last_ok"]: s["start"] = ts
                s["last_ok"] = False
        if not ok_any and any_down:
            if all_down["last_ok"]:
                all_down["start"] = ts
            all_down["last_ok"] = False
        else:
            if not all_down["last_ok"]:
                all_down["outages"].append((all_down["start"], ts))
                all_down["start"] = None
            all_down["last_ok"] = True

    for s in per.values():
        if not s["last_ok"] and s["start"]:
            s["outages"].append((s["start"], t_end))
    if not all_down["last_ok"] and all_down["start"]:
        all_down["outages"].append((all_down["start"], t_end))

    def long_only(lst):
        out = []
        for st, en in lst:
            try:
                dt = (to_aware(en) - to_aware(st)).total_seconds()
            except: dt = 0
            if dt >= OUTAGE_MIN_SEC:
                out.append((st, en, dt))
        return out

    all_down_long = long_only(all_down["outages"])
    per_long = {n: long_only(s["outages"]) for n, s in per.items()}

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

    L = []
    L.append(f"Отчет за интервал с {fmt_dt(t_start)} по {fmt_dt(t_end)}")
    L.append("")
    L.append("Диагностика проводилась методом TCP-подключения к внешним ресурсам:")
    L.append("  DNS 8.8.8.8:53, DNS 1.1.1.1:53, DNS 9.9.9.9:53,")
    L.append("  HTTPS google.com:443, HTTPS cloudflare.com:443, HTTPS github.com:443.")
    L.append(f"Проверка выполнялась каждые {INTERVAL_SEC} секунд.")
    L.append("Сервер подключён проводом к шлюзу 192.168.0.1,")
    L.append("Wi-Fi и TP-Link в цепи не участвуют.")
    L.append("")

    if gaps:
        L.append("Внимание: в период наблюдения сервер был выключен:")
        for st, en, dt in gaps:
            L.append(f"  с {fmt_dt(st)} по {fmt_dt(en)} ({fmt_dur(dt)}) — диагностика не проводилась.")
        L.append("")

    if not all_down_long:
        L.append("Сбоев доступа в интернет за период наблюдения не зафиксировано.")
    else:
        L.append(f"За период наблюдения зафиксировано {len(all_down_long)} "
                 f"сбоев доступа в интернет:")
        L.append("")
        total_dur = 0
        for st, en, dt in all_down_long:
            total_dur += dt
            L.append(f"  Сбой доступа в интернет с {fmt_dt(st)} по {fmt_dt(en)} ({fmt_dur(dt)})")
        L.append("")
        L.append(f"Всего сбоев: {len(all_down_long)}. "
                 f"Общая длительность недоступности: {fmt_dur(total_dur)}.")

    partial = []
    for n, lst in per_long.items():
        if lst:
            for st, en, dt in lst:
                inside = False
                for ast, aen, _ in all_down_long:
                    if ast <= st and en <= aen:
                        inside = True; break
                if not inside:
                    partial.append((n, st, en, dt))
    if partial:
        L.append("")
        L.append("Отдельные ресурсы были недоступны (при работающем интернете в целом):")
        for n, st, en, dt in partial:
            host = next(h for (nm, h, p) in TARGETS if nm == n)
            L.append(f"  {host} — с {fmt_dt(st)} по {fmt_dt(en)} ({fmt_dur(dt)})")

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