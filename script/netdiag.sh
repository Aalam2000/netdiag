#!/bin/bash
# NetDiag control script
set -e

# --- Определяем реальный путь скрипта, даже если он запущен через симлинк ---
SOURCE="${BASH_SOURCE[0]}"
while [ -L "$SOURCE" ]; do
    DIR="$(cd -P "$(dirname "$SOURCE")" && pwd)"
    SOURCE="$(readlink "$SOURCE")"
    [[ "$SOURCE" != /* ]] && SOURCE="$DIR/$SOURCE"
done
SCRIPT_DIR="$(cd -P "$(dirname "$SOURCE")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_DIR"

CMD="$1"

case "$CMD" in
  start)
    echo "[*] Запуск NetDiag..."
    docker compose up -d --build
    sleep 3
    docker compose ps
    echo "[*] Пишет в ./data/netdiag.jsonl"
    ;;

  stop)
    echo "[*] Строю отчёт и останавливаю..."
    docker compose exec -T netdiag python /app/netdiag.py report > /dev/null || true
    docker compose stop
    echo "[*] Отчёт готов: ./data/report.txt"
    ;;

  restart)
    docker compose restart
    ;;

  status)
    docker compose ps
    echo
    tail -n 10 data/netdiag.log 2>/dev/null || true
    ;;

  log)
    docker compose logs -f
    ;;

  raw)
    tail -n 10 data/netdiag.jsonl
    ;;

  report)
    echo "[*] Строю отчёт по накопленным данным..."
    shift
    docker compose exec -T netdiag python /app/netdiag.py report "$@"
    ;;

  down)
    docker compose down
    ;;

  clean)
    docker compose down
    rm -rf data/
    ;;

  *)
    echo "Использование: netdiag {start|stop|restart|status|log|raw|report|down|clean}"
    echo ""
    echo "  start    — запустить мониторинг"
    echo "  stop     — построить отчёт и остановить"
    echo "  restart  — перезапустить"
    echo "  status   — статус контейнера + последние логи"
    echo "  log      — живой лог (Ctrl+C для выхода)"
    echo "  raw      — последние 10 сырых замеров"
    echo "  report   — построить отчёт (не останавливая мониторинг)"
    echo "             report --since 2026-10-12 --until 2026-10-19 — за период"
    echo "  down     — удалить контейнер (данные остаются)"
    echo "  clean    — удалить контейнер и папку data/"
    exit 1
    ;;
esac