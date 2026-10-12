#!/bin/bash
# NetDiag control script
set -e

REPO_URL="https://github.com/Aalam2000/netdiag.git"
BRANCH="main"

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

usage() {
    echo "Использование: netdiag {deploy|start|stop|restart|status|log|raw|report|down|clean}"
    echo ""
    echo "  deploy   — взять последнюю версию из репозитория и перезапустить"
    echo "             deploy --force — то же, затирая правки, сделанные на сервере"
    echo "  start    — запустить мониторинг"
    echo "  stop     — построить отчёт и остановить"
    echo "  restart  — перезапустить"
    echo "  status   — версия, статус контейнера, последние строки лога"
    echo "  log      — живой лог (Ctrl+C для выхода)"
    echo "  raw      — последние 10 сырых замеров"
    echo "  report   — построить отчёт (не останавливая мониторинг)"
    echo "             report --since 2026-10-12 --until 2026-10-19 — за период"
    echo "             report --days 30 — за последние 30 суток; --all — за всё время"
    echo "  down     — удалить контейнер (данные остаются)"
    echo "  clean    — удалить контейнер и папку data/"
}

version() {
    git log -1 --format='%h от %cd — %s' --date=format:'%d.%m.%y %H:%M' 2>/dev/null \
        || echo "неизвестна (папка не связана с репозиторием)"
}

# Проверка файлов перед перезапуском. Возвращает 1, если запускать нельзя.
check_files() {
    if command -v python3 >/dev/null; then
        python3 - <<'PY' || { echo "[!] В netdiag.py синтаксическая ошибка."; return 1; }
import ast, sys
try:
    ast.parse(open("netdiag.py", encoding="utf-8").read())
except SyntaxError as e:
    sys.exit(f"    строка {e.lineno}: {e.msg}")
PY
    else
        echo "[i] python3 на сервере нет — проверку netdiag.py пропускаю."
    fi
    docker compose config -q \
        || { echo "[!] Ошибка в docker-compose.yml."; return 1; }
}

# Весь скрипт выполняется из функции: bash читает её целиком до запуска,
# поэтому обновление этого файла во время deploy ему не мешает.
main() {
    CMD="$1"
    case "$CMD" in
      deploy)
        FORCE=0
        [ "${2:-}" = "--force" ] && FORCE=1
        command -v git >/dev/null \
            || { echo "[!] git не установлен: sudo apt install -y git"; exit 1; }

        FIRST=0
        if [ ! -d .git ]; then
            echo "[*] Папка ещё не связана с репозиторием — подключаю $REPO_URL"
            git init -q -b "$BRANCH"
            git remote add origin "$REPO_URL"
            FIRST=1
        fi

        # права на запуск скрипта меняются на сервере — git не должен
        # считать это правкой
        git config core.fileMode false

        echo "[*] Получаю изменения из репозитория..."
        git fetch --quiet origin "$BRANCH"
        OLD="$(git rev-parse --short HEAD 2>/dev/null || true)"
        NEW="$(git rev-parse --short "origin/$BRANCH")"
        DIRTY="$(git status --porcelain --untracked-files=no 2>/dev/null || true)"

        # какая версия реально запущена: файлы могли обновить вручную
        # (git pull, первая привязка папки), не перезапуская сборщик
        RUNNING="$(cat .git/netdiag-deployed 2>/dev/null || true)"

        if [ "$FIRST" = 0 ] && [ "$OLD" = "$NEW" ] && [ -z "$DIRTY" ] \
                && [ "$RUNNING" = "$NEW" ]; then
            echo "[*] Уже установлена последняя версия: $(version)"
            echo "[*] Перезапуск не нужен. Чтобы перезапустить: netdiag restart"
            exit 0
        fi

        if [ "$FIRST" = 0 ] && [ -n "$DIRTY" ] && [ "$FORCE" = 0 ]; then
            echo "[!] На сервере есть правки, которых нет в репозитории:"
            echo "$DIRTY"
            echo "[!] Ничего не изменено. Чтобы заменить их версией из репозитория:"
            echo "    netdiag deploy --force"
            exit 1
        fi

        # data/ в .gitignore и не отслеживается — накопленные данные не трогаются
        git reset --hard -q "origin/$BRANCH"
        chmod +x script/netdiag.sh
        # дальше работает уже новая версия этого скрипта
        exec bash "$SCRIPT_DIR/netdiag.sh" _deploy_finish "${OLD:-}" "$NEW"
        ;;

      _deploy_finish)
        OLD="$2"; NEW="$3"
        echo "[*] Проверяю файлы новой версии..."
        if ! check_files; then
            if [ -n "$OLD" ]; then
                git reset --hard -q "$OLD"
                chmod +x script/netdiag.sh
                echo "[!] Вернул прежнюю версию ($OLD). Сервис не перезапускался и работает как раньше."
            else
                echo "[!] Сервис не перезапускался."
            fi
            exit 1
        fi

        echo "[*] Пересобираю и перезапускаю..."
        docker compose up -d --build --force-recreate
        sleep 8
        STATE="$(docker inspect -f '{{.State.Status}} {{.RestartCount}}' netdiag 2>/dev/null || true)"
        if [ "$STATE" != "running 0" ]; then
            echo "[!] Контейнер не работает стабильно (состояние: ${STATE:-нет контейнера}). Последние строки:"
            docker compose logs --tail 20 || true
            [ -n "$OLD" ] && echo "[!] Вернуть прежнюю версию: git reset --hard $OLD && netdiag start"
            exit 1
        fi
        echo "$NEW" > .git/netdiag-deployed
        docker compose ps
        echo
        tail -n 6 data/netdiag.log 2>/dev/null || true
        echo
        echo "[*] Установлена версия: $(version)"
        [ -n "$OLD" ] && [ "$OLD" != "$NEW" ] && echo "[*] Была: $OLD"
        echo "[*] Данные в ./data сохранены."
        ;;

      start)
        echo "[*] Запуск NetDiag..."
        docker compose up -d --build
        sleep 3
        docker compose ps
        echo "[*] Пишет в ./data/netdiag-ГГГГ-ММ-ДД.jsonl"
        ;;

      stop)
        echo "[*] Строю отчёт и останавливаю..."
        docker compose exec -T netdiag python /app/netdiag.py report > /dev/null || true
        docker compose stop
        echo "[*] Отчёт готов: ./data/report.html, подробно — ./data/report-full.txt"
        ;;

      restart)
        # --force-recreate: иначе контейнер продолжит видеть прежний netdiag.py
        docker compose up -d --force-recreate
        ;;

      status)
        echo "Версия: $(version)"
        docker compose ps
        echo
        tail -n 10 data/netdiag.log 2>/dev/null || true
        ;;

      log)
        docker compose logs -f
        ;;

      raw)
        tail -n 10 "$(ls -t data/netdiag*.jsonl | head -1)"
        ;;

      report)
        echo "[*] Строю отчёт по накопленным данным..."
        shift
        docker compose exec -T netdiag python /app/netdiag.py report "$@"
        echo "[*] Для руководства: $PROJECT_DIR/data/report.html (открыть в браузере)"
        echo "[*] Подробно: $PROJECT_DIR/data/report-full.txt"
        ;;

      down)
        docker compose down
        ;;

      clean)
        docker compose down
        rm -rf data/
        ;;

      *)
        usage
        exit 1
        ;;
    esac
}

main "$@"
exit
