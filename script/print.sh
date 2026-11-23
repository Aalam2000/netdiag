#!/bin/sh
# Печать отчёта (запускается в контейнере netdiag-print командой netdiag print).
# $1 — язык страницы: az (по умолчанию) или ru.
set -e
L="${1:-az}"
URL="http://127.0.0.1:${NETDIAG_HTTP_PORT:-8090}/?lang=$L&print=1"
PDF="/data/print-$L.pdf"

echo "[*] Страница $URL → PDF"
rm -f "$PDF"
chromium --headless=new --no-sandbox --disable-gpu --disable-dev-shm-usage \
    --no-pdf-header-footer --print-to-pdf-no-header --hide-scrollbars \
    --virtual-time-budget=15000 --print-to-pdf="$PDF" "$URL" 2>/dev/null || true
[ -s "$PDF" ] || { echo "[!] PDF не получился"; exit 1; }
echo "[*] PDF готов: data/print-$L.pdf"

cupsd
i=0
until lpstat -r >/dev/null 2>&1; do
    i=$((i + 1)); [ "$i" -gt 20 ] && { echo "[!] CUPS не запустился"; exit 1; }
    sleep 1
done
echo "[*] Принтер $PRINTER_URI"
lpadmin -p epson -E -v "$PRINTER_URI" -m everywhere \
    || { echo "[!] Принтер не ответил (включён? ufw пускает на порт 631?)"; exit 1; }
# описание принтера (PPD) CUPS создаёт в фоне, ~10 с. Без него очередь
# «сырая» и принтер печатает PDF как текст — поэтому ждём, а не печатаем сразу
i=0
until grep -q '^\*cupsFilter2' /etc/cups/ppd/epson.ppd 2>/dev/null; do
    i=$((i + 1)); [ "$i" -gt 45 ] && { echo "[!] Принтер не ответил на запрос параметров (включён?)"; exit 1; }
    sleep 2
done
echo "[*] PDF: $(pdfinfo "$PDF" 2>/dev/null | sed -n 's/^Pages: *//p') стр."
lp -d epson -o page-ranges=1 -o media=iso_a4_210x297mm -o fit-to-page -o document-format=application/pdf "$PDF"

# контейнер удаляется после выхода — ждём, пока задание уйдёт на принтер
i=0
while [ -n "$(lpstat -o epson 2>/dev/null)" ]; do
    i=$((i + 1))
    if [ "$i" -gt 90 ]; then
        echo "[!] Задание не ушло на принтер за 3 минуты:"
        lpstat -p epson -l 2>/dev/null || true
        cancel -a epson 2>/dev/null || true
        exit 1
    fi
    sleep 2
done
echo "[*] Отправлено на принтер."
