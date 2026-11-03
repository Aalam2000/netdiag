# Автодополнение по Tab для команды netdiag.
# Установка (один раз):
#   sudo ln -s /opt/netdiag/script/netdiag-completion.bash /etc/bash_completion.d/netdiag
# Файл подключён ссылкой, поэтому netdiag deploy обновляет и его.

_netdiag() {
    local cur prev cmd dir
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    cmd="${COMP_WORDS[1]}"

    if [ "$COMP_CWORD" -eq 1 ]; then
        COMPREPLY=($(compgen -W "deploy start stop restart status log raw report down clean" -- "$cur"))
        return
    fi

    case "$cmd" in
      deploy)
        [ "$COMP_CWORD" -eq 2 ] && COMPREPLY=($(compgen -W "--force" -- "$cur"))
        ;;
      report)
        case "$prev" in
          --since|--until)
            # даты, за которые есть данные
            dir="$(dirname "$(readlink -f "$(command -v netdiag)")")/../data"
            COMPREPLY=($(compgen -W "$(ls "$dir" 2>/dev/null \
                | sed -n 's/^netdiag-\([0-9-]*\)\.jsonl$/\1/p')" -- "$cur"))
            ;;
          --days)
            COMPREPLY=($(compgen -W "1 7 14 30" -- "$cur"))
            ;;
          *)
            COMPREPLY=($(compgen -W "--since --until --days --all" -- "$cur"))
            ;;
        esac
        ;;
    esac
}
complete -F _netdiag netdiag
