#!/system/bin/sh
# kpmctl.sh — SKRoot KPM management (zero-dependency shell version)
# Push to device: adb push kpmctl.sh /data/local/tmp/kpmctl
# Usage:
#   kpmctl load   /path/to/module.kpm
#   kpmctl unload ModuleName
#   kpmctl list
#   kpmctl status

CMD="$1"
ARG="$2"

case "$CMD" in
load)
    if [ -z "$ARG" ]; then
        echo "Usage: $0 load <file.kpm>"
        exit 1
    fi
    if [ ! -f "$ARG" ]; then
        echo "Error: file not found: $ARG"
        exit 1
    fi
    # Resolve to absolute path
    case "$ARG" in
        /*) KPATH="$ARG" ;;
        *)  KPATH="$(cd "$(dirname "$ARG")" && pwd)/$(basename "$ARG")" ;;
    esac
    echo "Loading $KPATH ..."
    # Trigger kernel hook via execve — will fail (ENOENT) but side effect happens
    dmesg -c >/dev/null 2>&1
    busybox env -i "@LD:$KPATH" 2>/dev/null
    sleep 0.1
    echo "--- kernel log ---"
    dmesg -c 2>/dev/null | grep 'SKRoot KPM' || echo "(no output — check dmesg manually)"
    ;;

unload)
    if [ -z "$ARG" ]; then
        echo "Usage: $0 unload <module_name>"
        exit 1
    fi
    echo "Unloading $ARG ..."
    dmesg -c >/dev/null 2>&1
    busybox env -i "@UL:$ARG" 2>/dev/null
    sleep 0.1
    dmesg -c 2>/dev/null | grep 'SKRoot KPM'
    ;;

list)
    echo "Listing modules..."
    dmesg -c >/dev/null 2>&1
    busybox env -i "@LS" 2>/dev/null
    sleep 0.1
    dmesg -c 2>/dev/null | grep 'SKRoot KPM'
    ;;

status)
    echo "Probing KPM runtime..."
    dmesg -c >/dev/null 2>&1
    busybox env -i "@LS" 2>/dev/null
    sleep 0.1
    if dmesg -c 2>/dev/null | grep -q 'SKRoot KPM'; then
        echo "KPM runtime: AVAILABLE"
    else
        echo "KPM runtime: NOT DETECTED (check dmesg for details)"
    fi
    ;;

*)
    echo "kpmctl — SKRoot KPM Module Manager"
    echo ""
    echo "Usage:"
    echo "  $0 load   <file>     Load .kpm file"
    echo "  $0 unload <name>     Unload module"
    echo "  $0 list              List modules"
    echo "  $0 status            Check runtime"
    echo ""
    echo "Examples:"
    echo "  $0 load /data/local/tmp/tomato.kpm"
    echo "  $0 unload Module"
    echo "  $0 list"
    exit 1
    ;;
esac
