#!/system/bin/sh
# SKRoot KPM management helper
#
# Features:
# - No busybox dependency
# - Android toybox /system/bin/sh compatible
# - LF line endings, safe for direct adb push
#
# Typical usage:
#   sh /data/local/tmp/kpmctl status
#   sh /data/local/tmp/kpmctl load /data/local/tmp/tomato.kpm
#   sh /data/local/tmp/kpmctl unload tomato
#   sh /data/local/tmp/kpmctl list
#
# If the current shell is not root, run it through su:
#   /path/to/su -c 'sh /data/local/tmp/kpmctl status'

CMD="$1"
ARG="$2"

clear_dmesg() {
    dmesg -C >/dev/null 2>&1 || dmesg -c >/dev/null 2>&1
}

read_kpm_log() {
    if command -v grep >/dev/null 2>&1; then
        dmesg -c 2>/dev/null | grep 'SKRoot KPM'
    else
        dmesg -c 2>/dev/null
    fi
}

run_trigger() {
    env -i "$1" 2>/dev/null
}

need_root_hint() {
    uid="$(id -u 2>/dev/null)"
    if [ "x$uid" != "x0" ]; then
        echo "[!] Current shell is not root. If KPM does not respond, run via su."
    fi
}

load_cmd() {
    if [ -z "$ARG" ]; then
        echo "Usage: $0 load <file.kpm>"
        exit 1
    fi

    if [ ! -f "$ARG" ]; then
        echo "Error: file not found: $ARG"
        exit 1
    fi

    case "$ARG" in
        /*) KPATH="$ARG" ;;
        *)  KPATH="$(cd "$(dirname "$ARG")" 2>/dev/null && pwd)/$(basename "$ARG")" ;;
    esac

    echo "Loading $KPATH ..."
    clear_dmesg
    run_trigger "@LD:$KPATH"
    sleep 1
    echo "--- kernel log ---"
    read_kpm_log || echo "(no output)"
}

unload_cmd() {
    if [ -z "$ARG" ]; then
        echo "Usage: $0 unload <module_name>"
        exit 1
    fi

    echo "Unloading $ARG ..."
    clear_dmesg
    run_trigger "@UL:$ARG"
    sleep 1
    echo "--- kernel log ---"
    read_kpm_log || echo "(no output)"
}

list_cmd() {
    echo "Listing modules ..."
    clear_dmesg
    run_trigger "@LS"
    sleep 1
    echo "--- kernel log ---"
    OUT="$(read_kpm_log)"
    if [ -n "$OUT" ]; then
        echo "$OUT"
    else
        echo "(no output; some builds do not expose module list logs)"
    fi
}

status_cmd() {
    echo "Probing KPM runtime ..."
    clear_dmesg
    run_trigger "@LS"
    sleep 1
    OUT="$(dmesg -c 2>/dev/null)"
    if echo "$OUT" | grep -q 'SKRoot KPM'; then
        echo "KPM runtime: AVAILABLE"
    else
        echo "KPM runtime: UNKNOWN"
        echo "Reason: this build does not print @LS probe logs."
        echo "Tip: use 'load <module.kpm>' to verify actual availability."
    fi
}

usage() {
    cat <<'EOF'
SKRoot KPM Module Manager

Usage:
  kpmctl load <file.kpm>     Load module from file
  kpmctl unload <name>       Unload module
  kpmctl list                List modules
  kpmctl status              Probe runtime

Examples:
  sh /data/local/tmp/kpmctl status
  sh /data/local/tmp/kpmctl load /data/local/tmp/tomato.kpm
  /path/to/su -c 'sh /data/local/tmp/kpmctl load /data/local/tmp/tomato.kpm'
EOF
}

need_root_hint

case "$CMD" in
    load)
        load_cmd
        ;;
    unload)
        unload_cmd
        ;;
    list)
        list_cmd
        ;;
    status)
        status_cmd
        ;;
    *)
        usage
        exit 1
        ;;
esac
