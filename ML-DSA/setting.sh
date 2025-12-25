#!/usr/bin/env bash
# setting.sh — Enable benchmark optimization settings
# Turbo OFF, shallow C-states ON, deep C-states OFF, governor=performance
set -euo pipefail

log()  { echo "[*] $*"; }
warn() { echo "[!] $*" >&2; }
die()  { echo "[X] $*" >&2; exit 1; }
is_root() { [ "$(id -u)" -eq 0 ]; }

write_if_exists() {
    local val="$1"; shift
    for f in "$@"; do
        if [ -w "$f" ]; then
            echo "$val" > "$f" 2>/dev/null || true
        fi
    done
}

save_current_settings() {
    log "Backing up current settings..."
    local backup_file="/tmp/cpu_settings_backup.txt"

    # Backup current governor settings
    echo "# CPU Governor Backup" > "$backup_file"
    for p in /sys/devices/system/cpu/cpufreq/policy*; do
        [ -d "$p" ] || continue
        policy=$(basename "$p")
        governor=$(cat "$p/scaling_governor" 2>/dev/null || echo "unknown")
        echo "GOVERNOR_$policy=$governor" >> "$backup_file"
    done

    # Backup Turbo settings
    echo "# Turbo Settings" >> "$backup_file"
    if [ -r /sys/devices/system/cpu/intel_pstate/no_turbo ]; then
        echo "INTEL_NO_TURBO=$(cat /sys/devices/system/cpu/intel_pstate/no_turbo)" >> "$backup_file"
    elif [ -r /sys/devices/system/cpu/cpufreq/boost ]; then
        echo "CPUFREQ_BOOST=$(cat /sys/devices/system/cpu/cpufreq/boost)" >> "$backup_file"
    fi

    # Backup C-state settings
    echo "# C-state Settings" >> "$backup_file"
    for s in /sys/devices/system/cpu/cpu0/cpuidle/state*/disable; do
        [ -r "$s" ] || continue
        state_name=$(basename "$(dirname "$s")")
        state_val=$(cat "$s" 2>/dev/null || echo "0")
        echo "CSTATE_$state_name=$state_val" >> "$backup_file"
    done

    if [ -r /sys/module/intel_idle/parameters/max_cstate ]; then
        echo "INTEL_MAX_CSTATE=$(cat /sys/module/intel_idle/parameters/max_cstate)" >> "$backup_file"
    fi

    log "Settings backed up to $backup_file"
}

set_governor_performance() {
    log "Setting all CPU policies to performance governor..."
    if command -v cpupower >/dev/null 2>&1; then
        cpupower -c all frequency-set -g performance >/dev/null 2>&1 || true
    fi
    for p in /sys/devices/system/cpu/cpufreq/policy*; do
        [ -d "$p" ] || continue
        write_if_exists performance "$p/scaling_governor"
    done
}

set_turbo_on() {
    log "Enabling Turbo Boost..."
        echo 0 > /sys/devices/system/cpu/intel_pstate/no_turbo || true
        log "  Intel Turbo enabled"
}
set_turbo_off() {
    log "Disabling Turbo Boost..."
        echo 1 > /sys/devices/system/cpu/intel_pstate/no_turbo || true
        log "  Intel Turbo disabled"
}



enable_shallow_cstates_only() {
    log "Optimizing C-states: enabling shallow states, disabling deep states..."
    local shallow_enabled=0
    local deep_disabled=0

    # Enable C0, C1, C2 (shallow states)
    for s in /sys/devices/system/cpu/cpu*/cpuidle/state[0-2]/disable; do
        if [ -w "$s" ]; then
            echo 0 > "$s" 2>/dev/null || true  # 0 = enabled
            shallow_enabled=$((shallow_enabled+1))
        fi
    done

    # Disable C3 and deeper states
    for s in /sys/devices/system/cpu/cpu*/cpuidle/state[3-9]/disable; do
        if [ -w "$s" ]; then
            echo 1 > "$s" 2>/dev/null || true  # 1 = disabled
            deep_disabled=$((deep_disabled+1))
        fi
    done

    log "  Shallow C-states enabled: $shallow_enabled"
    log "  Deep C-states disabled: $deep_disabled"

    # Limit intel_idle to C2 maximum
    if [ -w /sys/module/intel_idle/parameters/max_cstate ]; then
        echo 2 > /sys/module/intel_idle/parameters/max_cstate 2>/dev/null || true
        log "  intel_idle.max_cstate=2 (C0-C2 only)"
    fi
}

show_current_settings() {
    echo "==== Current Benchmark Settings ===="

    # Governor status
    echo "📊 CPU Governor:"
    for p in /sys/devices/system/cpu/cpufreq/policy*; do
        [ -d "$p" ] || continue
        policy=$(basename "$p")
        governor=$(cat "$p/scaling_governor" 2>/dev/null || echo "N/A")
        cur_freq=$(cat "$p/scaling_cur_freq" 2>/dev/null || echo "N/A")
        echo "  [$policy] $governor (current: ${cur_freq}kHz)"
    done

    # Turbo status
    echo "🚀 Turbo Status:"
    if [ -r /sys/devices/system/cpu/intel_pstate/no_turbo ]; then
        turbo_off=$(cat /sys/devices/system/cpu/intel_pstate/no_turbo)
        [ "$turbo_off" = "0" ] && echo "  Intel Turbo: enabled ✅" || echo "  Intel Turbo: disabled ❌"
    elif [ -r /sys/devices/system/cpu/cpufreq/boost ]; then
        boost=$(cat /sys/devices/system/cpu/cpufreq/boost)
        [ "$boost" = "1" ] && echo "  CPUFREQ Boost: enabled ✅" || echo "  CPUFREQ Boost: disabled ❌"
    fi

    # C-state status
    echo "😴 C-state Settings:"
    echo "  Shallow states (C0-C2): enabled ✅"
    echo "  Deep states (C3+): disabled ❌"

    if [ -r /sys/module/intel_idle/parameters/max_cstate ]; then
        max_cstate=$(cat /sys/module/intel_idle/parameters/max_cstate)
        echo "  Maximum C-state: $max_cstate"
    fi

    echo "================================"
    echo "💡 Benchmark Tips:"
    echo "  Check P-cores: lscpu -e=CPU,MAXMHZ | sort -k2,2nr | head"
    echo "  Pin to specific core: taskset -c <core> ./benchmark"
    echo "  Clear cache: echo 3 > /proc/sys/vm/drop_caches"
    echo "  Restore settings: ./unset.sh"
}

main() {
    is_root || die "❌ Root privileges required: sudo ./setting.sh"
    [ -d /sys/devices/system/cpu ] || die "❌ Cannot find sysfs CPU interface."

    echo "🎯 Starting benchmark optimization setup..."

    save_current_settings
    set_governor_performance
    set_turbo_off
    enable_shallow_cstates_only
    show_current_settings

    log "✅ Benchmark optimization setup completed!"
    warn "⚠️  Power consumption may increase. Restore with ./unset.sh after benchmarking."
}

main "$@"
