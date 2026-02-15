#!/usr/bin/env bash
#=============================================================================
# GSocket / gs-netcat Implant Detection Toolkit
# Target: gsocket.io deploy.sh variants (THC gsocket framework)
# Purpose: Blue-team threat hunting & incident response
# Usage: Run as root for full visibility
#=============================================================================

set -euo pipefail

CY="\033[1;33m"; CG="\033[1;32m"; CR="\033[1;31m"; CB="\033[1;34m"
CM="\033[1;35m"; CC="\033[1;36m"; CF="\033[2m"; CN="\033[0m"; CW="\033[1;37m"

FINDINGS=0
CRITICAL=0

header()  { echo -e "\n${CB}━━━ $1 ━━━${CN}"; }
finding() { ((FINDINGS++)); echo -e "  ${CR}[!] FINDING:${CN} $*"; }
critical(){ ((CRITICAL++)); ((FINDINGS++)); echo -e "  ${CR}[!!!] CRITICAL:${CN} $*"; }
info()    { echo -e "  ${CF}[i]${CN} $*"; }
clean()   { echo -e "  ${CG}[✓]${CN} $*"; }

echo -e "${CW}╔══════════════════════════════════════════════════════════════╗${CN}"
echo -e "${CW}║   GSocket Implant Detection Toolkit  — Blue Team Edition    ║${CN}"
echo -e "${CW}╠══════════════════════════════════════════════════════════════╣${CN}"
echo -e "${CW}║  Detects: gs-netcat, gsocket deploy.sh, THC backdoors      ║${CN}"
echo -e "${CW}║  Covers: Process masq, PTS anomaly, memfd, persistence     ║${CN}"
echo -e "${CW}╚══════════════════════════════════════════════════════════════╝${CN}"
echo -e "${CF}  Scan started: $(date -u '+%Y-%m-%d %H:%M:%S UTC')${CN}"
echo -e "${CF}  Running as: $(whoami) (UID $UID)${CN}"
[[ $UID -ne 0 ]] && echo -e "  ${CY}[WARN] Running without root — some checks will be limited${CN}"

#=============================================================================
# 1. FAKE KERNEL THREAD DETECTION
#    gsocket masquerades as kernel threads: [kthreadd], [kworker], [ksmd], etc.
#    Real kernel threads have PID parent = 2 (kthreadd) and NO /proc/PID/exe
#=============================================================================
header "1. FAKE KERNEL THREAD DETECTION (argv[0] masquerading)"

# Known gsocket proc_name_arr values from deploy.sh
GS_PROC_NAMES=("sshd:" "[kthreadd]" "[kstrp]" "[watchdogd]" "[ksmd]" "[kswapd0]" \
    "[card0-crtc8]" "[mm_percpu_wq]" "[rcu_preempt]" "[kworker]" "[raid5wq]" \
    "[slub_flushwq]" "[netns]" "[kaluad]")

found_fake=0
while IFS= read -r pid; do
    [[ ! -d "/proc/$pid" ]] && continue
    comm=$(cat "/proc/$pid/comm" 2>/dev/null) || continue
    cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null) || continue
    ppid=$(awk '{print $4}' "/proc/$pid/stat" 2>/dev/null) || continue

    # Heuristic: looks like a kernel thread (brackets) but has a real exe link
    if [[ "$cmdline" =~ ^\[.*\]$ ]] || [[ "$comm" =~ ^\[.*\] ]]; then
        exe_link=$(readlink "/proc/$pid/exe" 2>/dev/null) || true
        if [[ -n "$exe_link" ]] && [[ "$exe_link" != *"(deleted)"* || -n "$exe_link" ]]; then
            # Real kernel threads have NO exe symlink resolvable to a real binary
            # If we CAN resolve /proc/PID/exe, it's a userspace process faking a kernel name
            if [[ "$ppid" -ne 2 ]] && [[ "$pid" -ne 2 ]]; then
                critical "PID $pid masquerading as kernel thread: cmdline='${cmdline}' exe='${exe_link}' ppid=$ppid"
                found_fake=1
            fi
        fi
    fi

    # Also check for exact gsocket proc names without brackets
    if [[ "$cmdline" == "sshd:" ]] || [[ "$comm" == "sshd:" ]]; then
        # Real sshd shows full path or "sshd: user@pts/N"
        exe_link=$(readlink "/proc/$pid/exe" 2>/dev/null) || true
        if [[ -n "$exe_link" ]] && [[ "$exe_link" != *"/sshd"* ]]; then
            critical "PID $pid faking sshd but exe='${exe_link}'"
            found_fake=1
        fi
    fi
done < <(ls -1 /proc/ 2>/dev/null | grep -E '^[0-9]+$')

[[ $found_fake -eq 0 ]] && clean "No fake kernel threads detected"

#=============================================================================
# 2. ORPHANED / ANOMALOUS PTS DETECTION
#    gs-netcat allocates a PTY via forkpty()/openpty() for interactive shells.
#    These PTS entries are visible but may not match any utmp/wtmp record.
#=============================================================================
header "2. ORPHANED PTS DETECTION (utmp vs /dev/pts mismatch)"

# Get PTS entries known to utmp (logged sessions)
declare -A utmp_pts
while IFS= read -r line; do
    pts_num=$(echo "$line" | awk '{print $2}' | sed 's|pts/||')
    [[ -n "$pts_num" ]] && utmp_pts["$pts_num"]=1
done < <(who 2>/dev/null)

# Get PTS entries actually open in /dev/pts
pts_anomalies=0
for pts_file in /dev/pts/[0-9]*; do
    [[ ! -e "$pts_file" ]] && continue
    pts_num=$(basename "$pts_file")
    [[ "$pts_num" == "ptmx" ]] && continue

    if [[ -z "${utmp_pts[$pts_num]:-}" ]]; then
        # This PTS has no utmp record — find who owns it
        owner_pids=""
        for fd_dir in /proc/[0-9]*/fd; do
            pid=$(echo "$fd_dir" | cut -d/ -f3)
            if readlink "$fd_dir"/* 2>/dev/null | grep -q "/dev/pts/$pts_num$"; then
                pname=$(cat "/proc/$pid/comm" 2>/dev/null || echo "???")
                owner_pids+=" PID:${pid}(${pname})"
            fi
        done 2>/dev/null
        if [[ -n "$owner_pids" ]]; then
            finding "PTS/$pts_num has NO utmp entry — owners:${owner_pids}"
            ((pts_anomalies++))
        fi
    fi
done

[[ $pts_anomalies -eq 0 ]] && clean "All active PTS entries have corresponding utmp records"

# Additional: check for PTS with no controlling terminal in session leaders
info "Checking for PTS consumers with suspicious process lineage..."
for pts_file in /dev/pts/[0-9]*; do
    [[ ! -e "$pts_file" ]] && continue
    pts_num=$(basename "$pts_file")
    while IFS= read -r pid; do
        [[ ! -d "/proc/$pid" ]] && continue
        for fd in /proc/$pid/fd/*; do
            target=$(readlink "$fd" 2>/dev/null) || continue
            if [[ "$target" == "/dev/pts/$pts_num" ]]; then
                exe=$(readlink "/proc/$pid/exe" 2>/dev/null) || continue
                # Flag if the process holding this PTS looks like a kernel thread name
                comm=$(cat "/proc/$pid/comm" 2>/dev/null) || continue
                if [[ "$comm" =~ ^\[ ]] && [[ -n "$exe" ]]; then
                    critical "PTS/$pts_num held by fake kernel thread: PID $pid comm='$comm' exe='$exe'"
                fi
            fi
        done
    done < <(ls -1 /proc/ 2>/dev/null | grep -E '^[0-9]+$')
done

#=============================================================================
# 3. MEMFD / FILELESS EXECUTION DETECTION
#    gsocket uses memfd_create() for fileless execution (GS_MEMEXEC=1).
#    The binary runs entirely from an anonymous memory-backed fd.
#=============================================================================
header "3. MEMFD / FILELESS EXECUTION DETECTION"

memfd_found=0
while IFS= read -r pid; do
    [[ ! -d "/proc/$pid/fd" ]] && continue
    for fd in /proc/$pid/fd/*; do
        target=$(readlink "$fd" 2>/dev/null) || continue
        if [[ "$target" == *"memfd:"* ]] || [[ "$target" == "/memfd:"* ]]; then
            comm=$(cat "/proc/$pid/comm" 2>/dev/null || echo "???")
            cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null || echo "???")
            critical "PID $pid has memfd execution: fd=$(basename $fd) -> '${target}' comm='${comm}' cmdline='${cmdline}'"
            memfd_found=1
        fi
    done
done < <(ls -1 /proc/ 2>/dev/null | grep -E '^[0-9]+$')

# Also check /proc/PID/exe pointing to deleted or memfd
while IFS= read -r pid; do
    exe=$(readlink "/proc/$pid/exe" 2>/dev/null) || continue
    if [[ "$exe" == *"(deleted)"* ]] && [[ "$exe" != *"/tmp/"* ]]; then
        comm=$(cat "/proc/$pid/comm" 2>/dev/null || echo "???")
        cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null || echo "???")
        finding "PID $pid running deleted binary: exe='${exe}' comm='${comm}'"
    fi
    if [[ "$exe" == *"memfd:"* ]]; then
        critical "PID $pid exe is memfd: '${exe}'"
        memfd_found=1
    fi
done < <(ls -1 /proc/ 2>/dev/null | grep -E '^[0-9]+$')

[[ $memfd_found -eq 0 ]] && clean "No memfd-based fileless execution detected"

#=============================================================================
# 4. KNOWN GSOCKET BINARY & SERVICE NAME DETECTION
#    Scan for the randomized hidden names used by the deploy script.
#=============================================================================
header "4. KNOWN GSOCKET ARTIFACT DETECTION (binary/service/config names)"

# Binary names from deploy.sh bin_hidden_name_arr
GS_BIN_NAMES=("udevd-sync" "netd" "firewallctl" "bootcfg" "authd" \
    "core" "defunct" "gs-dbus" "gs-db" "gs-netcat" "gs_funcs" "gsocket")

# Service names from deploy.sh service_hidden_name_arr
GS_SVC_NAMES=("systemd-hwdb-update" "network-core" "auth-policykit" \
    "ssh-agent-proxy" "journald-forwarder" "defunct" "gs-dbus" "gs-db")

# Config dir names from deploy.sh config_dir_name_arr
GS_CONFIG_DIRS=("tmp" "etc" "lib" "cache" "bin" "share" "htop" "dbus")

info "Scanning for hidden binaries in common paths..."
for name in "${GS_BIN_NAMES[@]}"; do
    for dir in /usr/local/sbin /usr/local/bin /usr/sbin /usr/bin /sbin /bin /tmp; do
        if [[ -f "$dir/$name" ]]; then
            # Exclude legitimate binaries by checking for gsocket strings
            if strings "$dir/$name" 2>/dev/null | grep -qiE 'gsocket|gs-netcat|GS_SECRET|GSOCKET'; then
                critical "GSocket binary found: $dir/$name"
            elif [[ "$name" == "gs-netcat" ]] || [[ "$name" == "gsocket" ]]; then
                finding "Potential GSocket binary: $dir/$name"
            fi
        fi
    done
done

info "Scanning for hidden systemd services..."
for name in "${GS_SVC_NAMES[@]}"; do
    for sdir in /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system \
                ~/.config/systemd/user; do
        sf="${sdir}/${name}.service"
        [[ -f "$sf" ]] && {
            # Check service content for gsocket indicators
            if grep -qiE 'gs-netcat|gsocket|GS_SECRET|GSOCKET|memexec' "$sf" 2>/dev/null; then
                critical "GSocket systemd service: $sf"
            elif grep -qE 'Type=oneshot.*Remain|ExecStart=.*(udevd-sync|netd|firewallctl|bootcfg|authd)' "$sf" 2>/dev/null; then
                finding "Suspicious service matching gsocket pattern: $sf"
            fi
        }
    done
done

info "Scanning for hidden config directories in user homes..."
while IFS= read -r homedir; do
    [[ ! -d "$homedir" ]] && continue
    for cname in "${GS_CONFIG_DIRS[@]}"; do
        suspect_dir="$homedir/.config/$cname"
        [[ ! -d "$suspect_dir" ]] && continue
        # gsocket stores a config file with the secret
        if find "$suspect_dir" -maxdepth 2 -type f 2>/dev/null | \
            xargs grep -lE 'GS_SECRET|gs-netcat|GSOCKET' 2>/dev/null | head -1 | grep -q .; then
            critical "GSocket config directory: $suspect_dir"
        fi
    done
done < <(awk -F: '$3>=1000||$3==0{print $6}' /etc/passwd 2>/dev/null)

#=============================================================================
# 5. SYSTEMD SERVICE INFECTION DETECTION
#    gsocket can infect agetty (getty@tty1), serial-getty, and cron services
#    by replacing the ExecStart binary with a trojanized version.
#=============================================================================
header "5. SYSTEMD SERVICE INFECTION DETECTION"

# Check agetty binary integrity
for svc in "getty@tty1" "serial-getty@ttyS0" "cron" "cron.service"; do
    sf_path=""
    sf_path=$(systemctl show "$svc" --property=FragmentPath 2>/dev/null | cut -d= -f2) || true
    [[ -z "$sf_path" ]] && continue
    [[ ! -f "$sf_path" ]] && continue

    exec_bin=$(systemctl show "$svc" --property=ExecStart 2>/dev/null | \
        grep -oP 'path=\K[^ ;]+' | head -1) || true
    [[ -z "$exec_bin" ]] && continue
    [[ ! -f "$exec_bin" ]] && continue

    # Check if the binary has been tampered with
    if strings "$exec_bin" 2>/dev/null | grep -qiE 'gsocket|gs-netcat|GS_SECRET|GSOCKET'; then
        critical "INFECTED SERVICE BINARY: $svc -> $exec_bin contains gsocket strings"
    fi

    # Check binary hash against package manager
    if command -v dpkg-query &>/dev/null; then
        pkg=$(dpkg-query -S "$exec_bin" 2>/dev/null | cut -d: -f1) || true
        if [[ -n "$pkg" ]]; then
            expected_hash=$(dpkg-query -L "$pkg" 2>/dev/null | xargs md5sum 2>/dev/null | grep "$exec_bin" | awk '{print $1}') || true
            actual_hash=$(md5sum "$exec_bin" 2>/dev/null | awk '{print $1}') || true
            if [[ -n "$expected_hash" ]] && [[ "$expected_hash" != "$actual_hash" ]]; then
                finding "Binary mismatch for $svc: $exec_bin (expected: $expected_hash, got: $actual_hash)"
            fi
        fi
    fi
done

# Generic: find all oneshot services that RemainAfterExit and have suspicious ExecStart
info "Scanning for suspicious oneshot services (gsocket persistence pattern)..."
for sf in /etc/systemd/system/*.service /lib/systemd/system/*.service; do
    [[ ! -f "$sf" ]] && continue
    if grep -q "Type=oneshot" "$sf" 2>/dev/null && grep -q "RemainAfterExit" "$sf" 2>/dev/null; then
        exec_line=$(grep "ExecStart=" "$sf" 2>/dev/null | head -1)
        # Check if ExecStart points to a suspicious binary
        for bname in "${GS_BIN_NAMES[@]}"; do
            if echo "$exec_line" | grep -q "$bname"; then
                finding "Suspicious oneshot service $sf: $exec_line"
            fi
        done
    fi
done

#=============================================================================
# 6. SHELL RC / CRONTAB PERSISTENCE DETECTION
#    gsocket injects into .bashrc, .bash_profile, .profile, .zshrc
#    and/or crontab entries for persistence.
#=============================================================================
header "6. SHELL RC & CRONTAB PERSISTENCE DETECTION"

info "Scanning shell RC files for backdoor injections..."
while IFS= read -r homedir; do
    [[ ! -d "$homedir" ]] && continue
    user=$(stat -c '%U' "$homedir" 2>/dev/null || echo "unknown")
    for rcfile in .bashrc .bash_profile .bash_login .profile .zshrc; do
        rcpath="$homedir/$rcfile"
        [[ ! -f "$rcpath" ]] && continue
        # Look for gsocket indicators: hidden binary names, exec -a, encoded payloads
        if grep -nE '(udevd-sync|netd|firewallctl|bootcfg|authd|gs-netcat|gsocket|GS_SECRET|exec -a "\[|GSOCKET|gs_funcs)' "$rcpath" 2>/dev/null; then
            critical "GSocket persistence in ${rcpath} (user: ${user})"
        fi
        # Look for obfuscated eval+base64 one-liners (common deploy pattern)
        if grep -nE '(eval.*\$\(.*base64|openssl.*base64.*-d.*eval|perl.*-e.*eval)' "$rcpath" 2>/dev/null; then
            finding "Obfuscated eval+base64 payload in ${rcpath} (user: ${user})"
        fi
    done
done < <(awk -F: '{print $6}' /etc/passwd 2>/dev/null | sort -u)

info "Scanning crontabs..."
# System crontabs
for ctab in /var/spool/cron/crontabs/* /var/spool/cron/* /etc/cron.d/* /etc/crontab; do
    [[ ! -f "$ctab" ]] && continue
    if grep -nE '(udevd-sync|netd|firewallctl|bootcfg|authd|gs-netcat|gsocket|GS_SECRET|exec -a)' "$ctab" 2>/dev/null; then
        critical "GSocket crontab persistence: $ctab"
    fi
    if grep -nE '(eval.*base64|openssl.*base64.*\|.*bash|curl.*fsSL.*gsocket)' "$ctab" 2>/dev/null; then
        finding "Suspicious encoded/download crontab entry: $ctab"
    fi
done

#=============================================================================
# 7. NETWORK INDICATORS — GSOCKET RELAY CONNECTIONS
#    gs-netcat connects to gsocket relay infrastructure (gsocket.io / gs-relay)
#    Default port 443 (TLS) to relay servers, or custom GS_HOST/GS_PORT.
#=============================================================================
header "7. NETWORK CONNECTION ANALYSIS"

info "Checking for connections to known gsocket relay infrastructure..."
GS_KNOWN_IPS=("87.106.101.131")  # GS_HOST_MASTER_IP from deploy.sh
GS_KNOWN_DOMAINS=("gsocket.io" "gs.thc.org")

if command -v ss &>/dev/null; then
    for ip in "${GS_KNOWN_IPS[@]}"; do
        matches=$(ss -tnp 2>/dev/null | grep "$ip" || true)
        [[ -n "$matches" ]] && critical "Active connection to known gsocket relay IP $ip:\n$matches"
    done

    # Detect processes with ESTABLISHED connections on port 443 that look suspicious
    info "Checking for suspicious TLS connections from masqueraded processes..."
    while IFS= read -r line; do
        pid=$(echo "$line" | grep -oP 'pid=\K[0-9]+' || true)
        [[ -z "$pid" ]] && continue
        comm=$(cat "/proc/$pid/comm" 2>/dev/null || echo "???")
        # Flag if a "kernel thread" name has network connections
        if [[ "$comm" =~ ^\[ ]] || echo "$comm" | grep -qE '^(udevd-sync|netd|firewallctl|bootcfg|authd)$'; then
            critical "Network connection from suspicious process: PID $pid ($comm): $line"
        fi
    done < <(ss -tnp state established 2>/dev/null | grep -v "^State" || true)
fi

# DNS resolution check (if host/dig available)
if command -v host &>/dev/null; then
    for domain in "${GS_KNOWN_DOMAINS[@]}"; do
        if host "$domain" &>/dev/null; then
            resolved=$(host "$domain" 2>/dev/null | head -3)
            info "gsocket domain resolves: $resolved"
        fi
    done
fi

#=============================================================================
# 8. /proc FILESYSTEM DEEP ANALYSIS
#    Cross-reference exe, cmdline, comm, maps, environ for inconsistencies.
#    gsocket processes will show mismatches between these fields.
#=============================================================================
header "8. /proc DEEP ANOMALY ANALYSIS"

info "Cross-referencing /proc fields for process identity mismatches..."
proc_anomalies=0
while IFS= read -r pid; do
    [[ ! -d "/proc/$pid" ]] && continue
    [[ ! -r "/proc/$pid/comm" ]] && continue

    comm=$(cat "/proc/$pid/comm" 2>/dev/null) || continue
    cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null) || continue
    exe=$(readlink "/proc/$pid/exe" 2>/dev/null) || continue
    ppid=$(awk '{print $4}' "/proc/$pid/stat" 2>/dev/null) || continue

    # Skip actual kernel threads (ppid=2, no exe)
    [[ "$ppid" -eq 2 ]] && continue
    [[ "$pid" -eq 2 ]] && continue
    [[ -z "$exe" ]] && continue

    exe_basename=$(basename "$exe" 2>/dev/null | sed 's/ (deleted)//')

    # Heuristic 1: comm doesn't match exe basename at all
    # (gsocket rewrites argv[0] but exe still points to real binary)
    if [[ "$comm" != "$exe_basename" ]] && [[ "${comm}" =~ ^\[.*\]$ ]]; then
        finding "PID $pid: comm='${comm}' but exe='${exe}' (argv[0] rewritten)"
        ((proc_anomalies++))
    fi

    # Heuristic 2: Check /proc/PID/environ for GS_ environment variables
    if [[ -r "/proc/$pid/environ" ]]; then
        gs_env=$(tr '\0' '\n' < "/proc/$pid/environ" 2>/dev/null | grep -E '^GS_' || true)
        if [[ -n "$gs_env" ]]; then
            critical "PID $pid has GSocket environment variables: $(echo $gs_env | tr '\n' ' ')"
            ((proc_anomalies++))
        fi
    fi

    # Heuristic 3: Check /proc/PID/maps for memfd references
    if [[ -r "/proc/$pid/maps" ]]; then
        memfd_maps=$(grep -c "memfd:" "/proc/$pid/maps" 2>/dev/null || echo "0")
        if [[ "$memfd_maps" -gt 0 ]]; then
            finding "PID $pid has $memfd_maps memfd-backed memory regions (possible fileless exec)"
            ((proc_anomalies++))
        fi
    fi
done < <(ls -1 /proc/ 2>/dev/null | grep -E '^[0-9]+$')

[[ $proc_anomalies -eq 0 ]] && clean "No /proc anomalies detected"

#=============================================================================
# 9. UTMP / WTMP / BTMP INTEGRITY CHECK
#    gsocket doesn't clean utmp/wtmp by default, but the PTS it creates
#    won't have a proper login record. Compare active PTY sessions against
#    login databases.
#=============================================================================
header "9. LOGIN DATABASE INTEGRITY (utmp/wtmp analysis)"

if command -v utmpdump &>/dev/null; then
    info "Dumping active utmp sessions..."
    active_count=$(who 2>/dev/null | wc -l)
    pts_count=$(ls /dev/pts/[0-9]* 2>/dev/null | wc -l || echo "0")
    info "Active utmp sessions: $active_count, Active PTS devices: $pts_count"

    if [[ "$pts_count" -gt "$active_count" ]]; then
        finding "PTS count ($pts_count) exceeds utmp session count ($active_count) — possible hidden sessions"
    fi

    # Check wtmp for any gsocket-related hostnames or suspicious entries
    if [[ -f /var/log/wtmp ]]; then
        info "Checking wtmp for anomalous entries..."
        suspicious_wtmp=$(utmpdump /var/log/wtmp 2>/dev/null | \
            grep -iE '(gsocket|gs-netcat|0\.0\.0\.0.*pts/)' || true)
        [[ -n "$suspicious_wtmp" ]] && finding "Suspicious wtmp entries:\n$suspicious_wtmp"
    fi
else
    info "utmpdump not available — install for deeper analysis"
fi

# loginuid analysis: processes spawned via gs-netcat won't have a valid loginuid
info "Checking for processes with unset loginuid holding PTY descriptors..."
while IFS= read -r pid; do
    [[ ! -f "/proc/$pid/loginuid" ]] && continue
    loginuid=$(cat "/proc/$pid/loginuid" 2>/dev/null) || continue
    # 4294967295 means "not set" — process wasn't spawned via PAM/login
    [[ "$loginuid" != "4294967295" ]] && continue

    # Check if this process holds a PTS fd
    for fd in /proc/$pid/fd/*; do
        target=$(readlink "$fd" 2>/dev/null) || continue
        if [[ "$target" == /dev/pts/* ]]; then
            comm=$(cat "/proc/$pid/comm" 2>/dev/null || echo "???")
            exe=$(readlink "/proc/$pid/exe" 2>/dev/null || echo "???")
            # Skip known legitimate cases (systemd, agetty, etc.)
            if ! echo "$comm" | grep -qE '^(systemd|agetty|login|sshd|gdm|lightdm|xdm)'; then
                finding "PID $pid ($comm) has PTY ${target} but loginuid=UNSET (no PAM login) exe='$exe'"
            fi
        fi
    done
done < <(ls -1 /proc/ 2>/dev/null | grep -E '^[0-9]+$')

#=============================================================================
# 10. BINARY CRYPTER / BINCRYPTER DETECTION
#     gsocket's bincrypter wraps binaries in encrypted shell scripts.
#     Signature: #!/bin/sh + random junk + eval+openssl+base64 chain
#=============================================================================
header "10. BINCRYPTER PAYLOAD DETECTION"

info "Scanning for bincrypter-wrapped binaries..."
bc_found=0
for search_dir in /usr/local/sbin /usr/local/bin /usr/sbin /usr/bin /tmp /var/tmp; do
    [[ ! -d "$search_dir" ]] && continue
    while IFS= read -r f; do
        [[ ! -f "$f" ]] && continue
        # bincrypter signature: starts with #!/bin/sh, contains obfuscated eval+openssl
        head_bytes=$(head -c 512 "$f" 2>/dev/null) || continue
        if echo "$head_bytes" | grep -q '#!/bin/sh' && \
           echo "$head_bytes" | grep -qE "(openssl.*base64|eval.*perl.*-pe)"; then
            finding "Possible bincrypter-wrapped binary: $f"
            ((bc_found++))
        fi
    done < <(find "$search_dir" -maxdepth 2 -type f -executable 2>/dev/null)
done

# Also check user home directories
while IFS= read -r homedir; do
    [[ ! -d "$homedir/.config" ]] && continue
    while IFS= read -r f; do
        head_bytes=$(head -c 512 "$f" 2>/dev/null) || continue
        if echo "$head_bytes" | grep -q '#!/bin/sh' && \
           echo "$head_bytes" | grep -qE "(openssl.*base64|eval.*perl)"; then
            finding "Possible bincrypter payload in user config: $f"
            ((bc_found++))
        fi
    done < <(find "$homedir/.config" -maxdepth 3 -type f -executable 2>/dev/null)
done < <(awk -F: '$3>=1000||$3==0{print $6}' /etc/passwd 2>/dev/null)

[[ $bc_found -eq 0 ]] && clean "No bincrypter payloads detected"

#=============================================================================
# 11. TIMESTAMP MANIPULATION DETECTION
#     gsocket's _ts_fix() modifies timestamps on dropped files to blend in.
#     Check for suspicious timestamp clustering or impossible timestamps.
#=============================================================================
header "11. TIMESTAMP ANOMALY DETECTION"

info "Checking systemd service files for timestamp anomalies..."
for sdir in /etc/systemd/system /lib/systemd/system; do
    [[ ! -d "$sdir" ]] && continue
    # Find service files where mtime is suspiciously close to a system binary's mtime
    # (gsocket copies timestamps from legitimate binaries)
    while IFS= read -r sf; do
        [[ ! -f "$sf" ]] && continue
        sf_mtime=$(stat -c %Y "$sf" 2>/dev/null) || continue
        sf_ctime=$(stat -c %Z "$sf" 2>/dev/null) || continue
        # If ctime is much newer than mtime, timestamp was manipulated
        diff=$((sf_ctime - sf_mtime))
        if [[ $diff -gt 86400 ]]; then  # ctime > mtime by more than 24h
            svc_name=$(basename "$sf")
            for gs_name in "${GS_SVC_NAMES[@]}"; do
                if [[ "$svc_name" == "${gs_name}.service" ]]; then
                    finding "Service $sf: ctime is ${diff}s newer than mtime (timestamp manipulation?)"
                fi
            done
        fi
    done < <(find "$sdir" -maxdepth 1 -name "*.service" -type f 2>/dev/null)
done

#=============================================================================
# SUMMARY
#=============================================================================
echo ""
echo -e "${CW}━━━ SCAN SUMMARY ━━━${CN}"
echo -e "  Total findings: ${CR}${FINDINGS}${CN}"
echo -e "  Critical:       ${CR}${CRITICAL}${CN}"
echo ""

if [[ $CRITICAL -gt 0 ]]; then
    echo -e "${CR}╔══════════════════════════════════════════════════════════════╗${CN}"
    echo -e "${CR}║  CRITICAL FINDINGS — LIKELY ACTIVE COMPROMISE              ║${CN}"
    echo -e "${CR}╠══════════════════════════════════════════════════════════════╣${CN}"
    echo -e "${CR}║  Recommended IR steps:                                     ║${CN}"
    echo -e "${CR}║  1. Capture volatile evidence (memory dump, /proc snapshot) ║${CN}"
    echo -e "${CR}║  2. Isolate host from network                              ║${CN}"
    echo -e "${CR}║  3. Preserve logs: utmp, wtmp, journal, audit              ║${CN}"
    echo -e "${CR}║  4. Check: GS_UNDO=1 bash deploy.sh  (for cleanup IOCs)   ║${CN}"
    echo -e "${CR}║  5. Rotate ALL credentials that touched this host          ║${CN}"
    echo -e "${CR}╚══════════════════════════════════════════════════════════════╝${CN}"
elif [[ $FINDINGS -gt 0 ]]; then
    echo -e "${CY}  Findings require manual triage — may be false positives.${CN}"
else
    echo -e "${CG}  No gsocket implant indicators detected.${CN}"
fi

echo -e "${CF}  Scan completed: $(date -u '+%Y-%m-%d %H:%M:%S UTC')${CN}"
exit $FINDINGS
