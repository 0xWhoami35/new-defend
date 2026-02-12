#!/usr/bin/env bash
#===============================================================================
#
#  PROC THREAT HUNTER — Interactive /proc Forensics Tool
#
#  An interactive threat-hunting utility that inspects running processes via
#  the /proc filesystem. Designed to work for BOTH normal users and root,
#  gracefully degrading when permissions are insufficient.
#
#  Modes:
#    1) Binary   — Enumerate running executables, flag suspicious binaries
#    2) Environ  — Scan process environment variables with keyword filtering
#
#  Usage:
#      ./proc_threat_hunter.sh              # Launch interactive menu
#      bash proc_threat_hunter.sh           # Alternative invocation
#
#  Notes:
#    • Does NOT require root. Runs with whatever privileges are available.
#    • Root/sudo grants visibility into ALL processes (recommended).
#    • Non-root users can inspect their own processes and some system ones.
#
#===============================================================================

set -uo pipefail

# ─── Terminal Colors & Symbols ────────────────────────────────────────────────

if [[ -t 1 ]]; then
    RED='\033[0;91m'
    YELLOW='\033[0;93m'
    GREEN='\033[0;92m'
    CYAN='\033[0;96m'
    MAGENTA='\033[0;95m'
    BOLD='\033[1m'
    DIM='\033[2m'
    RESET='\033[0m'
else
    RED='' YELLOW='' GREEN='' CYAN='' MAGENTA='' BOLD='' DIM='' RESET=''
fi

readonly DIVIDER="$(printf '%.0s─' {1..70})"
readonly DOUBLE_DIV="$(printf '%.0s═' {1..70})"

# ─── Counters ─────────────────────────────────────────────────────────────────

TOTAL_INSPECTED=0
TOTAL_READABLE=0
TOTAL_UNREADABLE=0
TOTAL_SUSPICIOUS=0
TOTAL_DELETED=0
TOTAL_MATCHED=0

reset_counters() {
    TOTAL_INSPECTED=0
    TOTAL_READABLE=0
    TOTAL_UNREADABLE=0
    TOTAL_SUSPICIOUS=0
    TOTAL_DELETED=0
    TOTAL_MATCHED=0
}

# ─── Utility Functions ────────────────────────────────────────────────────────

log_info()  { echo -e "  ${GREEN}[INFO]${RESET}  $*"; }
log_warn()  { echo -e "  ${YELLOW}[WARN]${RESET}  $*"; }
log_alert() { echo -e "  ${RED}[ALERT]${RESET} $*"; }

print_header() {
    echo ""
    echo -e "  ${CYAN}${BOLD}${DOUBLE_DIV}${RESET}"
    echo -e "  ${CYAN}${BOLD}  $1${RESET}"
    echo -e "  ${CYAN}${BOLD}${DOUBLE_DIV}${RESET}"
    echo ""
}

privilege_notice() {
    if [[ "$(id -u)" -eq 0 ]]; then
        log_info "Running as ${BOLD}root${RESET} — full /proc visibility enabled."
    else
        log_warn "Running as ${BOLD}$(whoami)${RESET} (non-root)."
        log_warn "Only your own processes and some system processes are visible."
        log_warn "Run with ${BOLD}sudo${RESET} for full coverage."
    fi
    echo ""
}

# Safely get the process owner UID from /proc/<PID>/status
get_proc_owner() {
    local pid="$1"
    local status_file="/proc/${pid}/status"
    if [[ -r "${status_file}" ]]; then
        awk '/^Uid:/ { print $2 }' "${status_file}" 2>/dev/null || echo "?"
    else
        echo "?"
    fi
}

# Resolve UID to username
uid_to_user() {
    local uid="$1"
    if [[ "${uid}" == "?" ]]; then
        echo "?"
        return
    fi
    getent passwd "${uid}" 2>/dev/null | cut -d: -f1 || echo "${uid}"
}

# Read /proc/<PID>/comm safely
get_comm() {
    local pid="$1"
    if [[ -r "/proc/${pid}/comm" ]]; then
        cat "/proc/${pid}/comm" 2>/dev/null || echo "[unknown]"
    else
        echo "[no access]"
    fi
}

# Read /proc/<PID>/cmdline safely (null-byte separated)
get_cmdline() {
    local pid="$1"
    if [[ -r "/proc/${pid}/cmdline" ]]; then
        local cmd
        cmd="$(tr '\0' ' ' < "/proc/${pid}/cmdline" 2>/dev/null | sed 's/ $//')"
        if [[ -z "${cmd}" ]]; then
            echo "[kernel thread]"
        else
            echo "${cmd}"
        fi
    else
        echo "[no access]"
    fi
}

# Resolve the real binary path via readlink -f on /proc/<PID>/exe
resolve_binary() {
    local pid="$1"
    local exe_link="/proc/${pid}/exe"

    if [[ ! -e "/proc/${pid}" ]]; then
        echo "[process exited]"
        return 1
    fi

    if [[ -L "${exe_link}" ]]; then
        readlink -f "${exe_link}" 2>/dev/null || echo "[readlink failed]"
    elif [[ -e "${exe_link}" ]]; then
        echo "[exists but not a symlink]"
    else
        echo "[no exe — kernel thread or no permission]"
    fi
}

# ─── Suspicious Binary Heuristics ────────────────────────────────────────────

analyze_binary() {
    local pid="$1"
    local binary="$2"
    local flags=()

    # 1. Binary deleted from disk (fileless malware / process injection)
    if [[ "${binary}" == *"(deleted)"* ]]; then
        flags+=("DELETED_BINARY")
        ((TOTAL_DELETED++))
    fi

    # 2. Execution from world-writable staging directories
    if [[ "${binary}" =~ ^/(tmp|dev/shm|var/tmp|run/shm|run/lock)/ ]]; then
        flags+=("EXEC_FROM_TMPDIR")
    fi

    # 3. Memfd-based execution (fileless malware via memfd_create)
    if [[ "${binary}" == *"/memfd:"* ]]; then
        flags+=("MEMFD_EXECUTION")
    fi

    # 4. Hidden file execution (dotfile binary)
    local basename_bin
    basename_bin="$(basename "${binary}" 2>/dev/null || echo "")"
    if [[ "${basename_bin}" == .* && "${basename_bin}" != "." ]]; then
        flags+=("HIDDEN_BINARY")
    fi

    # 5. Binary in unusual home subdirectory dot-path
    if [[ "${binary}" =~ ^/home/.*\. ]]; then
        flags+=("DOTPATH_IN_HOME")
    fi

    # 6. Process name vs binary name mismatch (masquerading detection)
    local comm
    comm="$(get_comm "${pid}")"
    if [[ "${comm}" != "[no access]" && "${comm}" != "[unknown]" ]]; then
        local expected_name
        expected_name="$(basename "${binary}" 2>/dev/null | sed 's/ (deleted)//')"
        if [[ -n "${expected_name}" && \
              "${expected_name}" != "[no exe"* && \
              "${expected_name}" != "[readlink"* && \
              "${expected_name}" != "[process"* && \
              "${comm}" != "${expected_name}" ]]; then
            # Allow common interpreter patterns (python3 → python3.12, etc.)
            if [[ "${expected_name}" != "${comm}"* && "${comm}" != "${expected_name}"* ]]; then
                flags+=("NAME_MISMATCH:comm=${comm},exe=${expected_name}")
            fi
        fi
    fi

    # Report findings
    if [[ ${#flags[@]} -gt 0 ]]; then
        ((TOTAL_SUSPICIOUS++))
        for flag in "${flags[@]}"; do
            log_alert "PID ${pid}: ${BOLD}${flag}${RESET}"
        done
        return 0  # suspicious
    fi
    return 1  # clean
}

# ─── MODE 1: Binary Scan ─────────────────────────────────────────────────────

mode_binary() {
    reset_counters
    print_header "MODE 1 — Binary Executable Scan"
    privilege_notice

    log_info "Scanning /proc for running process executables..."
    echo -e "  ${DIVIDER}"
    echo ""

    local suspicious_list=()

    for pid_dir in /proc/[0-9]*; do
        local pid="${pid_dir##*/}"

        # Validate: numeric PID and process still exists
        [[ "${pid}" =~ ^[0-9]+$ ]] || continue
        [[ -d "/proc/${pid}" ]]    || continue

        ((TOTAL_INSPECTED++))

        # Resolve binary via readlink -f /proc/<PID>/exe
        local binary
        binary="$(resolve_binary "${pid}")"

        # Skip kernel threads (no exe symlink)
        if [[ "${binary}" == "[no exe — kernel thread or no permission]" ]]; then
            ((TOTAL_UNREADABLE++))
            continue
        fi

        # Skip unreadable entries
        if [[ "${binary}" == "[readlink failed]" || "${binary}" == "[process exited]" ]]; then
            ((TOTAL_UNREADABLE++))
            continue
        fi

        ((TOTAL_READABLE++))

        # Gather metadata
        local owner_uid
        owner_uid="$(get_proc_owner "${pid}")"
        local owner_name
        owner_name="$(uid_to_user "${owner_uid}")"
        local comm
        comm="$(get_comm "${pid}")"
        local cmdline
        cmdline="$(get_cmdline "${pid}")"

        # Truncate very long cmdlines
        if [[ ${#cmdline} -gt 80 ]]; then
            cmdline="${cmdline:0:77}..."
        fi

        # Run heuristic analysis
        local is_suspicious=false
        if analyze_binary "${pid}" "${binary}"; then
            is_suspicious=true
            suspicious_list+=("${pid}")
        fi

        # Display entry
        if ${is_suspicious}; then
            echo -e "  ${RED}${BOLD}▶ PID:${RESET}     ${RED}${pid}${RESET}  ${RED}[!!! SUSPICIOUS !!!]${RESET}"
        else
            echo -e "  ${BOLD}▶ PID:${RESET}     ${pid}"
        fi
        echo -e "    ${BOLD}User:${RESET}    ${owner_name} (uid=${owner_uid})"
        echo -e "    ${BOLD}Comm:${RESET}    ${comm}"
        echo -e "    ${BOLD}Binary:${RESET}  ${binary}"
        echo -e "    ${BOLD}Cmdline:${RESET} ${DIM}${cmdline}${RESET}"
        echo -e "  ${DIM}$(printf '%.0s┄' {1..66})${RESET}"

    done

    # ── Summary ───────────────────────────────────────────────────────────
    echo ""
    echo -e "  ${DOUBLE_DIV}"
    echo -e "  ${BOLD}BINARY SCAN SUMMARY${RESET}"
    echo -e "  ${DOUBLE_DIV}"
    echo -e "    Total PIDs scanned:     ${TOTAL_INSPECTED}"
    echo -e "    Binaries resolved:      ${TOTAL_READABLE}"
    echo -e "    Unreadable / skipped:   ${TOTAL_UNREADABLE}"
    echo -e "    Deleted binaries:       ${TOTAL_DELETED}"
    echo -e "    ${RED}${BOLD}Suspicious processes:   ${TOTAL_SUSPICIOUS}${RESET}"

    if [[ ${#suspicious_list[@]} -gt 0 ]]; then
        echo ""
        log_alert "Suspicious PIDs: ${BOLD}${suspicious_list[*]}${RESET}"
        echo ""
        echo -e "  ${YELLOW}${BOLD}Recommended follow-up commands:${RESET}"
        echo -e "    ${DIM}cat /proc/<PID>/maps${RESET}            # Memory mappings"
        echo -e "    ${DIM}ls -la /proc/<PID>/fd/${RESET}          # Open file descriptors"
        echo -e "    ${DIM}readlink /proc/<PID>/cwd${RESET}        # Working directory"
        echo -e "    ${DIM}cat /proc/<PID>/net/tcp${RESET}         # Network connections"
        echo -e "    ${DIM}cat /proc/<PID>/stack${RESET}           # Kernel stack trace"
    else
        echo ""
        log_info "No suspicious binaries detected."
    fi

    echo -e "  ${DOUBLE_DIV}"
    echo ""
}

# ─── MODE 2: Environment Variable Scan ───────────────────────────────────────

mode_environ() {
    reset_counters
    print_header "MODE 2 — Environment Variable Scan"
    privilege_notice

    # Prompt for optional keyword filter
    echo -e "  ${BOLD}Enter a keyword to filter environment variables (case-insensitive).${RESET}"
    echo -e "  ${DIM}Examples: LD_PRELOAD, GS_ARGS, SECRET, PASSWORD, TOKEN, PROXY${RESET}"
    echo -e "  ${DIM}Press ENTER to skip filtering and show summaries with auto-detection.${RESET}"
    echo ""
    echo -ne "  ${CYAN}${BOLD}Filter keyword: ${RESET}"
    read -r KEYWORD
    KEYWORD="$(echo "${KEYWORD}" | xargs)"  # Trim whitespace

    echo ""

    if [[ -n "${KEYWORD}" ]]; then
        log_info "Scanning with filter: ${BOLD}${KEYWORD}${RESET} (case-insensitive grep)"
    else
        log_info "No filter applied — showing summaries with auto-detection of risky vars."
    fi

    echo -e "  ${DIVIDER}"
    echo ""

    local match_pids=()

    for pid_dir in /proc/[0-9]*; do
        local pid="${pid_dir##*/}"

        [[ "${pid}" =~ ^[0-9]+$ ]] || continue
        [[ -d "/proc/${pid}" ]]    || continue

        ((TOTAL_INSPECTED++))

        local environ_path="/proc/${pid}/environ"

        # ── Permission Check (non-root graceful degradation) ─────────
        if [[ ! -r "${environ_path}" ]]; then
            ((TOTAL_UNREADABLE++))
            continue
        fi

        # Read and decode null-byte-separated environ via tr '\0' '\n'
        local environ_data
        environ_data="$(tr '\0' '\n' < "${environ_path}" 2>/dev/null || true)"

        # Skip empty environ (kernel threads)
        if [[ -z "${environ_data}" ]]; then
            continue
        fi

        ((TOTAL_READABLE++))

        # Gather metadata
        local binary
        binary="$(resolve_binary "${pid}")"
        local comm
        comm="$(get_comm "${pid}")"
        local owner_uid
        owner_uid="$(get_proc_owner "${pid}")"
        local owner_name
        owner_name="$(uid_to_user "${owner_uid}")"

        # ── FILTERED MODE: grep -i for keyword ───────────────────────
        if [[ -n "${KEYWORD}" ]]; then
            local matched_lines
            matched_lines="$(echo "${environ_data}" | grep -i -- "${KEYWORD}" 2>/dev/null || true)"

            if [[ -n "${matched_lines}" ]]; then
                ((TOTAL_MATCHED++))
                match_pids+=("${pid}")

                echo -e "  ${RED}${BOLD}★ MATCH — PID ${pid}${RESET}"
                echo -e "  ${DIM}$(printf '%.0s┄' {1..66})${RESET}"
                echo -e "    ${BOLD}User:${RESET}    ${owner_name} (uid=${owner_uid})"
                echo -e "    ${BOLD}Comm:${RESET}    ${comm}"
                echo -e "    ${BOLD}Binary:${RESET}  ${binary}"
                echo -e "    ${BOLD}Matched Variables:${RESET}"

                while IFS= read -r line; do
                    # Highlight the keyword in output
                    local highlighted
                    highlighted="$(echo "${line}" | grep -i --color=always -- "${KEYWORD}" 2>/dev/null || echo "${line}")"
                    echo -e "      ${YELLOW}→${RESET} ${highlighted}"
                done <<< "${matched_lines}"

                echo -e "  ${DIM}$(printf '%.0s┄' {1..66})${RESET}"
                echo ""
            fi

        # ── UNFILTERED MODE: show summary + auto-detect risky vars ───
        else
            local env_count
            env_count="$(echo "${environ_data}" | wc -l)"

            # Auto-detect commonly suspicious / sensitive environment variables
            local risky_vars=()
            echo "${environ_data}" | grep -qi "^LD_PRELOAD="       && risky_vars+=("LD_PRELOAD")
            echo "${environ_data}" | grep -qi "^LD_LIBRARY_PATH="  && risky_vars+=("LD_LIBRARY_PATH")
            echo "${environ_data}" | grep -qi "^GS_ARGS="          && risky_vars+=("GS_ARGS")
            echo "${environ_data}" | grep -qi "^HTTP_PROXY="       && risky_vars+=("HTTP_PROXY")
            echo "${environ_data}" | grep -qi "^HTTPS_PROXY="      && risky_vars+=("HTTPS_PROXY")
            echo "${environ_data}" | grep -qi "PASSWORD"           && risky_vars+=("*PASSWORD*")
            echo "${environ_data}" | grep -qi "TOKEN"              && risky_vars+=("*TOKEN*")
            echo "${environ_data}" | grep -qi "SECRET"             && risky_vars+=("*SECRET*")
            echo "${environ_data}" | grep -qi "API_KEY"            && risky_vars+=("*API_KEY*")

            local risk_marker=""
            if [[ ${#risky_vars[@]} -gt 0 ]]; then
                risk_marker=" ${YELLOW}[REVIEW: ${risky_vars[*]}]${RESET}"
                ((TOTAL_SUSPICIOUS++))
            fi

            echo -e "  ${BOLD}▶ PID:${RESET}     ${pid}${risk_marker}"
            echo -e "    ${BOLD}User:${RESET}    ${owner_name}"
            echo -e "    ${BOLD}Comm:${RESET}    ${comm}"
            echo -e "    ${BOLD}Binary:${RESET}  ${binary}"
            echo -e "    ${BOLD}Environ:${RESET} ${env_count} variable(s)"

            if [[ ${#risky_vars[@]} -gt 0 ]]; then
                echo -e "    ${BOLD}Noteworthy:${RESET}"
                for var_pattern in "${risky_vars[@]}"; do
                    local clean_pattern="${var_pattern//\*/}"
                    local var_lines
                    var_lines="$(echo "${environ_data}" | grep -i -- "${clean_pattern}" 2>/dev/null || true)"
                    while IFS= read -r vl; do
                        [[ -z "${vl}" ]] && continue
                        # Truncate extremely long values
                        if [[ ${#vl} -gt 120 ]]; then
                            vl="${vl:0:117}..."
                        fi
                        echo -e "      ${YELLOW}→${RESET} ${vl}"
                    done <<< "${var_lines}"
                done
            fi

            echo -e "  ${DIM}$(printf '%.0s┄' {1..66})${RESET}"
        fi

    done

    # ── Summary ───────────────────────────────────────────────────────────
    echo ""
    echo -e "  ${DOUBLE_DIV}"
    echo -e "  ${BOLD}ENVIRON SCAN SUMMARY${RESET}"
    echo -e "  ${DOUBLE_DIV}"
    echo -e "    Total PIDs scanned:       ${TOTAL_INSPECTED}"
    echo -e "    Environ readable:         ${TOTAL_READABLE}"
    echo -e "    Permission denied:        ${TOTAL_UNREADABLE}"

    if [[ -n "${KEYWORD}" ]]; then
        echo -e "    Filter keyword:           ${BOLD}${KEYWORD}${RESET}"
        echo -e "    ${RED}${BOLD}Processes matched:        ${TOTAL_MATCHED}${RESET}"
        if [[ ${#match_pids[@]} -gt 0 ]]; then
            echo ""
            log_alert "Matched PIDs: ${BOLD}${match_pids[*]}${RESET}"
        fi
    else
        echo -e "    ${YELLOW}${BOLD}Processes w/ risky vars:  ${TOTAL_SUSPICIOUS}${RESET}"
    fi

    echo -e "  ${DOUBLE_DIV}"
    echo ""
}

# ─── Main Menu ────────────────────────────────────────────────────────────────

show_banner() {
    clear 2>/dev/null || true
    echo ""
    echo -e "  ${CYAN}${BOLD}╔══════════════════════════════════════════════════════════╗${RESET}"
    echo -e "  ${CYAN}${BOLD}║            PROC THREAT HUNTER  —  v2.0                  ║${RESET}"
    echo -e "  ${CYAN}${BOLD}║            /proc Filesystem Forensics Tool              ║${RESET}"
    echo -e "  ${CYAN}${BOLD}╚══════════════════════════════════════════════════════════╝${RESET}"
    echo ""
    echo -e "  ${DIM}Date:   $(date '+%Y-%m-%d %H:%M:%S %Z')${RESET}"
    echo -e "  ${DIM}Host:   $(hostname)${RESET}"
    echo -e "  ${DIM}User:   $(whoami) (uid=$(id -u))${RESET}"
    echo -e "  ${DIM}Kernel: $(uname -r)${RESET}"
    echo ""
}

main_menu() {
    while true; do
        show_banner

        echo -e "  ${BOLD}==== Proc Threat Hunter ====${RESET}"
        echo ""
        echo -e "    ${BOLD}1.${RESET} Binary   ${DIM}(running executables)${RESET}"
        echo -e "    ${BOLD}2.${RESET} Environ  ${DIM}(process environment scan)${RESET}"
        echo -e "    ${BOLD}3.${RESET} Exit"
        echo ""
        echo -ne "  ${CYAN}${BOLD}Choose option: ${RESET}"
        read -r choice

        case "${choice}" in
            1)
                mode_binary
                echo -ne "  ${DIM}Press ENTER to return to menu...${RESET}"
                read -r
                ;;
            2)
                mode_environ
                echo -ne "  ${DIM}Press ENTER to return to menu...${RESET}"
                read -r
                ;;
            3)
                echo ""
                log_info "Exiting Proc Threat Hunter. Stay vigilant."
                echo ""
                exit 0
                ;;
            *)
                log_warn "Invalid option '${choice}'. Please enter 1, 2, or 3."
                sleep 1
                ;;
        esac
    done
}

# ─── Entry Point ──────────────────────────────────────────────────────────────

main_menu
