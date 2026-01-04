#!/usr/bin/env bash
#
# security_checks.sh - SSH security check functions module
#

declare -a WEAK_CIPHERS=(
    "3des-cbc"
    "aes128-cbc"
    "aes192-cbc"
    "aes256-cbc"
    "rijndael-cbc@lysator.liu.se"
    "blowfish-cbc"
    "cast128-cbc"
    "arcfour"
    "arcfour128"
    "arcfour256"
    "aes128-ctr"
    "aes192-ctr"
    "aes256-ctr"
)

declare -a WEAK_MACS=(
    "hmac-md5"
    "hmac-md5-96"
    "hmac-sha1"
    "hmac-sha1-96"
    "umac-64@openssh.com"
    "hmac-md5-etm@openssh.com"
    "hmac-md5-96-etm@openssh.com"
    "hmac-sha1-etm@openssh.com"
    "hmac-sha1-96-etm@openssh.com"
    "umac-64-etm@openssh.com"
)

declare -a WEAK_KEX=(
    "diffie-hellman-group1-sha1"
    "diffie-hellman-group14-sha1"
    "diffie-hellman-group-exchange-sha1"
    "ecdh-sha2-nistp256"
    "ecdh-sha2-nistp384"
    "ecdh-sha2-nistp521"
    "diffie-hellman-group14-sha256"
)

add_issue() {
    local severity="$1"
    local file="$2"
    local directive="$3"
    local current="$4"
    local recommended="$5"
    local description="$6"

    current="${current//|/\\|}"
    recommended="${recommended//|/\\|}"
    description="${description//|/\\|}"

    ISSUES+=("${severity}|${file}|${directive}|${current}|${recommended}|${description}")
    ((ISSUE_COUNTS[$severity]++))
}

check_permit_root_login() {
    local file="$1"
    local value="$2"

    value="${value:-prohibit-password}"

    case "${value,,}" in
        "yes")
            add_issue "critical" "$file" "PermitRootLogin" "$value" "no" \
                "Root login is permitted. This is a critical security risk as it allows direct root access."
            ;;
        "without-password"|"prohibit-password")
            add_issue "medium" "$file" "PermitRootLogin" "$value" "no" \
                "Root login with keys is permitted. Consider disabling root login entirely."
            ;;
        "no")
            :
            ;;
        *)
            add_issue "low" "$file" "PermitRootLogin" "$value" "no" \
                "Unrecognized PermitRootLogin value. Should be explicitly set to 'no'."
            ;;
    esac
}

check_password_authentication() {
    local file="$1"
    local value="$2"

    value="${value:-yes}"

    case "${value,,}" in
        "yes")
            add_issue "high" "$file" "PasswordAuthentication" "$value" "no" \
                "Password authentication is enabled. Use key-based authentication for better security."
            ;;
        "no")
            :
            ;;
        *)
            add_issue "low" "$file" "PasswordAuthentication" "$value" "no" \
                "Unrecognized PasswordAuthentication value. Should be explicitly set to 'no'."
            ;;
    esac
}

check_permit_empty_passwords() {
    local file="$1"
    local value="$2"

    value="${value:-no}"

    case "${value,,}" in
        "yes")
            add_issue "critical" "$file" "PermitEmptyPasswords" "$value" "no" \
                "Empty passwords are permitted. This is a critical security vulnerability."
            ;;
        "no")
            :
            ;;
        *)
            add_issue "low" "$file" "PermitEmptyPasswords" "$value" "no" \
                "Unrecognized PermitEmptyPasswords value. Should be explicitly set to 'no'."
            ;;
    esac
}

check_x11_forwarding() {
    local file="$1"
    local value="$2"

    value="${value:-no}"

    case "${value,,}" in
        "yes")
            add_issue "medium" "$file" "X11Forwarding" "$value" "no" \
                "X11 forwarding is enabled. Disable unless specifically required to reduce attack surface."
            ;;
        "no")
            :
            ;;
    esac
}

check_tcp_forwarding() {
    local file="$1"
    local value="$2"

    value="${value:-yes}"

    case "${value,,}" in
        "yes"|"all")
            add_issue "medium" "$file" "AllowTcpForwarding" "$value" "no" \
                "TCP forwarding is enabled. This can be used to bypass network security controls."
            ;;
        "no")
            :
            ;;
        "local"|"remote")
            add_issue "low" "$file" "AllowTcpForwarding" "$value" "no" \
                "Partial TCP forwarding is enabled. Consider disabling completely if not needed."
            ;;
    esac
}

check_agent_forwarding() {
    local file="$1"
    local value="$2"

    value="${value:-yes}"

    case "${value,,}" in
        "yes")
            add_issue "medium" "$file" "AllowAgentForwarding" "$value" "no" \
                "Agent forwarding is enabled. This can expose SSH keys to compromised servers."
            ;;
        "no")
            :
            ;;
    esac
}

check_strict_modes() {
    local file="$1"
    local value="$2"

    value="${value:-yes}"

    case "${value,,}" in
        "no")
            add_issue "high" "$file" "StrictModes" "$value" "yes" \
                "StrictModes is disabled. SSH will not check file permissions on key files."
            ;;
        "yes")
            :
            ;;
    esac
}

check_ignore_rhosts() {
    local file="$1"
    local value="$2"

    value="${value:-yes}"

    case "${value,,}" in
        "no")
            add_issue "high" "$file" "IgnoreRhosts" "$value" "yes" \
                "IgnoreRhosts is disabled. Legacy .rhosts authentication may be allowed."
            ;;
        "yes")
            :
            ;;
    esac
}

check_hostbased_authentication() {
    local file="$1"
    local value="$2"

    value="${value:-no}"

    case "${value,,}" in
        "yes")
            add_issue "high" "$file" "HostbasedAuthentication" "$value" "no" \
                "Host-based authentication is enabled. This is generally less secure than key-based auth."
            ;;
        "no")
            :
            ;;
    esac
}

check_login_grace_time() {
    local file="$1"
    local value="$2"

    value="${value:-120}"

    local seconds
    if [[ "$value" =~ ^([0-9]+)[mM]$ ]]; then
        seconds=$((BASH_REMATCH[1] * 60))
    elif [[ "$value" =~ ^([0-9]+)[hH]$ ]]; then
        seconds=$((BASH_REMATCH[1] * 3600))
    elif [[ "$value" =~ ^([0-9]+)[dD]$ ]]; then
        seconds=$((BASH_REMATCH[1] * 86400))
    elif [[ "$value" =~ ^[0-9]+$ ]]; then
        seconds="$value"
    else
        seconds=120
    fi

    if [[ $seconds -gt 120 ]]; then
        add_issue "low" "$file" "LoginGraceTime" "$value" "60" \
            "LoginGraceTime is set too high (${seconds}s). Consider reducing to 60 seconds or less."
    elif [[ $seconds -eq 0 ]]; then
        add_issue "medium" "$file" "LoginGraceTime" "$value" "60" \
            "LoginGraceTime is unlimited (0). This could allow indefinite connection attempts."
    fi
}

check_max_auth_tries() {
    local file="$1"
    local value="$2"

    value="${value:-6}"

    if [[ "$value" =~ ^[0-9]+$ ]]; then
        if [[ $value -gt 6 ]]; then
            add_issue "medium" "$file" "MaxAuthTries" "$value" "3" \
                "MaxAuthTries is set too high. Reduce to 3-4 to limit brute force attempts."
        elif [[ $value -lt 2 ]]; then
            add_issue "low" "$file" "MaxAuthTries" "$value" "3" \
                "MaxAuthTries is very low. May cause issues for legitimate users."
        fi
    fi
}

check_client_alive_interval() {
    local file="$1"
    local value="$2"

    if [[ -z "$value" || "$value" == "0" ]]; then
        add_issue "info" "$file" "ClientAliveInterval" "${value:-0}" "300" \
            "ClientAliveInterval is not set. Consider setting to 300 to detect dead connections."
    fi
}

check_client_alive_count_max() {
    local file="$1"
    local value="$2"

    value="${value:-3}"

    if [[ "$value" =~ ^[0-9]+$ ]]; then
        if [[ $value -gt 5 ]]; then
            add_issue "low" "$file" "ClientAliveCountMax" "$value" "3" \
                "ClientAliveCountMax is set high. Dead connections may not be detected promptly."
        fi
    fi
}

check_use_pam() {
    local file="$1"
    local value="$2"

    value="${value:-yes}"

    case "${value,,}" in
        "no")
            add_issue "low" "$file" "UsePAM" "$value" "yes" \
                "PAM is disabled. This may limit authentication options and session management."
            ;;
        "yes")
            :
            ;;
    esac
}

check_challenge_response() {
    local file="$1"
    local value="$2"

    value="${value:-yes}"

    case "${value,,}" in
        "yes")
            add_issue "low" "$file" "ChallengeResponseAuthentication" "$value" "no" \
                "Challenge-response authentication is enabled. Disable if not using keyboard-interactive."
            ;;
        "no")
            :
            ;;
    esac
}

check_ciphers() {
    local file="$1"
    local value="$2"

    if [[ -z "$value" ]]; then
        add_issue "info" "$file" "Ciphers" "(default)" "aes256-gcm@openssh.com,chacha20-poly1305@openssh.com" \
            "No explicit cipher list. Consider specifying strong ciphers only."
        return
    fi

    local found_weak=0
    local weak_list=""

    while IFS= read -r cipher; do
        for weak in "${WEAK_CIPHERS[@]}"; do
            if [[ "${cipher,,}" == "${weak,,}" ]]; then
                found_weak=1
                weak_list="${weak_list}${weak}, "
            fi
        done
    done < <(parse_list "$value")

    if [[ $found_weak -eq 1 ]]; then
        weak_list="${weak_list%, }"
        add_issue "critical" "$file" "Ciphers" "$value" "aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes256-ctr" \
            "Weak ciphers detected: ${weak_list}. Remove these immediately."
    fi
}

check_macs() {
    local file="$1"
    local value="$2"

    if [[ -z "$value" ]]; then
        add_issue "info" "$file" "MACs" "(default)" "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com" \
            "No explicit MAC list. Consider specifying strong MACs only."
        return
    fi

    local found_weak=0
    local weak_list=""

    while IFS= read -r mac; do
        for weak in "${WEAK_MACS[@]}"; do
            if [[ "${mac,,}" == "${weak,,}" ]]; then
                found_weak=1
                weak_list="${weak_list}${weak}, "
            fi
        done
    done < <(parse_list "$value")

    if [[ $found_weak -eq 1 ]]; then
        weak_list="${weak_list%, }"
        add_issue "critical" "$file" "MACs" "$value" "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com" \
            "Weak MACs detected: ${weak_list}. Remove these immediately."
    fi
}

check_kex_algorithms() {
    local file="$1"
    local value="$2"

    if [[ -z "$value" ]]; then
        add_issue "info" "$file" "KexAlgorithms" "(default)" "curve25519-sha256,curve25519-sha256@libssh.org" \
            "No explicit key exchange list. Consider specifying strong algorithms only."
        return
    fi

    local found_weak=0
    local weak_list=""

    while IFS= read -r kex; do
        for weak in "${WEAK_KEX[@]}"; do
            if [[ "${kex,,}" == "${weak,,}" ]]; then
                found_weak=1
                weak_list="${weak_list}${weak}, "
            fi
        done
    done < <(parse_list "$value")

    if [[ $found_weak -eq 1 ]]; then
        weak_list="${weak_list%, }"
        add_issue "critical" "$file" "KexAlgorithms" "$value" "curve25519-sha256,diffie-hellman-group16-sha512" \
            "Weak key exchange algorithms detected: ${weak_list}. Remove these immediately."
    fi
}

check_protocol() {
    local file="$1"
    local value="$2"

    if [[ -n "$value" ]]; then
        if [[ "$value" == "1" || "$value" =~ ^1, || "$value" =~ ,1, || "$value" =~ ,1$ ]]; then
            add_issue "critical" "$file" "Protocol" "$value" "2" \
                "SSH Protocol 1 is enabled or allowed. This protocol is insecure and must be disabled."
        fi
    fi
}

check_log_level() {
    local file="$1"
    local value="$2"

    value="${value:-INFO}"

    case "${value,,}" in
        "quiet"|"fatal"|"error")
            add_issue "medium" "$file" "LogLevel" "$value" "VERBOSE" \
                "LogLevel is too restrictive. Security events may not be logged."
            ;;
        "info")
            add_issue "low" "$file" "LogLevel" "$value" "VERBOSE" \
                "Consider increasing LogLevel to VERBOSE for better security auditing."
            ;;
        "verbose"|"debug"|"debug1"|"debug2"|"debug3")
            :
            ;;
    esac
}

check_syslog_facility() {
    local file="$1"
    local value="$2"

    value="${value:-AUTH}"

    case "${value,,}" in
        "auth")
            :
            ;;
        "daemon"|"user"|"local0"|"local1"|"local2"|"local3"|"local4"|"local5"|"local6"|"local7")
            add_issue "info" "$file" "SyslogFacility" "$value" "AUTH" \
                "SyslogFacility is set to $value. AUTH is recommended for security events."
            ;;
    esac
}

check_print_motd() {
    local file="$1"
    local value="$2"

    value="${value:-yes}"

    case "${value,,}" in
        "yes")
            add_issue "info" "$file" "PrintMotd" "$value" "no" \
                "PrintMotd is enabled. Consider disabling and using Banner for legal notices."
            ;;
    esac
}

check_print_last_log() {
    local file="$1"
    local value="$2"

    value="${value:-yes}"

    case "${value,,}" in
        "no")
            add_issue "low" "$file" "PrintLastLog" "$value" "yes" \
                "PrintLastLog is disabled. Users should see last login time for security awareness."
            ;;
    esac
}

check_compression() {
    local file="$1"
    local value="$2"

    value="${value:-yes}"

    case "${value,,}" in
        "yes")
            add_issue "low" "$file" "Compression" "$value" "no" \
                "Compression is enabled. Consider disabling to prevent CRIME-style attacks."
            ;;
        "delayed")
            add_issue "info" "$file" "Compression" "$value" "no" \
                "Delayed compression is enabled. Consider disabling completely."
            ;;
    esac
}

check_permit_user_environment() {
    local file="$1"
    local value="$2"

    value="${value:-no}"

    case "${value,,}" in
        "yes")
            add_issue "high" "$file" "PermitUserEnvironment" "$value" "no" \
                "PermitUserEnvironment is enabled. Users can set environment variables that may bypass security."
            ;;
    esac
}

check_use_dns() {
    local file="$1"
    local value="$2"

    value="${value:-yes}"

    case "${value,,}" in
        "yes")
            add_issue "low" "$file" "UseDNS" "$value" "no" \
                "UseDNS is enabled. This can cause login delays and is not required for security."
            ;;
    esac
}

check_gateway_ports() {
    local file="$1"
    local value="$2"

    value="${value:-no}"

    case "${value,,}" in
        "yes")
            add_issue "high" "$file" "GatewayPorts" "$value" "no" \
                "GatewayPorts is enabled. Remote hosts can connect to forwarded ports."
            ;;
        "clientspecified")
            add_issue "medium" "$file" "GatewayPorts" "$value" "no" \
                "GatewayPorts allows client-specified binding. Consider disabling."
            ;;
    esac
}

check_permit_tunnel() {
    local file="$1"
    local value="$2"

    value="${value:-no}"

    case "${value,,}" in
        "yes")
            add_issue "medium" "$file" "PermitTunnel" "$value" "no" \
                "Tunneling is permitted. This can be used to bypass network controls."
            ;;
        "point-to-point"|"ethernet")
            add_issue "low" "$file" "PermitTunnel" "$value" "no" \
                "Specific tunnel types are permitted. Consider if this is necessary."
            ;;
    esac
}

check_subsystem() {
    local file="$1"
    local value="$2"

    if [[ -n "$value" ]]; then
        if [[ "$value" =~ sftp && ! "$value" =~ internal-sftp ]]; then
            add_issue "info" "$file" "Subsystem" "$value" "internal-sftp" \
                "Using external sftp-server. Consider using internal-sftp for better chroot support."
        fi
    fi
}

run_generic_checks() {
    local file="$1"
    shift
    check_ciphers "$file" ""
    check_macs "$file" ""
    check_kex_algorithms "$file" ""
}

run_sshd_checks() {
    local file="$1"
    shift
    :
}

run_ssh_checks() {
    local file="$1"
    shift
    add_issue "info" "$file" "ConfigType" "ssh_config" "N/A" \
        "Client configuration file detected. Some server-side checks were skipped."
}
