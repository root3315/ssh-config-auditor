#!/usr/bin/env bash
#
# config_parser.sh - SSH configuration file parser module
#

parse_config_file() {
    local file="$1"

    if [[ ! -r "$file" ]]; then
        echo "ERROR: Cannot read file: $file" >&2
        return 1
    fi

    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line#"${line%%[![:space:]]*}"}"
        line="${line%"${line##*[![:space:]]}"}"

        [[ -z "$line" ]] && continue
        [[ "$line" =~ ^[[:space:]]*# ]] && continue

        line="${line%%#*}"
        line="${line%"${line##*[![:space:]]}"}"

        [[ -z "$line" ]] && continue

        local directive value

        if [[ "$line" =~ ^([A-Za-z][A-Za-z0-9]*)[[:space:]]+(.*) ]]; then
            directive="${BASH_REMATCH[1]}"
            value="${BASH_REMATCH[2]}"
            directive=$(normalize_directive "$directive")
            echo "${directive}=${value}"
        elif [[ "$line" =~ ^([A-Za-z][A-Za-z0-9]*)[[:space:]]*=[[:space:]]*(.*) ]]; then
            directive="${BASH_REMATCH[1]}"
            value="${BASH_REMATCH[2]}"
            directive=$(normalize_directive "$directive")
            echo "${directive}=${value}"
        fi

    done < "$file"
}

normalize_directive() {
    local directive="$1"

    declare -A standard_names=(
        ["permitrootlogin"]="PermitRootLogin"
        ["passwordauthentication"]="PasswordAuthentication"
        ["permitemptypasswords"]="PermitEmptyPasswords"
        ["x11forwarding"]="X11Forwarding"
        ["allowtcpforwarding"]="AllowTcpForwarding"
        ["allowagentforwarding"]="AllowAgentForwarding"
        ["strictmodes"]="StrictModes"
        ["ignorerhosts"]="IgnoreRhosts"
        ["hostbasedauthentication"]="HostbasedAuthentication"
        ["logingracetime"]="LoginGraceTime"
        ["maxauthtries"]="MaxAuthTries"
        ["clientaliveinterval"]="ClientAliveInterval"
        ["clientalivecountmax"]="ClientAliveCountMax"
        ["usepam"]="UsePAM"
        ["challengeresponseauthentication"]="ChallengeResponseAuthentication"
        ["ciphers"]="Ciphers"
        ["macs"]="MACs"
        ["kexalgorithms"]="KexAlgorithms"
        ["protocol"]="Protocol"
        ["loglevel"]="LogLevel"
        ["syslogfacility"]="SyslogFacility"
        ["printmotd"]="PrintMotd"
        ["printlastlog"]="PrintLastLog"
        ["compression"]="Compression"
        ["permituserenvironment"]="PermitUserEnvironment"
        ["usedns"]="UseDNS"
        ["gatewayports"]="GatewayPorts"
        ["permittunnel"]="PermitTunnel"
        ["subsystem"]="Subsystem"
        ["port"]="Port"
        ["listenaddress"]="ListenAddress"
        ["addressfamily"]="AddressFamily"
        ["hostkey"]="HostKey"
        ["authorizedkeysfile"]="AuthorizedKeysFile"
        ["allowusers"]="AllowUsers"
        ["allowgroups"]="AllowGroups"
        ["denyusers"]="DenyUsers"
        ["denygroups"]="DenyGroups"
        ["banner"]="Banner"
        ["pubkeyauthentication"]="PubkeyAuthentication"
        ["include"]="Include"
        ["acceptenv"]="AcceptEnv"
    )

    local lower_directive
    lower_directive=$(echo "$directive" | tr '[:upper:]' '[:lower:]')

    if [[ -n "${standard_names[$lower_directive]:-}" ]]; then
        echo "${standard_names[$lower_directive]}"
    else
        echo "${directive^}"
    fi
}

is_multi_value_directive() {
    local directive="$1"
    local lower_directive
    lower_directive=$(echo "$directive" | tr '[:upper:]' '[:lower:]')

    case "$lower_directive" in
        ciphers|macs|kexalgorithms|hostkeyalgorithms|pubkeyacceptedalgorithms|\
        pubkeyacceptedkeytypes|hostkey|hostcertificate|listenaddress|\
        authorizedkeysfile|acceptenv|allowusers|allowgroups|denyusers|denygroups|\
        authenticationmethods|include)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

get_directive_value() {
    local file="$1"
    local target_directive="$2"
    local value=""

    target_directive=$(normalize_directive "$target_directive")

    while IFS='=' read -r directive val; do
        if [[ "$directive" == "$target_directive" ]]; then
            value="$val"
        fi
    done < <(parse_config_file "$file")

    echo "$value"
}

has_directive() {
    local file="$1"
    local target_directive="$2"

    target_directive=$(normalize_directive "$target_directive")

    while IFS='=' read -r directive val; do
        if [[ "$directive" == "$target_directive" ]]; then
            return 0
        fi
    done < <(parse_config_file "$file")

    return 1
}

get_all_directive_values() {
    local file="$1"
    local target_directive="$2"

    target_directive=$(normalize_directive "$target_directive")

    while IFS='=' read -r directive val; do
        if [[ "$directive" == "$target_directive" ]]; then
            echo "$val"
        fi
    done < <(parse_config_file "$file")
}

parse_list() {
    local list="$1"
    list="${list//,/ }"

    for item in $list; do
        item="${item#"${item%%[![:space:]]*}"}"
        item="${item%"${item##*[![:space:]]}"}"
        [[ -n "$item" ]] && echo "$item"
    done
}

validate_config_syntax() {
    local file="$1"
    local line_num=0
    local errors=0

    while IFS= read -r line || [[ -n "$line" ]]; do
        ((line_num++))

        [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue

        if ! [[ "$line" =~ ^[[:space:]]*(Match|[A-Za-z][A-Za-z0-9]*)[[:space:]] ]]; then
            echo "Line $line_num: Invalid directive format: $line" >&2
            ((errors++))
        fi

    done < "$file"

    [[ $errors -eq 0 ]]
}

get_effective_value() {
    local file="$1"
    local directive="$2"
    local default="$3"

    local value
    value=$(get_directive_value "$file" "$directive")

    if [[ -n "$value" ]]; then
        echo "$value"
    else
        echo "$default"
    fi
}
