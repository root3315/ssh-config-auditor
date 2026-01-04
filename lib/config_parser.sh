#!/usr/bin/env bash
#
# config_parser.sh - SSH configuration file parser module
#
# Provides functions to parse and extract configuration directives
# from SSH configuration files (sshd_config and ssh_config).
#

# Parse a configuration file and output key=value pairs
# Handles comments, empty lines, and multi-value directives
#
# Arguments:
#   $1 - Path to configuration file
#
# Output:
#   Lines of "key=value" for each directive found
parse_config_file() {
    local file="$1"
    local line_num=0
    local in_match_block=0
    local current_match=""
    
    if [[ ! -r "$file" ]]; then
        echo "ERROR: Cannot read file: $file" >&2
        return 1
    fi
    
    while IFS= read -r line || [[ -n "$line" ]]; do
        ((line_num++))
        
        # Remove leading/trailing whitespace
        line="${line#"${line%%[![:space:]]*}"}"
        line="${line%"${line##*[![:space:]]}"}"
        
        # Skip empty lines
        [[ -z "$line" ]] && continue
        
        # Skip comments (lines starting with #)
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        
        # Remove inline comments
        line="${line%%#*}"
        line="${line%"${line##*[![:space:]]}"}"
        
        # Skip if line is now empty after removing comments
        [[ -z "$line" ]] && continue
        
        # Handle Match blocks (sshd_config specific)
        if [[ "$line" =~ ^Match[[:space:]]+(.*) ]]; then
            in_match_block=1
            current_match="${BASH_REMATCH[1]}"
            echo "MatchBlock=${current_match}"
            continue
        fi
        
        # Parse directive and value
        local directive value
        
        # Handle directives with space separator
        if [[ "$line" =~ ^([A-Za-z][A-Za-z0-9]*)[[:space:]]+(.*) ]]; then
            directive="${BASH_REMATCH[1]}"
            value="${BASH_REMATCH[2]}"
            
            # Normalize directive name (capitalize first letter)
            directive=$(normalize_directive "$directive")
            
            # Handle multi-value directives (accumulate values)
            if is_multi_value_directive "$directive"; then
                echo "${directive}=${value}"
            else
                echo "${directive}=${value}"
            fi
        # Handle directives with = separator
        elif [[ "$line" =~ ^([A-Za-z][A-Za-z0-9]*)[[:space:]]*=[[:space:]]*(.*) ]]; then
            directive="${BASH_REMATCH[1]}"
            value="${BASH_REMATCH[2]}"
            directive=$(normalize_directive "$directive")
            echo "${directive}=${value}"
        fi
        
    done < "$file"
}

# Normalize directive name to standard capitalization
normalize_directive() {
    local directive="$1"
    
    # Common SSH directives with standard capitalization
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
        ["hostcertificate"]="HostCertificate"
        ["authorizedkeysfile"]="AuthorizedKeysFile"
        ["trustedusercakeys"]="TrustedUserCAKeys"
        ["revokedkeys"]="RevokedKeys"
        ["allowusers"]="AllowUsers"
        ["allowgroups"]="AllowGroups"
        ["denyusers"]="DenyUsers"
        ["denygroups"]="DenyGroups"
        ["banner"]="Banner"
        ["chrootdirectory"]="ChrootDirectory"
        ["forcecommand"]="ForceCommand"
        ["permitopen"]="PermitOpen"
        ["permitlisten"]="PermitListen"
        ["versionaddendum"]="VersionAddendum"
        ["authenticationmethods"]="AuthenticationMethods"
        ["pubkeyauthentication"]="PubkeyAuthentication"
        ["kerberosauthentication"]="KerberosAuthentication"
        ["gssapiauthentication"]="GSSAPIAuthentication"
        ["include"]="Include"
        ["acceptenv"]="AcceptEnv"
        ["setenv"]="SetEnv"
        ["loginactionscript"]="LoginActionScript"
        ["exposeauthinfo"]="ExposeAuthInfo"
        ["fingerprinthash"]="FingerprintHash"
        ["hostkeyagent"]="HostKeyAgent"
        ["hostkeyalgorithms"]="HostKeyAlgorithms"
        ["ipqos"]="IPQoS"
        ["kexalgorithms"]="KexAlgorithms"
        ["maxsessions"]="MaxSessions"
        ["maxstartups"]="MaxStartups"
        ["passwordauthentication"]="PasswordAuthentication"
        ["permitrootlogin"]="PermitRootLogin"
        ["pubkeyacceptedalgorithms"]="PubkeyAcceptedAlgorithms"
        ["pubkeyacceptedkeytypes"]="PubkeyAcceptedKeyTypes"
        ["rdomain"]="RDomain"
        ["rekeylimit"]="RekeyLimit"
        ["revokedkeys"]="RevokedKeys"
        ["securitykeyprovider"]="SecurityKeyProvider"
        ["streamlocalbindmask"]="StreamLocalBindMask"
        ["streamlocalbindunlink"]="StreamLocalBindUnlink"
        ["tcpkeepalive"]="TCPKeepAlive"
        ["trustedusercakeys"]="TrustedUserCAKeys"
        ["unusedconnectiontimeout"]="UnusedConnectionTimeout"
        ["verifyhostkeydns"]="VerifyHostKeyDNS"
    )
    
    local lower_directive
    lower_directive=$(echo "$directive" | tr '[:upper:]' '[:lower:]')
    
    if [[ -n "${standard_names[$lower_directive]:-}" ]]; then
        echo "${standard_names[$lower_directive]}"
    else
        # Default: capitalize first letter, lowercase rest
        echo "${directive^}"
    fi
}

# Check if a directive can have multiple values
is_multi_value_directive() {
    local directive="$1"
    local lower_directive
    lower_directive=$(echo "$directive" | tr '[:upper:]' '[:lower:]')
    
    case "$lower_directive" in
        ciphers|macs|kexalgorithms|hostkeyalgorithms|pubkeyacceptedalgorithms|\
        pubkeyacceptedkeytypes|hostkey|hostcertificate|listenaddress|\
        authorizedkeysfile|acceptenv|allowusers|allowgroups|denyusers|denygroups|\
        authenticationmethods|include|trustedusercakeys|revokedkeys)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

# Extract a specific directive value from config file
#
# Arguments:
#   $1 - Path to configuration file
#   $2 - Directive name to extract
#
# Output:
#   The value of the directive, or empty if not found
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

# Check if a directive is set in the config file
#
# Arguments:
#   $1 - Path to configuration file
#   $2 - Directive name to check
#
# Returns:
#   0 if directive exists, 1 otherwise
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

# Get all directives of a specific type (e.g., all Ciphers)
#
# Arguments:
#   $1 - Path to configuration file
#   $2 - Directive name
#
# Output:
#   All values for the directive, one per line
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

# Parse comma or space-separated list into array elements
#
# Arguments:
#   $1 - String containing list of values
#
# Output:
#   One value per line
parse_list() {
    local list="$1"
    
    # Replace commas with spaces, then split on whitespace
    list="${list//,/ }"
    
    for item in $list; do
        # Remove leading/trailing whitespace
        item="${item#"${item%%[![:space:]]*}"}"
        item="${item%"${item##*[![:space:]]}"}"
        [[ -n "$item" ]] && echo "$item"
    done
}

# Validate config file syntax (basic check)
#
# Arguments:
#   $1 - Path to configuration file
#
# Returns:
#   0 if syntax appears valid, 1 if issues found
validate_config_syntax() {
    local file="$1"
    local line_num=0
    local errors=0
    
    while IFS= read -r line || [[ -n "$line" ]]; do
        ((line_num++))
        
        # Skip empty lines and comments
        [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
        
        # Check for lines without proper directive format
        if ! [[ "$line" =~ ^[[:space:]]*(Match|[A-Za-z][A-Za-z0-9]*)[[:space:]] ]]; then
            echo "Line $line_num: Invalid directive format: $line" >&2
            ((errors++))
        fi
        
    done < "$file"
    
    [[ $errors -eq 0 ]]
}

# Get effective value considering defaults
#
# Arguments:
#   $1 - Path to configuration file
#   $2 - Directive name
#   $3 - Default value if not specified
#
# Output:
#   The effective value (configured or default)
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
