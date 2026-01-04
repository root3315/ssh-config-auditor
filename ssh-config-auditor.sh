#!/usr/bin/env bash
#
# ssh-config-auditor - Security auditor for SSH configuration files
#
# This tool scans SSH configuration files (sshd_config, ssh_config) for
# security issues and misconfigurations, providing actionable recommendations.
#

set -uo pipefail

# Script directory for sourcing libraries
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source library modules
source "${SCRIPT_DIR}/lib/config_parser.sh"
source "${SCRIPT_DIR}/lib/security_checks.sh"
source "${SCRIPT_DIR}/lib/reporter.sh"

# Version information
VERSION="1.0.0"

# Default configuration
declare -A CONFIG=(
    [verbose]=0
    [quiet]=0
    [output_format]="text"
    [output_file]=""
    [check_level]="standard"
    [include_recommended]=0
)

# Color configuration
declare -A COLORS=(
    [reset]="\033[0m"
    [red]="\033[31m"
    [green]="\033[32m"
    [yellow]="\033[33m"
    [blue]="\033[34m"
    [bold]="\033[1m"
)

# Issue counters
declare -A ISSUE_COUNTS=(
    [critical]=0
    [high]=0
    [medium]=0
    [low]=0
    [info]=0
)

# Collected issues array
declare -a ISSUES=()

# Usage information
usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS] <config_file> [config_file...]

SSH Configuration Security Auditor

Scans SSH configuration files for security issues and misconfigurations.

Arguments:
  config_file    Path to SSH config file (sshd_config, ssh_config, or custom)

Options:
  -h, --help              Show this help message and exit
  -v, --verbose           Enable verbose output
  -q, --quiet             Suppress non-essential output
  -o, --output FILE       Write results to FILE instead of stdout
  -f, --format FORMAT     Output format: text, json, csv (default: text)
  -l, --level LEVEL       Check level: basic, standard, strict (default: standard)
  -r, --recommended       Include recommended (non-critical) checks
  --version               Show version information

Examples:
  $(basename "$0") /etc/ssh/sshd_config
  $(basename "$0") -v -f json /etc/ssh/sshd_config
  $(basename "$0") -l strict -o audit_report.txt /etc/ssh/sshd_config
  $(basename "$0") -r ~/.ssh/config

Exit Codes:
  0 - No issues found
  1 - Issues found (severity: low)
  2 - Issues found (severity: medium)
  3 - Issues found (severity: high)
  4 - Issues found (severity: critical)
  5 - Error during execution

EOF
}

# Show version
show_version() {
    echo "ssh-config-auditor version ${VERSION}"
}

# Log message based on verbosity
log() {
    local level="$1"
    shift
    local message="$*"
    
    case "$level" in
        error)
            echo -e "${COLORS[red]}[ERROR]${COLORS[reset]} ${message}" >&2
            ;;
        warn)
            echo -e "${COLORS[yellow]}[WARN]${COLORS[reset]} ${message}" >&2
            ;;
        info)
            if [[ ${CONFIG[verbose]} -eq 1 ]]; then
                echo -e "${COLORS[blue]}[INFO]${COLORS[reset]} ${message}" >&2
            fi
            ;;
        debug)
            if [[ ${CONFIG[verbose]} -eq 2 ]]; then
                echo -e "[DEBUG] ${message}" >&2
            fi
            ;;
    esac
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                usage
                exit 0
                ;;
            --version)
                show_version
                exit 0
                ;;
            -v|--verbose)
                CONFIG[verbose]=1
                shift
                ;;
            -q|--quiet)
                CONFIG[quiet]=1
                shift
                ;;
            -o|--output)
                if [[ -z "${2:-}" ]]; then
                    log error "Output file not specified"
                    exit 5
                fi
                CONFIG[output_file]="$2"
                shift 2
                ;;
            -f|--format)
                if [[ -z "${2:-}" ]]; then
                    log error "Output format not specified"
                    exit 5
                fi
                case "$2" in
                    text|json|csv)
                        CONFIG[output_format]="$2"
                        ;;
                    *)
                        log error "Invalid output format: $2 (use: text, json, csv)"
                        exit 5
                        ;;
                esac
                shift 2
                ;;
            -l|--level)
                if [[ -z "${2:-}" ]]; then
                    log error "Check level not specified"
                    exit 5
                fi
                case "$2" in
                    basic|standard|strict)
                        CONFIG[check_level]="$2"
                        ;;
                    *)
                        log error "Invalid check level: $2 (use: basic, standard, strict)"
                        exit 5
                        ;;
                esac
                shift 2
                ;;
            -r|--recommended)
                CONFIG[include_recommended]=1
                shift
                ;;
            -*)
                log error "Unknown option: $1"
                usage
                exit 5
                ;;
            *)
                CONFIG_FILES+=("$1")
                shift
                ;;
        esac
    done
}

# Validate config file exists and is readable
validate_config_file() {
    local file="$1"
    
    if [[ ! -e "$file" ]]; then
        log error "File not found: $file"
        return 1
    fi
    
    if [[ ! -f "$file" ]]; then
        log error "Not a regular file: $file"
        return 1
    fi
    
    if [[ ! -r "$file" ]]; then
        log error "Cannot read file: $file"
        return 1
    fi
    
    return 0
}

# Detect config file type
detect_config_type() {
    local file="$1"
    local filename
    filename=$(basename "$file")
    
    # Check filename patterns
    case "$filename" in
        sshd_config*|*_sshd_config*)
            echo "sshd"
            return
            ;;
        ssh_config*|*_ssh_config*)
            echo "ssh"
            return
            ;;
    esac
    
    # Analyze content for keywords
    if grep -qE "^(PermitRootLogin|PasswordAuthentication|PermitEmptyPasswords)" "$file" 2>/dev/null; then
        echo "sshd"
    elif grep -qE "^(Host |HostName |User |IdentityFile)" "$file" 2>/dev/null; then
        echo "ssh"
    else
        echo "unknown"
    fi
}

# Run all security checks on a config file
audit_config_file() {
    local file="$1"
    local config_type
    config_type=$(detect_config_type "$file")
    
    log info "Auditing file: $file (type: $config_type)"
    
    # Parse the configuration file
    local -A config_values
    config_values=$(parse_config_file "$file")
    
    # Run security checks based on config type
    if [[ "$config_type" == "sshd" ]]; then
        run_sshd_checks "$file" "${!config_values[@]}"
    elif [[ "$config_type" == "ssh" ]]; then
        run_ssh_checks "$file" "${!config_values[@]}"
    else
        # Run generic checks
        run_generic_checks "$file" "${!config_values[@]}"
    fi
}

# Main audit function
run_audit() {
    local file="$1"

    if ! validate_config_file "$file"; then
        return 1
    fi

    # Initialize for this file
    local file_issues=()

    # Get all configuration directives into a temp file to avoid subshell issues
    local tmpdirectives
    tmpdirectives=$(mktemp)
    parse_config_file "$file" > "$tmpdirectives"
    
    # Read directives into associative array
    local -A directives
    while IFS='=' read -r key value; do
        [[ -n "$key" ]] && directives["$key"]="$value"
    done < "$tmpdirectives"
    rm -f "$tmpdirectives"

    # Run comprehensive security checks
    check_permit_root_login "$file" "${directives[PermitRootLogin]:-}"
    check_password_authentication "$file" "${directives[PasswordAuthentication]:-}"
    check_permit_empty_passwords "$file" "${directives[PermitEmptyPasswords]:-}"
    check_x11_forwarding "$file" "${directives[X11Forwarding]:-}"
    check_tcp_forwarding "$file" "${directives[AllowTcpForwarding]:-}"
    check_agent_forwarding "$file" "${directives[AllowAgentForwarding]:-}"
    check_strict_modes "$file" "${directives[StrictModes]:-}"
    check_ignore_rhosts "$file" "${directives[IgnoreRhosts]:-}"
    check_hostbased_authentication "$file" "${directives[HostbasedAuthentication]:-}"
    check_login_grace_time "$file" "${directives[LoginGraceTime]:-}"
    check_max_auth_tries "$file" "${directives[MaxAuthTries]:-}"
    check_client_alive_interval "$file" "${directives[ClientAliveInterval]:-}"
    check_client_alive_count_max "$file" "${directives[ClientAliveCountMax]:-}"
    check_use_pam "$file" "${directives[UsePAM]:-}"
    check_challenge_response "$file" "${directives[ChallengeResponseAuthentication]:-}"
    check_ciphers "$file" "${directives[Ciphers]:-}"
    check_macs "$file" "${directives[MACs]:-}"
    check_kex_algorithms "$file" "${directives[KexAlgorithms]:-}"
    check_protocol "$file" "${directives[Protocol]:-}"
    check_log_level "$file" "${directives[LogLevel]:-}"
    check_syslog_facility "$file" "${directives[SyslogFacility]:-}"
    check_print_motd "$file" "${directives[PrintMotd]:-}"
    check_print_last_log "$file" "${directives[PrintLastLog]:-}"
    check_compression "$file" "${directives[Compression]:-}"
    check_permit_user_environment "$file" "${directives[PermitUserEnvironment]:-}"
    check_use_dns "$file" "${directives[UseDNS]:-}"
    check_gateway_ports "$file" "${directives[GatewayPorts]:-}"
    check_permit_tunnel "$file" "${directives[PermitTunnel]:-}"
    check_subsystem "$file" "${directives[Subsystem]:-}"

    return 0
}

# Calculate overall severity and exit code
calculate_exit_code() {
    local exit_code=0
    
    if [[ ${ISSUE_COUNTS[critical]} -gt 0 ]]; then
        exit_code=4
    elif [[ ${ISSUE_COUNTS[high]} -gt 0 ]]; then
        exit_code=3
    elif [[ ${ISSUE_COUNTS[medium]} -gt 0 ]]; then
        exit_code=2
    elif [[ ${ISSUE_COUNTS[low]} -gt 0 ]]; then
        exit_code=1
    fi
    
    echo "$exit_code"
}

# Main entry point
main() {
    CONFIG_FILES=()
    
    # Parse command line arguments
    parse_args "$@"
    
    # Check if config files were provided
    if [[ ${#CONFIG_FILES[@]} -eq 0 ]]; then
        log error "No configuration files specified"
        usage
        exit 5
    fi
    
    # Process each configuration file
    for config_file in "${CONFIG_FILES[@]}"; do
        log info "Processing: $config_file"
        run_audit "$config_file"
    done
    
    # Generate and output report
    local report
    report=$(generate_report "${ISSUES[@]}")
    
    # Output report
    if [[ -n "${CONFIG[output_file]}" ]]; then
        echo "$report" > "${CONFIG[output_file]}"
        log info "Report written to: ${CONFIG[output_file]}"
    else
        echo "$report"
    fi
    
    # Calculate and return exit code
    local exit_code
    exit_code=$(calculate_exit_code)
    
    if [[ ${CONFIG[quiet]} -eq 0 ]]; then
        echo ""
        echo "Summary: ${ISSUE_COUNTS[critical]} critical, ${ISSUE_COUNTS[high]} high, ${ISSUE_COUNTS[medium]} medium, ${ISSUE_COUNTS[low]} low, ${ISSUE_COUNTS[info]} info"
    fi
    
    exit "$exit_code"
}

# Run main if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
