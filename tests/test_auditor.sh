#!/usr/bin/env bash
#
# test_auditor.sh - Test suite for ssh-config-auditor
#

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[34m"
RESET="\033[0m"

source "${PROJECT_DIR}/lib/config_parser.sh"
source "${PROJECT_DIR}/lib/security_checks.sh"
source "${PROJECT_DIR}/lib/reporter.sh"
source "${PROJECT_DIR}/lib/custom_rules.sh"

declare -a ISSUES=()
declare -A ISSUE_COUNTS=(
    [critical]=0
    [high]=0
    [medium]=0
    [low]=0
    [info]=0
)

declare -A CONFIG=(
    [verbose]=0
    [quiet]=0
    [output_format]="text"
    [output_file]=""
    [check_level]="standard"
    [include_recommended]=0
    [rules_file]=""
)

log() {
    local level="$1"
    shift
    local message="$*"
    # No-op for tests
}

log_test() {
    echo -e "${BLUE}[TEST]${RESET} $1"
}

log_pass() {
    echo -e "${GREEN}[PASS]${RESET} $1"
    ((TESTS_PASSED++))
    ((TESTS_RUN++))
}

log_fail() {
    echo -e "${RED}[FAIL]${RESET} $1"
    ((TESTS_FAILED++))
    ((TESTS_RUN++))
}

log_info() {
    echo -e "${YELLOW}[INFO]${RESET} $1"
}

assert_equals() {
    local expected="$1"
    local actual="$2"
    local message="${3:-}"

    if [[ "$expected" == "$actual" ]]; then
        return 0
    else
        [[ -n "$message" ]] && echo "  Expected: $expected, Got: $actual - $message"
        return 1
    fi
}

assert_contains() {
    local haystack="$1"
    local needle="$2"
    local message="${3:-}"

    if [[ "$haystack" == *"$needle"* ]]; then
        return 0
    else
        [[ -n "$message" ]] && echo "  '$haystack' does not contain '$needle' - $message"
        return 1
    fi
}

assert_file_exists() {
    local file="$1"
    local message="${2:-}"

    if [[ -f "$file" ]]; then
        return 0
    else
        [[ -n "$message" ]] && echo "  File does not exist: $file - $message"
        return 1
    fi
}

create_temp_file() {
    local content="$1"
    local tmpfile
    tmpfile=$(mktemp)
    echo "$content" > "$tmpfile"
    echo "$tmpfile"
}

cleanup_temp_files() {
    rm -f "${TEMP_FILES[@]}" 2>/dev/null || true
    TEMP_FILES=()
}

TEMP_FILES=()

test_parse_simple_config() {
    log_test "Parsing simple config file..."

    local config="
# Test config
PermitRootLogin no
PasswordAuthentication yes
Port 22
"
    local tmpfile
    tmpfile=$(create_temp_file "$config")
    TEMP_FILES+=("$tmpfile")

    local result
    result=$(parse_config_file "$tmpfile")

    if assert_contains "$result" "PermitRootLogin=no" && \
       assert_contains "$result" "PasswordAuthentication=yes" && \
       assert_contains "$result" "Port=22"; then
        log_pass "Simple config parsing"
    else
        log_fail "Simple config parsing"
    fi
}

test_parse_config_with_comments() {
    log_test "Parsing config with comments..."

    local config="
# This is a comment
PermitRootLogin no  # inline comment
# Another comment
PasswordAuthentication yes
"
    local tmpfile
    tmpfile=$(create_temp_file "$config")
    TEMP_FILES+=("$tmpfile")

    local result
    result=$(parse_config_file "$tmpfile")

    if assert_contains "$result" "PermitRootLogin=no" && \
       assert_contains "$result" "PasswordAuthentication=yes"; then
        log_pass "Config with comments parsing"
    else
        log_fail "Config with comments parsing"
    fi
}

test_parse_config_with_spaces() {
    log_test "Parsing config with various whitespace..."

    local config="
  PermitRootLogin   no
    PasswordAuthentication    yes
    Port    2222
"
    local tmpfile
    tmpfile=$(create_temp_file "$config")
    TEMP_FILES+=("$tmpfile")

    local result
    result=$(parse_config_file "$tmpfile")

    if assert_contains "$result" "PermitRootLogin=no" && \
       assert_contains "$result" "PasswordAuthentication=yes" && \
       assert_contains "$result" "Port=2222"; then
        log_pass "Whitespace handling"
    else
        log_fail "Whitespace handling"
    fi
}

test_get_directive_value() {
    log_test "Getting specific directive value..."

    local config="
PermitRootLogin no
PasswordAuthentication yes
Port 22
"
    local tmpfile
    tmpfile=$(create_temp_file "$config")
    TEMP_FILES+=("$tmpfile")

    local value
    value=$(get_directive_value "$tmpfile" "PermitRootLogin")

    if assert_equals "no" "$value"; then
        log_pass "Get directive value"
    else
        log_fail "Get directive value (expected 'no', got '$value')"
    fi
}

test_has_directive() {
    log_test "Checking directive existence..."

    local config="
PermitRootLogin no
PasswordAuthentication yes
"
    local tmpfile
    tmpfile=$(create_temp_file "$config")
    TEMP_FILES+=("$tmpfile")

    if has_directive "$tmpfile" "PermitRootLogin" && \
       ! has_directive "$tmpfile" "NonExistent"; then
        log_pass "Has directive check"
    else
        log_fail "Has directive check"
    fi
}

test_parse_list() {
    log_test "Parsing comma/space separated list..."

    local list="aes256-gcm@openssh.com,chacha20-poly1305@openssh.com aes256-ctr"
    local result
    result=$(parse_list "$list")

    local count
    count=$(echo "$result" | wc -l)

    if [[ $count -eq 3 ]]; then
        log_pass "Parse list"
    else
        log_fail "Parse list (expected 3 items, got $count)"
    fi
}

test_normalize_directive() {
    log_test "Normalizing directive names..."

    local result
    result=$(normalize_directive "permitrootlogin")

    if assert_equals "PermitRootLogin" "$result"; then
        log_pass "Normalize directive"
    else
        log_fail "Normalize directive (expected 'PermitRootLogin', got '$result')"
    fi
}

test_parse_malformed_entries() {
    log_test "Parsing config with malformed entries..."

    local config="
PermitRootLogin no
123Invalid yes
PasswordAuthentication yes
@BadDirective value
=InvalidStart test
"
    local tmpfile
    tmpfile=$(create_temp_file "$config")
    TEMP_FILES+=("$tmpfile")

    local errors_file
    errors_file=$(mktemp)

    PARSE_ERRORS_FILE="$errors_file"
    local result
    result=$(parse_config_file "$tmpfile")
    PARSE_ERRORS_FILE=""

    local error_count
    error_count=$(count_parse_errors "$errors_file")

    if has_parse_errors "$errors_file" && [[ "$error_count" -eq 3 ]]; then
        log_pass "Malformed entries detection"
        rm -f "$errors_file"
    else
        log_fail "Malformed entries detection (expected 3 errors, got $error_count)"
        rm -f "$errors_file"
    fi
}

test_parse_error_messages() {
    log_test "Checking malformed entry error messages..."

    local config="
PermitRootLogin no
123Invalid yes
@BadDirective value
"
    local tmpfile
    tmpfile=$(create_temp_file "$config")
    TEMP_FILES+=("$tmpfile")

    local errors_file
    errors_file=$(mktemp)

    PARSE_ERRORS_FILE="$errors_file"
    local result
    result=$(parse_config_file "$tmpfile")
    PARSE_ERRORS_FILE=""

    local errors
    errors=$(get_parse_errors "$errors_file")

    rm -f "$errors_file"

    if assert_contains "$errors" "Line 3" && \
       assert_contains "$errors" "Malformed entry" && \
       assert_contains "$errors" "123Invalid"; then
        log_pass "Error message format"
    else
        log_fail "Error message format"
    fi
}

test_clear_parse_errors() {
    log_test "Testing clear_parse_errors function..."

    local config="
123Invalid yes
"
    local tmpfile
    tmpfile=$(create_temp_file "$config")
    TEMP_FILES+=("$tmpfile")

    local errors_file
    errors_file=$(mktemp)

    PARSE_ERRORS_FILE="$errors_file"
    parse_config_file "$tmpfile" > /dev/null
    PARSE_ERRORS_FILE=""

    if has_parse_errors "$errors_file"; then
        clear_parse_errors "$errors_file"
        if ! has_parse_errors "$errors_file"; then
            log_pass "Clear parse errors"
            rm -f "$errors_file"
        else
            log_fail "Clear parse errors (errors still present)"
            rm -f "$errors_file"
        fi
    else
        log_fail "Clear parse errors (no errors to clear)"
        rm -f "$errors_file"
    fi
}

test_parse_valid_after_malformed() {
    log_test "Parsing valid entries after malformed ones..."

    local config="
PermitRootLogin no
123Invalid yes
PasswordAuthentication yes
"
    local tmpfile
    tmpfile=$(create_temp_file "$config")
    TEMP_FILES+=("$tmpfile")

    local errors_file
    errors_file=$(mktemp)

    PARSE_ERRORS_FILE="$errors_file"
    local result
    result=$(parse_config_file "$tmpfile")
    PARSE_ERRORS_FILE=""

    rm -f "$errors_file"

    if assert_contains "$result" "PermitRootLogin=no" && \
       assert_contains "$result" "PasswordAuthentication=yes"; then
        log_pass "Valid entries parsed after malformed"
    else
        log_fail "Valid entries parsed after malformed"
    fi
}

test_validate_config_file_starting_with_digit() {
    log_test "Validating config with directive starting with digit..."

    local config="
PermitRootLogin no
123Invalid yes
PasswordAuthentication yes
"
    local tmpfile
    tmpfile=$(create_temp_file "$config")
    TEMP_FILES+=("$tmpfile")

    local errors_file
    errors_file=$(mktemp)

    PARSE_ERRORS_FILE="$errors_file"
    parse_config_file "$tmpfile" > /dev/null
    PARSE_ERRORS_FILE=""

    local errors
    errors=$(get_parse_errors "$errors_file")

    if assert_contains "$errors" "123Invalid"; then
        log_pass "Detect directive starting with digit"
        rm -f "$errors_file"
    else
        log_fail "Detect directive starting with digit"
        rm -f "$errors_file"
    fi
}

test_validate_config_file_invalid_start_char() {
    log_test "Validating config with invalid start character..."

    local config="
PermitRootLogin no
@InvalidDirective yes
PasswordAuthentication yes
"
    local tmpfile
    tmpfile=$(create_temp_file "$config")
    TEMP_FILES+=("$tmpfile")

    local errors_file
    errors_file=$(mktemp)

    PARSE_ERRORS_FILE="$errors_file"
    parse_config_file "$tmpfile" > /dev/null
    PARSE_ERRORS_FILE=""

    local errors
    errors=$(get_parse_errors "$errors_file")

    if assert_contains "$errors" "@InvalidDirective"; then
        log_pass "Detect directive with invalid start character"
        rm -f "$errors_file"
    else
        log_fail "Detect directive with invalid start character"
        rm -f "$errors_file"
    fi
}

test_parse_config_strict() {
    log_test "Testing strict parsing with error counting..."

    local config="
PermitRootLogin no
123Bad value
PasswordAuthentication yes
@Invalid test
Port 22
"
    local tmpfile
    tmpfile=$(create_temp_file "$config")
    TEMP_FILES+=("$tmpfile")

    local errors_file
    errors_file=$(mktemp)

    local result
    result=$(parse_config_strict "$tmpfile" "$errors_file" 2>&1)

    local error_count
    error_count=$(count_parse_errors "$errors_file")

    if [[ "$error_count" -eq 2 ]]; then
        log_pass "Strict parsing error count"
        rm -f "$errors_file"
    else
        log_fail "Strict parsing error count (expected 2, got $error_count)"
        rm -f "$errors_file"
    fi
}

test_get_parse_error_summary() {
    log_test "Testing parse error summary generation..."

    local config="
123Bad value
@Invalid test
"
    local tmpfile
    tmpfile=$(create_temp_file "$config")
    TEMP_FILES+=("$tmpfile")

    local errors_file
    errors_file=$(mktemp)

    PARSE_ERRORS_FILE="$errors_file"
    parse_config_file "$tmpfile" > /dev/null
    PARSE_ERRORS_FILE=""

    local summary
    summary=$(get_parse_error_summary "$errors_file")

    if assert_contains "$summary" "2" && assert_contains "$summary" "malformed"; then
        log_pass "Parse error summary"
        rm -f "$errors_file"
    else
        log_fail "Parse error summary"
        rm -f "$errors_file"
    fi
}

test_check_permit_root_login_yes() {
    log_test "Checking PermitRootLogin yes (critical)..."

    ISSUES=()
    declare -A ISSUE_COUNTS=([critical]=0 [high]=0 [medium]=0 [low]=0 [info]=0)

    check_permit_root_login "/test/config" "yes"

    if [[ ${ISSUE_COUNTS[critical]} -eq 1 ]]; then
        log_pass "PermitRootLogin yes detection"
    else
        log_fail "PermitRootLogin yes detection"
    fi
}

test_check_permit_root_login_no() {
    log_test "Checking PermitRootLogin no (secure)..."

    ISSUES=()
    declare -A ISSUE_COUNTS=([critical]=0 [high]=0 [medium]=0 [low]=0 [info]=0)

    check_permit_root_login "/test/config" "no"

    if [[ ${ISSUE_COUNTS[critical]} -eq 0 && ${ISSUE_COUNTS[high]} -eq 0 ]]; then
        log_pass "PermitRootLogin no (secure)"
    else
        log_fail "PermitRootLogin no should not raise issues"
    fi
}

test_check_password_authentication() {
    log_test "Checking PasswordAuthentication yes (high)..."

    ISSUES=()
    declare -A ISSUE_COUNTS=([critical]=0 [high]=0 [medium]=0 [low]=0 [info]=0)

    check_password_authentication "/test/config" "yes"

    if [[ ${ISSUE_COUNTS[high]} -eq 1 ]]; then
        log_pass "PasswordAuthentication yes detection"
    else
        log_fail "PasswordAuthentication yes detection"
    fi
}

test_check_permit_empty_passwords() {
    log_test "Checking PermitEmptyPasswords yes (critical)..."

    ISSUES=()
    declare -A ISSUE_COUNTS=([critical]=0 [high]=0 [medium]=0 [low]=0 [info]=0)

    check_permit_empty_passwords "/test/config" "yes"

    if [[ ${ISSUE_COUNTS[critical]} -eq 1 ]]; then
        log_pass "PermitEmptyPasswords yes detection"
    else
        log_fail "PermitEmptyPasswords yes detection"
    fi
}

test_check_weak_ciphers() {
    log_test "Checking weak ciphers detection..."

    ISSUES=()
    declare -A ISSUE_COUNTS=([critical]=0 [high]=0 [medium]=0 [low]=0 [info]=0)

    check_ciphers "/test/config" "3des-cbc,aes256-gcm@openssh.com"

    if [[ ${ISSUE_COUNTS[critical]} -eq 1 ]]; then
        log_pass "Weak ciphers detection"
    else
        log_fail "Weak ciphers detection"
    fi
}

test_check_weak_macs() {
    log_test "Checking weak MACs detection..."

    ISSUES=()
    declare -A ISSUE_COUNTS=([critical]=0 [high]=0 [medium]=0 [low]=0 [info]=0)

    check_macs "/test/config" "hmac-md5,hmac-sha2-256-etm@openssh.com"

    if [[ ${ISSUE_COUNTS[critical]} -eq 1 ]]; then
        log_pass "Weak MACs detection"
    else
        log_fail "Weak MACs detection"
    fi
}

test_check_weak_kex() {
    log_test "Checking weak KEX algorithms detection..."

    ISSUES=()
    declare -A ISSUE_COUNTS=([critical]=0 [high]=0 [medium]=0 [low]=0 [info]=0)

    check_kex_algorithms "/test/config" "diffie-hellman-group1-sha1,curve25519-sha256"

    if [[ ${ISSUE_COUNTS[critical]} -eq 1 ]]; then
        log_pass "Weak KEX detection"
    else
        log_fail "Weak KEX detection"
    fi
}

test_check_protocol_v1() {
    log_test "Checking SSH Protocol 1 detection..."

    ISSUES=()
    declare -A ISSUE_COUNTS=([critical]=0 [high]=0 [medium]=0 [low]=0 [info]=0)

    check_protocol "/test/config" "1"

    if [[ ${ISSUE_COUNTS[critical]} -eq 1 ]]; then
        log_pass "Protocol 1 detection"
    else
        log_fail "Protocol 1 detection"
    fi
}

test_check_strict_modes() {
    log_test "Checking StrictModes no (high)..."

    ISSUES=()
    declare -A ISSUE_COUNTS=([critical]=0 [high]=0 [medium]=0 [low]=0 [info]=0)

    check_strict_modes "/test/config" "no"

    if [[ ${ISSUE_COUNTS[high]} -eq 1 ]]; then
        log_pass "StrictModes no detection"
    else
        log_fail "StrictModes no detection"
    fi
}

test_check_x11_forwarding() {
    log_test "Checking X11Forwarding yes (medium)..."

    ISSUES=()
    declare -A ISSUE_COUNTS=([critical]=0 [high]=0 [medium]=0 [low]=0 [info]=0)

    check_x11_forwarding "/test/config" "yes"

    if [[ ${ISSUE_COUNTS[medium]} -eq 1 ]]; then
        log_pass "X11Forwarding yes detection"
    else
        log_fail "X11Forwarding yes detection"
    fi
}

test_generate_text_report() {
    log_test "Generating text format report..."

    ISSUES=()
    declare -A ISSUE_COUNTS=([critical]=1 [high]=0 [medium]=0 [low]=0 [info]=0)
    ISSUES+=("critical|/test/config|PermitRootLogin|yes|no|Root login permitted")

    local report
    report=$(generate_text_report "${ISSUES[@]}")

    if assert_contains "$report" "SSH CONFIG SECURITY AUDIT REPORT" && \
       assert_contains "$report" "CRITICAL" && \
       assert_contains "$report" "PermitRootLogin"; then
        log_pass "Text report generation"
    else
        log_fail "Text report generation"
    fi
}

test_generate_json_report() {
    log_test "Generating JSON format report..."

    ISSUES=()
    declare -A ISSUE_COUNTS=([critical]=1 [high]=0 [medium]=0 [low]=0 [info]=0)
    ISSUES+=("critical|/test/config|PermitRootLogin|yes|no|Root login permitted")

    local report
    report=$(generate_json_report "${ISSUES[@]}")

    if assert_contains "$report" '"tool"' && \
       assert_contains "$report" '"issues"' && \
       assert_contains "$report" '"severity"'; then
        log_pass "JSON report generation"
    else
        log_fail "JSON report generation"
    fi
}

test_generate_csv_report() {
    log_test "Generating CSV format report..."

    ISSUES=()
    declare -A ISSUE_COUNTS=([critical]=1 [high]=0 [medium]=0 [low]=0 [info]=0)
    ISSUES+=("critical|/test/config|PermitRootLogin|yes|no|Root login permitted")

    local report
    report=$(generate_csv_report "${ISSUES[@]}")

    if assert_contains "$report" "Severity,File,Directive" && \
       assert_contains "$report" "critical" && \
       assert_contains "$report" "PermitRootLogin"; then
        log_pass "CSV report generation"
    else
        log_fail "CSV report generation"
    fi
}

test_json_escape() {
    log_test "Testing JSON string escaping..."

    local input='test"value'
    local result
    result=$(json_escape "$input")

    if [[ "$result" != "$input" ]] || [[ "$result" != *'"'* ]]; then
        log_pass "JSON escaping"
    else
        log_fail "JSON escaping"
    fi
}

test_full_audit_insecure_config() {
    log_test "Running full audit on insecure config..."

    local config="
# Insecure SSH config for testing
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords yes
X11Forwarding yes
Protocol 1
Ciphers 3des-cbc,aes256-gcm@openssh.com
MACs hmac-md5,hmac-sha2-256-etm@openssh.com
KexAlgorithms diffie-hellman-group1-sha1,curve25519-sha256
StrictModes no
"
    local tmpfile
    tmpfile=$(create_temp_file "$config")
    TEMP_FILES+=("$tmpfile")

    ISSUES=()
    declare -A ISSUE_COUNTS=([critical]=0 [high]=0 [medium]=0 [low]=0 [info]=0)

    check_permit_root_login "$tmpfile" "yes"
    check_password_authentication "$tmpfile" "yes"
    check_permit_empty_passwords "$tmpfile" "yes"
    check_x11_forwarding "$tmpfile" "yes"
    check_protocol "$tmpfile" "1"
    check_ciphers "$tmpfile" "3des-cbc,aes256-gcm@openssh.com"
    check_macs "$tmpfile" "hmac-md5,hmac-sha2-256-etm@openssh.com"
    check_kex_algorithms "$tmpfile" "diffie-hellman-group1-sha1,curve25519-sha256"
    check_strict_modes "$tmpfile" "no"

    local total=$((ISSUE_COUNTS[critical] + ISSUE_COUNTS[high] + ISSUE_COUNTS[medium] + ISSUE_COUNTS[low] + ISSUE_COUNTS[info]))

    if [[ $total -ge 8 ]]; then
        log_pass "Full audit on insecure config"
    else
        log_fail "Full audit on insecure config (expected >=8 issues, got $total)"
    fi
}

test_full_audit_secure_config() {
    log_test "Running full audit on secure config..."

    local config="
# Secure SSH config for testing
PermitRootLogin no
PasswordAuthentication no
PermitEmptyPasswords no
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
StrictModes yes
IgnoreRhosts yes
HostbasedAuthentication no
Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
KexAlgorithms curve25519-sha256,diffie-hellman-group16-sha512
LogLevel VERBOSE
UsePAM yes
"
    local tmpfile
    tmpfile=$(create_temp_file "$config")
    TEMP_FILES+=("$tmpfile")

    ISSUES=()
    declare -A ISSUE_COUNTS=([critical]=0 [high]=0 [medium]=0 [low]=0 [info]=0)

    check_permit_root_login "$tmpfile" "no"
    check_password_authentication "$tmpfile" "no"
    check_permit_empty_passwords "$tmpfile" "no"
    check_x11_forwarding "$tmpfile" "no"
    check_strict_modes "$tmpfile" "yes"
    check_ciphers "$tmpfile" "aes256-gcm@openssh.com,chacha20-poly1305@openssh.com"
    check_macs "$tmpfile" "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com"
    check_kex_algorithms "$tmpfile" "curve25519-sha256,diffie-hellman-group16-sha512"

    local critical_high=$((ISSUE_COUNTS[critical] + ISSUE_COUNTS[high]))

    if [[ $critical_high -eq 0 ]]; then
        log_pass "Full audit on secure config"
    else
        log_fail "Full audit on secure config (should have no critical/high issues)"
    fi
}

test_full_audit_with_malformed_entries() {
    log_test "Running audit on config with malformed entries..."

    local config="
# Config with malformed entries
PermitRootLogin yes
123Invalid directive
@BadDirective value
PasswordAuthentication yes
"
    local tmpfile
    tmpfile=$(create_temp_file "$config")
    TEMP_FILES+=("$tmpfile")

    local errors_file
    errors_file=$(mktemp)

    PARSE_ERRORS_FILE="$errors_file"
    ISSUES=()
    declare -A ISSUE_COUNTS=([critical]=0 [high]=0 [medium]=0 [low]=0 [info]=0)

    local parsed
    parsed=$(parse_config_file "$tmpfile")
    PARSE_ERRORS_FILE=""

    local has_errors=0
    if has_parse_errors "$errors_file"; then
        has_errors=1
    fi
    rm -f "$errors_file"

    if assert_contains "$parsed" "PermitRootLogin=yes" && \
       assert_contains "$parsed" "PasswordAuthentication=yes" && \
       [[ "$has_errors" -eq 1 ]]; then
        log_pass "Audit with malformed entries"
    else
        log_fail "Audit with malformed entries"
    fi
}

test_audit_severely_malformed_config() {
    log_test "Running audit on severely malformed config..."

    local config="
123 all numbers
@special chars!!!
===more special===
no_valid_directive_here
"
    local tmpfile
    tmpfile=$(create_temp_file "$config")
    TEMP_FILES+=("$tmpfile")

    local errors_file
    errors_file=$(mktemp)

    PARSE_ERRORS_FILE="$errors_file"
    local parsed
    parsed=$(parse_config_file "$tmpfile")
    PARSE_ERRORS_FILE=""

    local error_count
    error_count=$(count_parse_errors "$errors_file")
    rm -f "$errors_file"

    if [[ "$error_count" -ge 3 ]]; then
        log_pass "Severely malformed config detection"
    else
        log_fail "Severely malformed config detection (expected >=3 errors, got $error_count)"
    fi
}

test_audit_mixed_valid_invalid_config() {
    log_test "Running audit on mixed valid/invalid config..."

    local config="
# Mixed config
PermitRootLogin no
123Invalid yes
PasswordAuthentication no
@BadDir value
Port 22
X11Forwarding no
"
    local tmpfile
    tmpfile=$(create_temp_file "$config")
    TEMP_FILES+=("$tmpfile")

    local errors_file
    errors_file=$(mktemp)

    PARSE_ERRORS_FILE="$errors_file"
    local parsed
    parsed=$(parse_config_file "$tmpfile")
    PARSE_ERRORS_FILE=""

    local valid_count=0
    while IFS= read -r line; do
        [[ -n "$line" ]] && ((valid_count++))
    done <<< "$parsed"

    local error_count
    error_count=$(count_parse_errors "$errors_file")
    rm -f "$errors_file"

    if [[ "$valid_count" -ge 4 && "$error_count" -eq 2 ]]; then
        log_pass "Mixed valid/invalid config handling"
    else
        log_fail "Mixed valid/invalid config handling (valid: $valid_count, errors: $error_count)"
    fi
}

create_rules_file() {
    local content="$1"
    local tmpfile
    tmpfile=$(mktemp)
    echo "$content" > "$tmpfile"
    echo "$tmpfile"
}

test_custom_rules_validate_rules_file() {
    log_test "Testing rules file validation..."

    local rules="
# Valid rules
high|PermitRootLogin|eq|no|Root login must be disabled
critical|PermitEmptyPasswords|eq|no|Empty passwords must be disabled
medium|X11Forwarding|eq|no|X11 forwarding must be disabled
"
    local tmpfile
    tmpfile=$(create_rules_file "$rules")
    TEMP_FILES+=("$tmpfile")

    if validate_rules_file "$tmpfile"; then
        log_pass "Rules file validation"
    else
        log_fail "Rules file validation"
    fi
}

test_custom_rules_invalid_rules_file() {
    log_test "Testing invalid rules file detection..."

    local rules="
bad_severity|PermitRootLogin|eq|no|Bad severity
high|PermitRootLogin|badop|no|Bad operator
"
    local tmpfile
    tmpfile=$(create_rules_file "$rules")
    TEMP_FILES+=("$tmpfile")

    if ! validate_rules_file "$tmpfile"; then
        log_pass "Invalid rules file detection"
    else
        log_fail "Invalid rules file detection"
    fi
}

test_custom_rules_eq_operator() {
    log_test "Testing custom rule eq operator..."

    ISSUES=()
    declare -A ISSUE_COUNTS=([critical]=0 [high]=0 [medium]=0 [low]=0 [info]=0)

    local config="PermitRootLogin yes"
    local tmpfile
    tmpfile=$(create_temp_file "$config")
    TEMP_FILES+=("$tmpfile")

    local rules="high|PermitRootLogin|eq|no|Root login must be disabled"
    local rules_file
    rules_file=$(create_rules_file "$rules")
    TEMP_FILES+=("$rules_file")

    run_custom_rules "$tmpfile" "$rules_file"

    if [[ ${ISSUE_COUNTS[high]} -eq 1 ]]; then
        log_pass "Custom rule eq operator (violation)"
    else
        log_fail "Custom rule eq operator (expected 1 high issue)"
    fi
}

test_custom_rules_neq_operator() {
    log_test "Testing custom rule neq operator..."

    ISSUES=()
    declare -A ISSUE_COUNTS=([critical]=0 [high]=0 [medium]=0 [low]=0 [info]=0)

    local config="PermitRootLogin yes"
    local tmpfile
    tmpfile=$(create_temp_file "$config")
    TEMP_FILES+=("$tmpfile")

    local rules="high|PermitRootLogin|neq|yes|Root login must not be yes"
    local rules_file
    rules_file=$(create_rules_file "$rules")
    TEMP_FILES+=("$rules_file")

    run_custom_rules "$tmpfile" "$rules_file"

    if [[ ${ISSUE_COUNTS[high]} -eq 1 ]]; then
        log_pass "Custom rule neq operator (violation)"
    else
        log_fail "Custom rule neq operator (expected 1 high issue)"
    fi
}

test_custom_rules_in_operator() {
    log_test "Testing custom rule in operator..."

    ISSUES=()
    declare -A ISSUE_COUNTS=([critical]=0 [high]=0 [medium]=0 [low]=0 [info]=0)

    local config="LogLevel INFO"
    local tmpfile
    tmpfile=$(create_temp_file "$config")
    TEMP_FILES+=("$tmpfile")

    local rules="low|LogLevel|in|VERBOSE,DEBUG|LogLevel must be VERBOSE or DEBUG"
    local rules_file
    rules_file=$(create_rules_file "$rules")
    TEMP_FILES+=("$rules_file")

    run_custom_rules "$tmpfile" "$rules_file"

    if [[ ${ISSUE_COUNTS[low]} -eq 1 ]]; then
        log_pass "Custom rule in operator (violation)"
    else
        log_fail "Custom rule in operator (expected 1 low issue)"
    fi
}

test_custom_rules_notin_operator() {
    log_test "Testing custom rule notin operator..."

    ISSUES=()
    declare -A ISSUE_COUNTS=([critical]=0 [high]=0 [medium]=0 [low]=0 [info]=0)

    local config="Ciphers 3des-cbc"
    local tmpfile
    tmpfile=$(create_temp_file "$config")
    TEMP_FILES+=("$tmpfile")

    local rules="critical|Ciphers|notin|3des-cbc,aes128-cbc|Weak ciphers must not be used"
    local rules_file
    rules_file=$(create_rules_file "$rules")
    TEMP_FILES+=("$rules_file")

    run_custom_rules "$tmpfile" "$rules_file"

    if [[ ${ISSUE_COUNTS[critical]} -eq 1 ]]; then
        log_pass "Custom rule notin operator (violation)"
    else
        log_fail "Custom rule notin operator (expected 1 critical issue)"
    fi
}

test_custom_rules_exists_operator() {
    log_test "Testing custom rule exists operator..."

    ISSUES=()
    declare -A ISSUE_COUNTS=([critical]=0 [high]=0 [medium]=0 [low]=0 [info]=0)

    local config="Port 22"
    local tmpfile
    tmpfile=$(create_temp_file "$config")
    TEMP_FILES+=("$tmpfile")

    local rules="info|Banner|exists||Banner directive must be set"
    local rules_file
    rules_file=$(create_rules_file "$rules")
    TEMP_FILES+=("$rules_file")

    run_custom_rules "$tmpfile" "$rules_file"

    if [[ ${ISSUE_COUNTS[info]} -eq 1 ]]; then
        log_pass "Custom rule exists operator (violation - Banner not set)"
    else
        log_fail "Custom rule exists operator (expected 1 info issue)"
    fi
}

test_custom_rules_notexists_operator() {
    log_test "Testing custom rule notexists operator..."

    ISSUES=()
    declare -A ISSUE_COUNTS=([critical]=0 [high]=0 [medium]=0 [low]=0 [info]=0)

    local config="Banner /etc/ssh/banner"
    local tmpfile
    tmpfile=$(create_temp_file "$config")
    TEMP_FILES+=("$tmpfile")

    local rules="low|Banner|notexists||Banner directive should not be set"
    local rules_file
    rules_file=$(create_rules_file "$rules")
    TEMP_FILES+=("$rules_file")

    run_custom_rules "$tmpfile" "$rules_file"

    if [[ ${ISSUE_COUNTS[low]} -eq 1 ]]; then
        log_pass "Custom rule notexists operator (violation)"
    else
        log_fail "Custom rule notexists operator (expected 1 low issue)"
    fi
}

test_custom_rules_regex_operator() {
    log_test "Testing custom rule regex operator..."

    ISSUES=()
    declare -A ISSUE_COUNTS=([critical]=0 [high]=0 [medium]=0 [low]=0 [info]=0)

    local config="ListenAddress 192.168.1.1"
    local tmpfile
    tmpfile=$(create_temp_file "$config")
    TEMP_FILES+=("$tmpfile")

    local rules="medium|ListenAddress|regex|^127\.0\.0\.1$|Must bind to localhost"
    local rules_file
    rules_file=$(create_rules_file "$rules")
    TEMP_FILES+=("$rules_file")

    run_custom_rules "$tmpfile" "$rules_file"

    if [[ ${ISSUE_COUNTS[medium]} -eq 1 ]]; then
        log_pass "Custom rule regex operator (violation)"
    else
        log_fail "Custom rule regex operator (expected 1 medium issue)"
    fi
}

test_custom_rules_multiple_rules() {
    log_test "Testing multiple custom rules..."

    ISSUES=()
    declare -A ISSUE_COUNTS=([critical]=0 [high]=0 [medium]=0 [low]=0 [info]=0)

    local config="
PermitRootLogin yes
PasswordAuthentication yes
X11Forwarding yes
"
    local tmpfile
    tmpfile=$(create_temp_file "$config")
    TEMP_FILES+=("$tmpfile")

    local rules="
critical|PermitRootLogin|eq|no|Root login must be disabled
high|PasswordAuthentication|eq|no|Password auth must be disabled
medium|X11Forwarding|eq|no|X11 forwarding must be disabled
"
    local rules_file
    rules_file=$(create_rules_file "$rules")
    TEMP_FILES+=("$rules_file")

    run_custom_rules "$tmpfile" "$rules_file"

    local total=$((ISSUE_COUNTS[critical] + ISSUE_COUNTS[high] + ISSUE_COUNTS[medium]))

    if [[ $total -eq 3 ]]; then
        log_pass "Multiple custom rules"
    else
        log_fail "Multiple custom rules (expected 3 issues, got $total)"
    fi
}

test_custom_rules_with_comments() {
    log_test "Testing rules file with comments..."

    ISSUES=()
    declare -A ISSUE_COUNTS=([critical]=0 [high]=0 [medium]=0 [low]=0 [info]=0)

    local config="PermitRootLogin yes"
    local tmpfile
    tmpfile=$(create_temp_file "$config")
    TEMP_FILES+=("$tmpfile")

    local rules="
# This is a comment
high|PermitRootLogin|eq|no|Root login must be disabled
# Another comment
"
    local rules_file
    rules_file=$(create_rules_file "$rules")
    TEMP_FILES+=("$rules_file")

    run_custom_rules "$tmpfile" "$rules_file"

    if [[ ${ISSUE_COUNTS[high]} -eq 1 ]]; then
        log_pass "Rules file with comments"
    else
        log_fail "Rules file with comments"
    fi
}

test_custom_rules_blank_lines() {
    log_test "Testing rules file with blank lines..."

    ISSUES=()
    declare -A ISSUE_COUNTS=([critical]=0 [high]=0 [medium]=0 [low]=0 [info]=0)

    local config="PermitRootLogin yes"
    local tmpfile
    tmpfile=$(create_temp_file "$config")
    TEMP_FILES+=("$tmpfile")

    local rules="

high|PermitRootLogin|eq|no|Root login must be disabled


"
    local rules_file
    rules_file=$(create_rules_file "$rules")
    TEMP_FILES+=("$rules_file")

    run_custom_rules "$tmpfile" "$rules_file"

    if [[ ${ISSUE_COUNTS[high]} -eq 1 ]]; then
        log_pass "Rules file with blank lines"
    else
        log_fail "Rules file with blank lines"
    fi
}

test_custom_rules_severity_levels() {
    log_test "Testing all severity levels in custom rules..."

    ISSUES=()
    declare -A ISSUE_COUNTS=([critical]=0 [high]=0 [medium]=0 [low]=0 [info]=0)

    local config="PermitRootLogin yes"
    local tmpfile
    tmpfile=$(create_temp_file "$config")
    TEMP_FILES+=("$tmpfile")

    local rules="
critical|PermitRootLogin|eq|no|Critical rule
high|PermitRootLogin|eq|no|High rule
medium|PermitRootLogin|eq|no|Medium rule
low|PermitRootLogin|eq|no|Low rule
info|PermitRootLogin|eq|no|Info rule
"
    local rules_file
    rules_file=$(create_rules_file "$rules")
    TEMP_FILES+=("$rules_file")

    run_custom_rules "$tmpfile" "$rules_file"

    if [[ ${ISSUE_COUNTS[critical]} -eq 1 && \
          ${ISSUE_COUNTS[high]} -eq 1 && \
          ${ISSUE_COUNTS[medium]} -eq 1 && \
          ${ISSUE_COUNTS[low]} -eq 1 && \
          ${ISSUE_COUNTS[info]} -eq 1 ]]; then
        log_pass "All severity levels"
    else
        log_fail "All severity levels (expected 1 of each, got critical=${ISSUE_COUNTS[critical]} high=${ISSUE_COUNTS[high]} medium=${ISSUE_COUNTS[medium]} low=${ISSUE_COUNTS[low]} info=${ISSUE_COUNTS[info]})"
    fi
}

run_all_tests() {
    echo ""
    echo "========================================"
    echo "  SSH Config Auditor - Test Suite"
    echo "========================================"
    echo ""

    echo -e "${BLUE}--- Config Parser Tests ---${RESET}"
    test_parse_simple_config
    test_parse_config_with_comments
    test_parse_config_with_spaces
    test_get_directive_value
    test_has_directive
    test_parse_list
    test_normalize_directive
    echo ""

    echo -e "${BLUE}--- Malformed Entry Tests ---${RESET}"
    test_parse_malformed_entries
    test_parse_error_messages
    test_clear_parse_errors
    test_parse_valid_after_malformed
    test_validate_config_file_starting_with_digit
    test_validate_config_file_invalid_start_char
    test_parse_config_strict
    test_get_parse_error_summary
    test_full_audit_with_malformed_entries
    test_audit_severely_malformed_config
    test_audit_mixed_valid_invalid_config
    echo ""

    echo -e "${BLUE}--- Security Checks Tests ---${RESET}"
    test_check_permit_root_login_yes
    test_check_permit_root_login_no
    test_check_password_authentication
    test_check_permit_empty_passwords
    test_check_weak_ciphers
    test_check_weak_macs
    test_check_weak_kex
    test_check_protocol_v1
    test_check_strict_modes
    test_check_x11_forwarding
    echo ""

    echo -e "${BLUE}--- Reporter Tests ---${RESET}"
    test_generate_text_report
    test_generate_json_report
    test_generate_csv_report
    test_json_escape
    echo ""

    echo -e "${BLUE}--- Integration Tests ---${RESET}"
    test_full_audit_insecure_config
    test_full_audit_secure_config
    echo ""

    echo -e "${BLUE}--- Custom Rules Tests ---${RESET}"
    test_custom_rules_validate_rules_file
    test_custom_rules_invalid_rules_file
    test_custom_rules_eq_operator
    test_custom_rules_neq_operator
    test_custom_rules_in_operator
    test_custom_rules_notin_operator
    test_custom_rules_exists_operator
    test_custom_rules_notexists_operator
    test_custom_rules_regex_operator
    test_custom_rules_multiple_rules
    test_custom_rules_with_comments
    test_custom_rules_blank_lines
    test_custom_rules_severity_levels
    echo ""

    cleanup_temp_files

    echo "========================================"
    echo "  Test Summary"
    echo "========================================"
    echo -e "  Total:  ${TESTS_RUN}"
    echo -e "  ${GREEN}Passed: ${TESTS_PASSED}${RESET}"
    echo -e "  ${RED}Failed: ${TESTS_FAILED}${RESET}"
    echo "========================================"

    if [[ $TESTS_FAILED -gt 0 ]]; then
        exit 1
    fi
    exit 0
}

run_all_tests
