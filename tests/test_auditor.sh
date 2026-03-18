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
    test_full_audit_with_malformed_entries
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
