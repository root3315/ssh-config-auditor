#!/usr/bin/env bash
#
# custom_rules.sh - Custom policy rules support for SSH config auditor
#
# Rule file format (one rule per line):
#   SEVERITY|DIRECTIVE|OPERATOR|VALUE|DESCRIPTION
#
# Fields:
#   SEVERITY   - critical, high, medium, low, info
#   DIRECTIVE  - SSH directive name (e.g. PermitRootLogin)
#   OPERATOR   - one of: eq, neq, in, notin, regex, exists, notexists
#   VALUE      - comparison value (not used for exists/notexists)
#   DESCRIPTION - human-readable explanation of the rule
#
# Lines starting with # are comments. Blank lines are ignored.
#

validate_rules_file() {
    local file="$1"

    if [[ ! -e "$file" ]]; then
        log error "Rules file not found: $file"
        return 1
    fi

    if [[ ! -f "$file" ]]; then
        log error "Not a regular file: $file"
        return 1
    fi

    if [[ ! -r "$file" ]]; then
        log error "Cannot read rules file: $file"
        return 1
    fi

    local line_num=0
    local invalid=0
    while IFS= read -r line || [[ -n "$line" ]]; do
        ((line_num++))

        line="${line#"${line%%[![:space:]]*}"}"
        line="${line%"${line##*[![:space:]]}"}"

        [[ -z "$line" ]] && continue
        [[ "$line" =~ ^# ]] && continue

        if ! _validate_rule_line "$line"; then
            log error "Invalid rule at $file:$line_num: $line"
            ((invalid++))
        fi
    done < "$file"

    if [[ $invalid -gt 0 ]]; then
        log error "Found $invalid invalid rule(s) in rules file"
        return 1
    fi

    return 0
}

_validate_rule_line() {
    local line="$1"

    local severity directive operator value

    IFS='|' read -r severity directive operator value _ <<< "$line"

    if [[ -z "$severity" || -z "$directive" || -z "$operator" ]]; then
        return 1
    fi

    case "$severity" in
        critical|high|medium|low|info) ;;
        *) return 1 ;;
    esac

    case "$operator" in
        eq|neq|in|notin|regex|exists|notexists) ;;
        *) return 1 ;;
    esac

    return 0
}

run_custom_rules() {
    local file="$1"
    local rules_file="$2"
    shift 2

    local -A directives
    while IFS='=' read -r key value; do
        [[ -z "$key" ]] && continue
        directives["$key"]="$value"
    done < <(
        while IFS= read -r line || [[ -n "$line" ]]; do
            line="${line#"${line%%[![:space:]]*}"}"
            line="${line%"${line##*[![:space:]]}"}"
            [[ -z "$line" || "$line" =~ ^# ]] && continue
            line="${line%%#*}"
            line="${line%"${line##*[![:space:]]}"}"
            [[ -z "$line" ]] && continue
            if [[ "$line" =~ ^([A-Za-z][A-Za-z0-9]*)[[:space:]]+(.*) ]]; then
                echo "${BASH_REMATCH[1]}=${BASH_REMATCH[2]}"
            elif [[ "$line" =~ ^([A-Za-z][A-Za-z0-9]*)[[:space:]]*=[[:space:]]*(.*) ]]; then
                echo "${BASH_REMATCH[1]}=${BASH_REMATCH[2]}"
            fi
        done < "$file"
    )

    local line_num=0
    while IFS= read -r line || [[ -n "$line" ]]; do
        ((line_num++))

        line="${line#"${line%%[![:space:]]*}"}"
        line="${line%"${line##*[![:space:]]}"}"

        [[ -z "$line" ]] && continue
        [[ "$line" =~ ^# ]] && continue

        local severity directive operator value description
        IFS='|' read -r severity directive operator value description <<< "$line"

        directive=$(normalize_directive "$directive")

        local current_value="${directives[$directive]:-}"

        if _evaluate_rule "$operator" "$current_value" "$value"; then
            continue
        fi

        if [[ -z "$description" ]]; then
            description="Custom rule violation: ${directive} ${operator} ${value}"
        fi

        local recommended="${value:-(unset)}"
        add_issue "$severity" "$file" "$directive" "${current_value:-(not set)}" "$recommended" "$description"

    done < "$rules_file"
}

_evaluate_rule() {
    local operator="$1"
    local current="$2"
    local expected="$3"

    local current_lower="${current,,}"
    local expected_lower="${expected,,}"

    case "$operator" in
        eq)
            [[ "$current_lower" == "$expected_lower" ]]
            ;;
        neq)
            [[ "$current_lower" != "$expected_lower" ]]
            ;;
        in)
            local item found=1
            for item in $(parse_list "$expected"); do
                if [[ "$current_lower" == "${item,,}" ]]; then
                    found=0
                    break
                fi
            done
            return $found
            ;;
        notin)
            local item
            for item in $(parse_list "$expected"); do
                if [[ "$current_lower" == "${item,,}" ]]; then
                    return 1
                fi
            done
            return 0
            ;;
        regex)
            if [[ -n "$current" ]]; then
                [[ "$current" =~ $expected ]]
            else
                return 1
            fi
            ;;
        exists)
            [[ -n "$current" ]]
            ;;
        notexists)
            [[ -z "$current" ]]
            ;;
        *)
            return 1
            ;;
    esac
}
