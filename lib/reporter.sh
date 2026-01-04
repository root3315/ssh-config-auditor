#!/usr/bin/env bash
#
# reporter.sh - Report generation module for SSH config auditor
#

declare -A REPORT_COLORS=(
    [reset]="\033[0m"
    [red]="\033[31m"
    [green]="\033[32m"
    [yellow]="\033[33m"
    [blue]="\033[34m"
    [magenta]="\033[35m"
    [cyan]="\033[36m"
    [bold]="\033[1m"
    [dim]="\033[2m"
)

get_severity_color() {
    local severity="$1"

    case "$severity" in
        critical) echo -e "${REPORT_COLORS[red]}${REPORT_COLORS[bold]}" ;;
        high)     echo -e "${REPORT_COLORS[red]}" ;;
        medium)   echo -e "${REPORT_COLORS[yellow]}" ;;
        low)      echo -e "${REPORT_COLORS[cyan]}" ;;
        info)     echo -e "${REPORT_COLORS[dim]}" ;;
        *)        echo -e "${REPORT_COLORS[reset]}" ;;
    esac
}

get_severity_badge() {
    local severity="$1"

    case "$severity" in
        critical) echo "[CRITICAL]" ;;
        high)     echo "[HIGH]    " ;;
        medium)   echo "[MEDIUM]  " ;;
        low)      echo "[LOW]     " ;;
        info)     echo "[INFO]    " ;;
        *)        echo "[UNKNOWN] " ;;
    esac
}

json_escape() {
    local str="$1"
    str="${str//\\/\\\\}"
    str="${str//\"/\\\"}"
    str="${str//$'\n'/\\n}"
    str="${str//$'\r'/\\r}"
    str="${str//$'\t'/\\t}"
    echo "$str"
}

csv_escape() {
    local str="$1"
    if [[ "$str" =~ [,\"\n\r] ]]; then
        str="${str//\"/\"\"}"
        str="\"$str\""
    fi
    echo "$str"
}

generate_text_report() {
    local -a issues=("$@")
    local report=""
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    report+="================================================================================\n"
    report+="                    SSH CONFIG SECURITY AUDIT REPORT\n"
    report+="================================================================================\n"
    report+="Generated: ${timestamp}\n"
    report+="\n"

    report+="--------------------------------------------------------------------------------\n"
    report+="SUMMARY\n"
    report+="--------------------------------------------------------------------------------\n"
    report+="  Critical: ${ISSUE_COUNTS[critical]}\n"
    report+="  High:     ${ISSUE_COUNTS[high]}\n"
    report+="  Medium:   ${ISSUE_COUNTS[medium]}\n"
    report+="  Low:      ${ISSUE_COUNTS[low]}\n"
    report+="  Info:     ${ISSUE_COUNTS[info]}\n"
    report+="  --------------------------------\n"
    local total=$((ISSUE_COUNTS[critical] + ISSUE_COUNTS[high] + ISSUE_COUNTS[medium] + ISSUE_COUNTS[low] + ISSUE_COUNTS[info]))
    report+="  TOTAL:    ${total}\n"
    report+="\n"

    if [[ ${#issues[@]} -eq 0 ]]; then
        report+="No security issues found.\n"
    else
        report+="--------------------------------------------------------------------------------\n"
        report+="FINDINGS\n"
        report+="--------------------------------------------------------------------------------\n"

        for severity in critical high medium low info; do
            local severity_issues=()
            for issue in "${issues[@]}"; do
                if [[ "$issue" == "${severity}|"* ]]; then
                    severity_issues+=("$issue")
                fi
            done

            if [[ ${#severity_issues[@]} -gt 0 ]]; then
                local color
                color=$(get_severity_color "$severity")
                local reset="${REPORT_COLORS[reset]}"

                report+="\n${color}=== ${severity^^} SEVERITY ISSUES ===${reset}\n\n"

                for issue in "${severity_issues[@]}"; do
                    IFS='|' read -r sev file directive current recommended description <<< "$issue"

                    current="${current//\\|/|}"
                    recommended="${recommended//\\|/|}"
                    description="${description//\\|/|}"

                    local badge
                    badge=$(get_severity_badge "$sev")

                    report+="${color}${badge}${reset} ${directive}\n"
                    report+="  File:       ${file}\n"
                    report+="  Current:    ${current}\n"
                    report+="  Recommended: ${recommended}\n"
                    report+="  Issue:      ${description}\n"
                    report+="\n"
                done
            fi
        done
    fi

    report+="--------------------------------------------------------------------------------\n"
    report+="RECOMMENDATIONS\n"
    report+="--------------------------------------------------------------------------------\n"

    if [[ ${ISSUE_COUNTS[critical]} -gt 0 ]]; then
        report+="! CRITICAL issues must be addressed immediately.\n"
    fi

    if [[ ${ISSUE_COUNTS[high]} -gt 0 ]]; then
        report+="! HIGH severity issues should be fixed as soon as possible.\n"
    fi

    if [[ ${ISSUE_COUNTS[medium]} -gt 0 || ${ISSUE_COUNTS[low]} -gt 0 ]]; then
        report+="- Review and address MEDIUM and LOW severity issues during maintenance.\n"
    fi

    if [[ ${ISSUE_COUNTS[info]} -gt 0 ]]; then
        report+="- Consider implementing INFO suggestions for defense-in-depth.\n"
    fi

    if [[ $total -eq 0 ]]; then
        report+="Configuration appears secure. Continue regular audits.\n"
    fi

    report+="\n"
    report+="================================================================================\n"
    report+="                           END OF REPORT\n"
    report+="================================================================================\n"

    echo -e "$report"
}

generate_json_report() {
    local -a issues=("$@")
    local timestamp
    timestamp=$(date -u '+%Y-%m-%dT%H:%M:%SZ')

    local json="{\n"
    json+="  \"report\": {\n"
    json+="    \"tool\": \"ssh-config-auditor\",\n"
    json+="    \"version\": \"${VERSION:-1.0.0}\",\n"
    json+="    \"timestamp\": \"${timestamp}\",\n"
    json+="    \"summary\": {\n"
    json+="      \"critical\": ${ISSUE_COUNTS[critical]},\n"
    json+="      \"high\": ${ISSUE_COUNTS[high]},\n"
    json+="      \"medium\": ${ISSUE_COUNTS[medium]},\n"
    json+="      \"low\": ${ISSUE_COUNTS[low]},\n"
    json+="      \"info\": ${ISSUE_COUNTS[info]},\n"
    local total=$((ISSUE_COUNTS[critical] + ISSUE_COUNTS[high] + ISSUE_COUNTS[medium] + ISSUE_COUNTS[low] + ISSUE_COUNTS[info]))
    json+="      \"total\": ${total}\n"
    json+="    },\n"
    json+="    \"issues\": [\n"

    local first=1
    for issue in "${issues[@]}"; do
        IFS='|' read -r sev file directive current recommended description <<< "$issue"

        current="${current//\\|/|}"
        recommended="${recommended//\\|/|}"
        description="${description//\\|/|}"

        if [[ $first -eq 0 ]]; then
            json+=",\n"
        fi
        first=0

        json+="      {\n"
        json+="        \"severity\": \"$(json_escape "$sev")\",\n"
        json+="        \"file\": \"$(json_escape "$file")\",\n"
        json+="        \"directive\": \"$(json_escape "$directive")\",\n"
        json+="        \"current_value\": \"$(json_escape "$current")\",\n"
        json+="        \"recommended_value\": \"$(json_escape "$recommended")\",\n"
        json+="        \"description\": \"$(json_escape "$description")\"\n"
        json+="      }"
    done

    json+="\n    ]\n"
    json+="  }\n"
    json+="}\n"

    echo -e "$json"
}

generate_csv_report() {
    local -a issues=("$@")
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    echo "Timestamp,Severity,File,Directive,CurrentValue,RecommendedValue,Description"

    for issue in "${issues[@]}"; do
        IFS='|' read -r sev file directive current recommended description <<< "$issue"

        current="${current//\\|/|}"
        recommended="${recommended//\\|/|}"
        description="${description//\\|/|}"

        echo "$(csv_escape "$timestamp"),$(csv_escape "$sev"),$(csv_escape "$file"),$(csv_escape "$directive"),$(csv_escape "$current"),$(csv_escape "$recommended"),$(csv_escape "$description")"
    done
}

generate_report() {
    local -a issues=("$@")
    local format="${CONFIG[output_format]:-text}"

    case "$format" in
        json)
            generate_json_report "${issues[@]}"
            ;;
        csv)
            generate_csv_report "${issues[@]}"
            ;;
        text|*)
            generate_text_report "${issues[@]}"
            ;;
    esac
}

print_issue_summary() {
    local -a issues=("$@")

    if [[ ${#issues[@]} -eq 0 ]]; then
        echo -e "${REPORT_COLORS[green]}No security issues found.${REPORT_COLORS[reset]}" >&2
        return
    fi

    echo -e "${REPORT_COLORS[yellow]}Found ${#issues[@]} security issue(s):${REPORT_COLORS[reset]}" >&2

    for severity in critical high medium low info; do
        local count=${ISSUE_COUNTS[$severity]}
        if [[ $count -gt 0 ]]; then
            local color
            color=$(get_severity_color "$severity")
            echo -e "  ${color}${severity^^}: ${count}${REPORT_COLORS[reset]}" >&2
        fi
    done
}

print_issue_detail() {
    local severity="$1"
    local file="$2"
    local directive="$3"
    local current="$4"
    local recommended="$5"
    local description="$6"

    local color
    color=$(get_severity_color "$severity")
    local badge
    badge=$(get_severity_badge "$severity")

    echo -e "${color}${badge} ${directive}${REPORT_COLORS[reset]}" >&2
    echo -e "  File:       ${file}" >&2
    echo -e "  Current:    ${current}" >&2
    echo -e "  Recommended: ${recommended}" >&2
    echo -e "  Issue:      ${description}" >&2
    echo "" >&2
}

generate_summary_line() {
    local total=$((ISSUE_COUNTS[critical] + ISSUE_COUNTS[high] + ISSUE_COUNTS[medium] + ISSUE_COUNTS[low] + ISSUE_COUNTS[info]))

    if [[ $total -eq 0 ]]; then
        echo -e "${REPORT_COLORS[green]}PASS: No security issues found${REPORT_COLORS[reset]}"
    else
        local status="WARN"
        local color="${REPORT_COLORS[yellow]}"

        if [[ ${ISSUE_COUNTS[critical]} -gt 0 ]]; then
            status="CRITICAL"
            color="${REPORT_COLORS[red]}${REPORT_COLORS[bold]}"
        elif [[ ${ISSUE_COUNTS[high]} -gt 0 ]]; then
            status="HIGH"
            color="${REPORT_COLORS[red]}"
        elif [[ ${ISSUE_COUNTS[medium]} -gt 0 ]]; then
            status="MEDIUM"
            color="${REPORT_COLORS[yellow]}"
        fi

        echo -e "${color}${status}: ${total} issue(s) found${REPORT_COLORS[reset]}"
    fi
}
