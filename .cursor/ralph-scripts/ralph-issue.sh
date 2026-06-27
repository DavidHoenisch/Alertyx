#!/bin/bash
# Ralph Issue Loader for Alertyx
# Pulls a GitHub issue and converts it to a RALPH_TASK.md

set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/ralph-common.sh"

# Parse arguments
ISSUE_NUMBER=""
PHASE=""
LIST_ONLY=false

print_usage() {
    echo "Usage: ralph-issue.sh [options]"
    echo ""
    echo "Options:"
    echo "  -i, --issue NUMBER    Load specific issue by number"
    echo "  -p, --phase PHASE     Load issues from phase (1-6)"
    echo "  -l, --list            List available issues without loading"
    echo "  -h, --help            Show this help"
    echo ""
    echo "Examples:"
    echo "  ralph-issue.sh --list                    # List all open issues"
    echo "  ralph-issue.sh --phase 1 --list         # List Phase 1 issues"
    echo "  ralph-issue.sh --issue 7                # Load issue #7"
    echo "  ralph-issue.sh --phase 1                # Interactive select from Phase 1"
}

while [[ $# -gt 0 ]]; do
    case $1 in
        -i|--issue) ISSUE_NUMBER="$2"; shift 2 ;;
        -p|--phase) PHASE="$2"; shift 2 ;;
        -l|--list) LIST_ONLY=true; shift ;;
        -h|--help) print_usage; exit 0 ;;
        *) log_error "Unknown option: $1"; print_usage; exit 1 ;;
    esac
done

# Build label filter
LABEL_FILTER=""
if [[ -n "$PHASE" ]]; then
    case "$PHASE" in
        1) LABEL_FILTER="phase-1-testing" ;;
        2) LABEL_FILTER="phase-2-bugs" ;;
        3) LABEL_FILTER="phase-3-modernization" ;;
        4) LABEL_FILTER="phase-4-features" ;;
        5) LABEL_FILTER="phase-5-quality" ;;
        6) LABEL_FILTER="phase-6-operations" ;;
        *) log_error "Invalid phase: $PHASE (use 1-6)"; exit 1 ;;
    esac
fi

# List issues
list_issues() {
    local label_arg=""
    if [[ -n "$LABEL_FILTER" ]]; then
        label_arg="--label $LABEL_FILTER"
    fi
    
    echo ""
    log_info "Open Issues${PHASE:+ (Phase $PHASE)}:"
    echo ""
    gh issue list --state open $label_arg --json number,title,labels \
        --template '{{range .}}#{{.number}} {{.title}}{{"\n"}}  Labels: {{range .labels}}{{.name}} {{end}}{{"\n\n"}}{{end}}'
}

# Get issue details
get_issue() {
    local num=$1
    gh issue view "$num" --json number,title,body,labels
}

# Convert issue to RALPH_TASK.md
issue_to_task() {
    local issue_json=$1
    
    local number=$(echo "$issue_json" | jq -r '.number')
    local title=$(echo "$issue_json" | jq -r '.title')
    local body=$(echo "$issue_json" | jq -r '.body')
    local labels=$(echo "$issue_json" | jq -r '.labels[].name' | tr '\n' ', ' | sed 's/,$//')
    
    # Determine test command based on labels
    local test_cmd="go test ./..."
    if echo "$labels" | grep -q "testing"; then
        test_cmd="go test -v ./..."
    fi
    
    cat << EOF
---
task: "Issue #$number: $title"
test_command: "$test_cmd"
github_issue: $number
---

# Issue #$number: $title

**Labels:** $labels

## Task Description

$body

## Success Criteria

EOF

    # Extract checkboxes from body if present
    if echo "$body" | grep -q '\[ \]'; then
        echo "$body" | grep -E '^\s*-?\s*\[ \]' | sed 's/^[[:space:]]*//'
    else
        # Create generic criteria from acceptance criteria section
        echo "- [ ] Implementation complete"
        echo "- [ ] Tests written and passing"
        echo "- [ ] Code reviewed against AGENTS.md standards"
        echo "- [ ] Changes committed with descriptive message"
    fi
    
    cat << EOF

## Notes

- Read AGENTS.md for coding standards
- Run \`go test ./...\` before committing
- Update .ralph/progress.md with your work
- When complete, the issue will be closed via PR

EOF
}

# Select issue interactively
select_issue() {
    local label_arg=""
    if [[ -n "$LABEL_FILTER" ]]; then
        label_arg="--label $LABEL_FILTER"
    fi
    
    # Get issues as JSON
    local issues=$(gh issue list --state open $label_arg --json number,title --limit 20)
    local count=$(echo "$issues" | jq length)
    
    if [[ "$count" -eq 0 ]]; then
        log_warn "No open issues found${PHASE:+ for Phase $PHASE}"
        exit 1
    fi
    
    if has_gum; then
        # Use gum for selection
        local selection=$(echo "$issues" | jq -r '.[] | "#\(.number) \(.title)"' | gum choose)
        echo "$selection" | grep -oP '(?<=#)\d+'
    else
        # Fallback to numbered list
        echo ""
        echo "Select an issue:"
        echo "$issues" | jq -r 'to_entries | .[] | "\(.key + 1)) #\(.value.number) \(.value.title)"'
        echo ""
        read -p "Choice: " choice
        echo "$issues" | jq -r ".[$((choice - 1))].number"
    fi
}

# Main logic
if [[ "$LIST_ONLY" == "true" ]]; then
    list_issues
    exit 0
fi

# Get issue number (from arg or interactive)
if [[ -z "$ISSUE_NUMBER" ]]; then
    log_info "No issue specified, selecting interactively..."
    ISSUE_NUMBER=$(select_issue)
fi

if [[ -z "$ISSUE_NUMBER" ]]; then
    log_error "No issue selected"
    exit 1
fi

log_info "Loading issue #$ISSUE_NUMBER..."

# Fetch issue
ISSUE_JSON=$(get_issue "$ISSUE_NUMBER")

if [[ -z "$ISSUE_JSON" ]] || [[ "$ISSUE_JSON" == "null" ]]; then
    log_error "Could not fetch issue #$ISSUE_NUMBER"
    exit 1
fi

# Check if RALPH_TASK.md already exists
if [[ -f "$TASK_FILE" ]]; then
    log_warn "RALPH_TASK.md already exists"
    if ! confirm "Overwrite?"; then
        log_info "Aborted"
        exit 0
    fi
    # Backup existing
    mv "$TASK_FILE" "$TASK_FILE.bak"
    log_info "Backed up to $TASK_FILE.bak"
fi

# Generate task file
issue_to_task "$ISSUE_JSON" > "$TASK_FILE"

log_success "Created RALPH_TASK.md for issue #$ISSUE_NUMBER"
echo ""
cat "$TASK_FILE"
echo ""

# Initialize ralph state
init_ralph

# Create branch suggestion
BRANCH_NAME="ralph/$ISSUE_NUMBER-$(echo "$ISSUE_JSON" | jq -r '.title' | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]/-/g' | sed 's/--*/-/g' | cut -c1-40)"

echo ""
log_info "Suggested next steps:"
echo "  1. Review RALPH_TASK.md and adjust criteria if needed"
echo "  2. Run: .cursor/ralph-scripts/ralph-loop.sh --branch $BRANCH_NAME"
echo ""
