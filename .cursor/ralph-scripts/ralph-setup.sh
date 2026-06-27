#!/bin/bash
# Ralph Setup for Alertyx
# Interactive setup and execution of Ralph loops

set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/ralph-common.sh"

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║           Ralph Loop Setup for Alertyx                   ║"
echo "║   Autonomous agent iteration with fresh context          ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# Pre-flight checks
log_info "Checking prerequisites..."

if ! check_cursor_cli; then
    log_error "cursor-agent CLI required"
    echo "Install with: curl -fsSL https://www.cursor.com/install.sh | sh"
    exit 1
fi
log_success "cursor-agent CLI found"

if ! command -v gh &> /dev/null; then
    log_warn "GitHub CLI (gh) not found - issue integration disabled"
else
    log_success "GitHub CLI found"
fi

if has_gum; then
    log_success "gum found (enhanced UI enabled)"
else
    log_info "gum not found (using basic UI)"
    echo "  Install gum for better experience: brew install gum"
fi

echo ""

# Step 1: Task selection
log_info "Step 1: Select task source"
echo ""

if has_gum; then
    TASK_SOURCE=$(gum choose \
        "Load from GitHub Issue" \
        "Use existing RALPH_TASK.md" \
        "Create new task manually")
else
    echo "1) Load from GitHub Issue"
    echo "2) Use existing RALPH_TASK.md"
    echo "3) Create new task manually"
    read -p "Choice [1]: " choice
    case "${choice:-1}" in
        1) TASK_SOURCE="Load from GitHub Issue" ;;
        2) TASK_SOURCE="Use existing RALPH_TASK.md" ;;
        3) TASK_SOURCE="Create new task manually" ;;
    esac
fi

case "$TASK_SOURCE" in
    "Load from GitHub Issue")
        if ! command -v gh &> /dev/null; then
            log_error "GitHub CLI required for issue loading"
            exit 1
        fi
        
        # Show phase selection
        echo ""
        log_info "Select phase (or all):"
        if has_gum; then
            PHASE=$(gum choose \
                "All phases" \
                "Phase 1: Testing" \
                "Phase 2: Bugs" \
                "Phase 3: Modernization" \
                "Phase 4: Features" \
                "Phase 5: Quality" \
                "Phase 6: Operations")
            PHASE_NUM=$(echo "$PHASE" | grep -oP '(?<=Phase )\d' || echo "")
        else
            echo "0) All phases"
            echo "1) Phase 1: Testing"
            echo "2) Phase 2: Bugs"
            echo "3) Phase 3: Modernization"
            echo "4) Phase 4: Features"
            echo "5) Phase 5: Quality"
            echo "6) Phase 6: Operations"
            read -p "Choice [0]: " PHASE_NUM
            PHASE_NUM="${PHASE_NUM:-0}"
            [[ "$PHASE_NUM" == "0" ]] && PHASE_NUM=""
        fi
        
        # Run issue selector
        PHASE_ARG=""
        [[ -n "$PHASE_NUM" ]] && PHASE_ARG="--phase $PHASE_NUM"
        "$SCRIPT_DIR/ralph-issue.sh" $PHASE_ARG
        ;;
        
    "Use existing RALPH_TASK.md")
        if [[ ! -f "$TASK_FILE" ]]; then
            log_error "No RALPH_TASK.md found"
            exit 1
        fi
        log_success "Using existing $TASK_FILE"
        ;;
        
    "Create new task manually")
        log_info "Creating new RALPH_TASK.md..."
        cat > "$TASK_FILE" << 'EOF'
---
task: "Your task title here"
test_command: "go test ./..."
---

# Task: Your Task Title

## Description

Describe what needs to be done.

## Success Criteria

- [ ] First criterion
- [ ] Second criterion
- [ ] Tests pass
- [ ] Code follows AGENTS.md standards

## Notes

Add any relevant context here.
EOF
        log_success "Created $TASK_FILE - please edit it before continuing"
        ${EDITOR:-nano} "$TASK_FILE"
        ;;
esac

# Verify task file exists
if [[ ! -f "$TASK_FILE" ]]; then
    log_error "No task file found"
    exit 1
fi

echo ""
log_info "Current task:"
head -20 "$TASK_FILE"
echo "..."
echo ""

# Step 2: Model selection
log_info "Step 2: Select model"
MODEL=$(select_model)
log_success "Using model: $MODEL"

# Step 3: Options
echo ""
log_info "Step 3: Configure options"

if has_gum; then
    ITERATIONS=$(gum input --placeholder "Max iterations" --value "20")
else
    read -p "Max iterations [20]: " ITERATIONS
    ITERATIONS="${ITERATIONS:-20}"
fi

# Branch option
CREATE_BRANCH=""
OPEN_PR=false

if has_gum; then
    if gum confirm "Create a new branch for this work?"; then
        # Suggest branch name from task
        TASK_TITLE=$(grep -oP '(?<=task: ").*(?=")' "$TASK_FILE" 2>/dev/null | head -1 || echo "ralph-task")
        SUGGESTED_BRANCH="ralph/$(echo "$TASK_TITLE" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]/-/g' | cut -c1-40)"
        CREATE_BRANCH=$(gum input --placeholder "Branch name" --value "$SUGGESTED_BRANCH")
        
        if gum confirm "Open PR when complete?"; then
            OPEN_PR=true
        fi
    fi
else
    read -p "Create branch? (name or empty to skip): " CREATE_BRANCH
    if [[ -n "$CREATE_BRANCH" ]]; then
        read -p "Open PR when complete? [y/N]: " pr_response
        [[ "$pr_response" =~ ^[Yy] ]] && OPEN_PR=true
    fi
fi

# Step 4: Confirm and run
echo ""
log_info "=== Configuration Summary ==="
echo "Task: $(grep -oP '(?<=task: ").*(?=")' "$TASK_FILE" 2>/dev/null | head -1 || echo "Custom")"
echo "Model: $MODEL"
echo "Max iterations: $ITERATIONS"
echo "Remaining criteria: $(count_remaining_tasks)"
[[ -n "$CREATE_BRANCH" ]] && echo "Branch: $CREATE_BRANCH"
[[ "$OPEN_PR" == "true" ]] && echo "Will open PR when complete"
echo ""

if ! confirm "Start Ralph loop?"; then
    log_info "Aborted"
    exit 0
fi

# Build command
CMD="$SCRIPT_DIR/ralph-loop.sh -m $MODEL -n $ITERATIONS -y"
[[ -n "$CREATE_BRANCH" ]] && CMD="$CMD --branch $CREATE_BRANCH"
[[ "$OPEN_PR" == "true" ]] && CMD="$CMD --pr"

# Run!
echo ""
log_info "Starting Ralph loop..."
exec $CMD
