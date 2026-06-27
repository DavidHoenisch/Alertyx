#!/bin/bash
# Ralph Common Functions for Alertyx
# Shared utilities for Ralph loop scripts

set -eo pipefail

# Configuration
MAX_ITERATIONS="${MAX_ITERATIONS:-20}"
WARN_THRESHOLD="${WARN_THRESHOLD:-70000}"
ROTATE_THRESHOLD="${ROTATE_THRESHOLD:-80000}"
DEFAULT_MODEL="${RALPH_MODEL:-composer-2.5-fast}"

# Paths
RALPH_DIR=".ralph"
TASK_FILE="RALPH_TASK.md"
PROGRESS_FILE="$RALPH_DIR/progress.md"
GUARDRAILS_FILE="$RALPH_DIR/guardrails.md"
ACTIVITY_LOG="$RALPH_DIR/activity.log"
ERRORS_LOG="$RALPH_DIR/errors.log"
ITERATION_FILE="$RALPH_DIR/.iteration"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${CYAN}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Initialize Ralph state files
init_ralph() {
    mkdir -p "$RALPH_DIR"
    
    if [[ ! -f "$PROGRESS_FILE" ]]; then
        cat > "$PROGRESS_FILE" << 'EOF'
# Progress Log

This file tracks progress across Ralph iterations. Updated by the agent after each work session.

## Completed Work

(None yet)

## Current Status

Starting fresh.
EOF
    fi
    
    if [[ ! -f "$GUARDRAILS_FILE" ]]; then
        cat > "$GUARDRAILS_FILE" << 'EOF'
# Guardrails

Lessons learned from previous iterations. Read this FIRST before starting work.

## Project-Specific Rules

1. **Testing First**: All code changes require tests. Run `go test ./...` before committing.
2. **eBPF Changes**: Test on multiple kernel versions if modifying events/*.go
3. **Permissions**: Always use octal notation (0640 not 640) for file permissions
4. **No fmt.Println**: Use the output package for user-facing messages

## Signs (Lessons from Failures)

(None yet - will be added as we learn)
EOF
    fi
    
    if [[ ! -f "$ACTIVITY_LOG" ]]; then
        echo "# Activity Log - $(date)" > "$ACTIVITY_LOG"
    fi
    
    if [[ ! -f "$ERRORS_LOG" ]]; then
        echo "# Error Log - $(date)" > "$ERRORS_LOG"
    fi
    
    if [[ ! -f "$ITERATION_FILE" ]]; then
        echo "0" > "$ITERATION_FILE"
    fi
}

# Get current iteration number
get_iteration() {
    if [[ -f "$ITERATION_FILE" ]]; then
        cat "$ITERATION_FILE"
    else
        echo "0"
    fi
}

# Increment iteration
increment_iteration() {
    local current=$(get_iteration)
    echo $((current + 1)) > "$ITERATION_FILE"
}

# Count unchecked boxes in task file
count_remaining_tasks() {
    local count=0
    if [[ -f "$TASK_FILE" ]]; then
        count=$(grep -c '\[ \]' "$TASK_FILE" 2>/dev/null || true)
    fi
    # Ensure we return a clean integer
    echo "${count:-0}" | tr -d '[:space:]' | head -1
}

# Count completed boxes
count_completed_tasks() {
    local count=0
    if [[ -f "$TASK_FILE" ]]; then
        count=$(grep -c '\[x\]' "$TASK_FILE" 2>/dev/null || true)
    fi
    # Ensure we return a clean integer
    echo "${count:-0}" | tr -d '[:space:]' | head -1
}

# Check if all tasks are complete
all_tasks_complete() {
    local remaining=$(count_remaining_tasks)
    [[ "$remaining" -eq 0 ]]
}

# Run verification command if specified in task file
run_verification() {
    local test_cmd=$(grep -oP '(?<=test_command: ").*(?=")' "$TASK_FILE" 2>/dev/null || echo "")
    if [[ -n "$test_cmd" ]]; then
        log_info "Running verification: $test_cmd"
        if eval "$test_cmd"; then
            log_success "Verification passed"
            return 0
        else
            log_warn "Verification failed"
            return 1
        fi
    fi
    return 0
}

# Check if cursor-agent CLI is installed
check_cursor_cli() {
    if ! command -v cursor-agent &> /dev/null; then
        log_error "cursor-agent CLI not found"
        echo "Install with: curl -fsSL https://www.cursor.com/install.sh | sh"
        return 1
    fi
    return 0
}

# Check if gum is installed (for pretty UI)
has_gum() {
    command -v gum &> /dev/null
}

# Select model (with gum if available)
select_model() {
    if has_gum; then
        gum choose \
            "composer-2.5-fast" \
            "claude-4.6-sonnet-medium-thinking" \
            "claude-opus-4-8-thinking-high" \
            "gpt-5.3-codex" \
            "gpt-5.5-medium" \
            "Custom..."
    else
        echo "Select model:"
        echo "1) composer-2.5-fast (default)"
        echo "2) claude-4.6-sonnet-medium-thinking"
        echo "3) claude-opus-4-8-thinking-high"
        echo "4) gpt-5.3-codex"
        echo "5) gpt-5.5-medium"
        echo "6) Custom"
        read -p "Choice [1]: " choice
        case "${choice:-1}" in
            1) echo "composer-2.5-fast" ;;
            2) echo "claude-4.6-sonnet-medium-thinking" ;;
            3) echo "claude-opus-4-8-thinking-high" ;;
            4) echo "gpt-5.3-codex" ;;
            5) echo "gpt-5.5-medium" ;;
            6) read -p "Model name: " custom; echo "$custom" ;;
            *) echo "composer-2.5-fast" ;;
        esac
    fi
}

# Prompt input (with gum if available)
prompt_input() {
    local prompt="$1"
    local default="${2:-}"
    
    if has_gum; then
        gum input --placeholder "$prompt" --value "$default"
    else
        read -p "$prompt [$default]: " value
        echo "${value:-$default}"
    fi
}

# Confirm action (with gum if available)
confirm() {
    local prompt="$1"
    
    if has_gum; then
        gum confirm "$prompt"
    else
        read -p "$prompt [y/N]: " response
        [[ "$response" =~ ^[Yy] ]]
    fi
}
