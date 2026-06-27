#!/bin/bash
# Ralph Once - Single Iteration Test
# Runs one iteration to test before going AFK

set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/ralph-common.sh"

MODEL="${1:-$DEFAULT_MODEL}"

log_info "Running single Ralph iteration (model: $MODEL)"
log_info "This is for testing before running the full loop"
echo ""

# Check prerequisites
check_cursor_cli || exit 1

if [[ ! -f "$TASK_FILE" ]]; then
    log_error "No RALPH_TASK.md found"
    echo "Run ralph-issue.sh first to load an issue, or create RALPH_TASK.md manually"
    exit 1
fi

# Initialize
init_ralph

# Show current state
log_info "Task: $(grep -oP '(?<=task: ").*(?=")' "$TASK_FILE" 2>/dev/null | head -1 || echo "Custom")"
log_info "Remaining criteria: $(count_remaining_tasks)"
echo ""

# Run single iteration
"$SCRIPT_DIR/ralph-loop.sh" -m "$MODEL" -n 1 -y

echo ""
log_info "Single iteration complete. Review the changes before running full loop:"
echo "  git diff"
echo "  git log --oneline -5"
echo ""
log_info "To continue with full loop:"
echo "  .cursor/ralph-scripts/ralph-setup.sh"
