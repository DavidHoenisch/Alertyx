#!/bin/bash
# Ralph Loop for Alertyx
# Main execution loop that runs cursor-agent repeatedly with fresh context

set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/ralph-common.sh"

# Parse arguments
MODEL="$DEFAULT_MODEL"
ITERATIONS="$MAX_ITERATIONS"
SKIP_CONFIRM=false
CREATE_BRANCH=""
OPEN_PR=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -n|--iterations) ITERATIONS="$2"; shift 2 ;;
        -m|--model) MODEL="$2"; shift 2 ;;
        -y|--yes) SKIP_CONFIRM=true; shift ;;
        --branch) CREATE_BRANCH="$2"; shift 2 ;;
        --pr) OPEN_PR=true; shift ;;
        -h|--help)
            echo "Usage: ralph-loop.sh [options]"
            echo ""
            echo "Options:"
            echo "  -n, --iterations N   Max iterations (default: $MAX_ITERATIONS)"
            echo "  -m, --model MODEL    Model to use (default: $DEFAULT_MODEL)"
            echo "  -y, --yes            Skip confirmation"
            echo "  --branch NAME        Create/use branch"
            echo "  --pr                 Open PR when complete (requires --branch)"
            exit 0
            ;;
        *) log_error "Unknown option: $1"; exit 1 ;;
    esac
done

# Pre-flight checks
check_cursor_cli || exit 1

if [[ ! -f "$TASK_FILE" ]]; then
    log_error "No RALPH_TASK.md found. Create one first or run ralph-issue.sh"
    exit 1
fi

# Initialize state
init_ralph

# Show current state
echo ""
log_info "=== Ralph Loop for Alertyx ==="
echo "Task file: $TASK_FILE"
echo "Model: $MODEL"
echo "Max iterations: $ITERATIONS"
echo "Remaining tasks: $(count_remaining_tasks)"
echo "Completed tasks: $(count_completed_tasks)"
echo ""

# Confirm start
if [[ "$SKIP_CONFIRM" != "true" ]]; then
    if ! confirm "Start Ralph loop?"; then
        log_info "Aborted"
        exit 0
    fi
fi

# Create branch if specified
if [[ -n "$CREATE_BRANCH" ]]; then
    if git show-ref --verify --quiet "refs/heads/$CREATE_BRANCH"; then
        log_info "Switching to existing branch: $CREATE_BRANCH"
        git checkout "$CREATE_BRANCH"
    else
        log_info "Creating new branch: $CREATE_BRANCH"
        git checkout -b "$CREATE_BRANCH"
    fi
fi

# Build the prompt
build_prompt() {
    local iteration=$1
    local remaining=$2
    
    cat << EOF
You are working on the Alertyx project, an eBPF-based Linux EDR tool.

## Your Task

Read RALPH_TASK.md for the current task and success criteria.
Read .ralph/guardrails.md FIRST for project rules and lessons learned.
Read .ralph/progress.md to see what's already been done.
Read AGENTS.md for project coding standards.

## Instructions

1. Pick ONE unchecked criterion from RALPH_TASK.md
2. Implement it completely with tests
3. Run \`go test ./...\` to verify
4. Commit your changes: \`git add -A && git commit -m "ralph: [criterion description]"\`
5. Update .ralph/progress.md with what you accomplished
6. Check the box in RALPH_TASK.md: change \`[ ]\` to \`[x]\`

## Important Rules

- Only work on ONE criterion per iteration
- Always run tests before committing
- If something fails repeatedly, add a Sign to .ralph/guardrails.md
- Use octal permissions (0640 not 640)
- No fmt.Println - use the output package

## Current State

- Iteration: $iteration of $ITERATIONS
- Remaining criteria: $remaining
- If all criteria are complete, output: <!-- COMPLETE -->

## Context Budget

You have ~80k tokens. Work efficiently:
- Don't read entire files if you can grep
- Focus on one criterion at a time
- Commit frequently

Start by reading RALPH_TASK.md and .ralph/guardrails.md.
EOF
}

# Main loop
CURRENT_ITERATION=$(get_iteration)

while [[ $CURRENT_ITERATION -lt $ITERATIONS ]]; do
    increment_iteration
    CURRENT_ITERATION=$(get_iteration)
    
    REMAINING=$(count_remaining_tasks)
    
    # Check if done
    if [[ "$REMAINING" -eq 0 ]]; then
        log_success "All tasks complete!"
        
        # Run final verification
        if run_verification; then
            log_success "Verification passed - Ralph complete!"
            
            # Open PR if requested
            if [[ "$OPEN_PR" == "true" && -n "$CREATE_BRANCH" ]]; then
                log_info "Pushing branch and opening PR..."
                git push -u origin "$CREATE_BRANCH"
                gh pr create --fill
            fi
            
            exit 0
        else
            log_warn "Tasks marked complete but verification failed. Continuing..."
        fi
    fi
    
    echo ""
    log_info "=== Iteration $CURRENT_ITERATION / $ITERATIONS ==="
    log_info "Remaining tasks: $REMAINING"
    echo ""
    
    # Build prompt
    PROMPT=$(build_prompt "$CURRENT_ITERATION" "$REMAINING")
    
    # Log start
    echo "[$(date '+%H:%M:%S')] Starting iteration $CURRENT_ITERATION" >> "$ACTIVITY_LOG"
    
    # Run cursor-agent; stream output live (job logs stay readable via tail -f)
    set +e
    AGENT_OUTPUT=$(mktemp)
    cursor-agent --model "$MODEL" --print "$PROMPT" 2>&1 | tee "$AGENT_OUTPUT"
    EXIT_CODE=${PIPESTATUS[0]}
    OUTPUT=$(cat "$AGENT_OUTPUT")
    rm -f "$AGENT_OUTPUT"
    set -e
    
    echo "$OUTPUT" >> "$ACTIVITY_LOG"
    
    # Log completion
    echo "[$(date '+%H:%M:%S')] Iteration $CURRENT_ITERATION completed (exit: $EXIT_CODE)" >> "$ACTIVITY_LOG"
    
    # Check for COMPLETE marker in output
    if echo "$OUTPUT" | grep -q '<!-- COMPLETE -->'; then
        log_success "Agent signaled completion!"
        
        # Run final verification
        if run_verification; then
            log_success "Verification passed - Ralph complete!"
            
            # Open PR if requested
            if [[ "$OPEN_PR" == "true" && -n "$CREATE_BRANCH" ]]; then
                log_info "Pushing branch and opening PR..."
                git push -u origin "$CREATE_BRANCH"
                gh pr create --fill
            fi
            
            exit 0
        else
            log_warn "Agent says complete but verification failed. Continuing..."
        fi
    fi
    
    # Check for errors
    if [[ $EXIT_CODE -ne 0 ]]; then
        log_warn "Agent exited with code $EXIT_CODE"
        echo "[$(date '+%H:%M:%S')] ERROR: Exit code $EXIT_CODE" >> "$ERRORS_LOG"
        
        # Check for rate limiting
        if [[ $EXIT_CODE -eq 429 ]] || grep -q "rate limit" "$ACTIVITY_LOG" 2>/dev/null; then
            log_warn "Rate limited - waiting 30 seconds..."
            sleep 30
        fi
    fi
    
    # Brief pause between iterations
    sleep 2
done

log_warn "Reached max iterations ($ITERATIONS)"
log_info "Remaining tasks: $(count_remaining_tasks)"
exit 1
