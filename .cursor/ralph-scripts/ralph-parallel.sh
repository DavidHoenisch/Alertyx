#!/bin/bash
# Ralph Parallel Runner for Alertyx
# Runs multiple agents concurrently on different issues using git worktrees

set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/ralph-common.sh"

# Configuration
PHASE=""
MODEL="$DEFAULT_MODEL"
ITERATIONS_PER_ISSUE="${ITERATIONS_PER_ISSUE:-20}"
MAX_PARALLEL="${MAX_PARALLEL:-3}"
SKIP_CONFIRM=false
OPEN_PRS=false
PRIORITY_ONLY=false
DRY_RUN=false
NO_MERGE=false

print_usage() {
    echo "Usage: ralph-parallel.sh --phase N [options]"
    echo ""
    echo "Run multiple agents in parallel on different issues using git worktrees."
    echo "Each agent works in isolation, then branches are merged."
    echo ""
    echo "Options:"
    echo "  -p, --phase N           Phase number (1-6) - REQUIRED"
    echo "  -j, --parallel N        Max parallel agents (default: 3)"
    echo "  -m, --model MODEL       Model to use (default: $DEFAULT_MODEL)"
    echo "  -n, --iterations N      Max iterations per issue (default: 20)"
    echo "  --priority              Only work on priority-critical and priority-high issues"
    echo "  --pr                    Open single integration PR when complete"
    echo "  --no-merge              Keep branches separate (don't auto-merge)"
    echo "  --dry-run               Show what would be done without doing it"
    echo "  -y, --yes               Skip confirmations"
    echo "  -h, --help              Show this help"
    echo ""
    echo "Examples:"
    echo "  ralph-parallel.sh --phase 1 -j 4              # 4 parallel agents on Phase 1"
    echo "  ralph-parallel.sh --phase 1 --priority -j 2  # 2 agents, priority only"
    echo "  ralph-parallel.sh --phase 2 --pr -y          # Phase 2, open PR, no prompts"
}

while [[ $# -gt 0 ]]; do
    case $1 in
        -p|--phase) PHASE="$2"; shift 2 ;;
        -j|--parallel) MAX_PARALLEL="$2"; shift 2 ;;
        -m|--model) MODEL="$2"; shift 2 ;;
        -n|--iterations) ITERATIONS_PER_ISSUE="$2"; shift 2 ;;
        --priority) PRIORITY_ONLY=true; shift ;;
        --pr) OPEN_PRS=true; shift ;;
        --no-merge) NO_MERGE=true; shift ;;
        --dry-run) DRY_RUN=true; shift ;;
        -y|--yes) SKIP_CONFIRM=true; shift ;;
        -h|--help) print_usage; exit 0 ;;
        *) log_error "Unknown option: $1"; print_usage; exit 1 ;;
    esac
done

# Validate phase
if [[ -z "$PHASE" ]]; then
    log_error "Phase is required"
    print_usage
    exit 1
fi

case "$PHASE" in
    1) PHASE_LABEL="phase-1-testing"; PHASE_NAME="Testing Foundation" ;;
    2) PHASE_LABEL="phase-2-bugs"; PHASE_NAME="Critical Bugs" ;;
    3) PHASE_LABEL="phase-3-modernization"; PHASE_NAME="Library Modernization" ;;
    4) PHASE_LABEL="phase-4-features"; PHASE_NAME="Feature Completion" ;;
    5) PHASE_LABEL="phase-5-quality"; PHASE_NAME="Code Quality" ;;
    6) PHASE_LABEL="phase-6-operations"; PHASE_NAME="Operational Improvements" ;;
    *) log_error "Invalid phase: $PHASE (use 1-6)"; exit 1 ;;
esac

# Check prerequisites
check_cursor_cli || exit 1

if ! command -v gh &> /dev/null; then
    log_error "GitHub CLI (gh) required"
    exit 1
fi

# Get repo root
REPO_ROOT=$(git rev-parse --show-toplevel)
WORKTREE_DIR="$REPO_ROOT/.ralph-worktrees"
RUN_ID=$(date +%s)

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║         Ralph Parallel Runner for Alertyx                ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
log_info "Phase $PHASE: $PHASE_NAME"
log_info "Max parallel agents: $MAX_PARALLEL"
echo ""

# Get issues for this phase
log_info "Fetching issues..."

if [[ "$PRIORITY_ONLY" == "true" ]]; then
    ISSUES_JSON=$(gh issue list --state open --label "$PHASE_LABEL" --label "priority-critical" --json number,title --limit 50)
    ISSUES_HIGH=$(gh issue list --state open --label "$PHASE_LABEL" --label "priority-high" --json number,title --limit 50)
    ISSUES_JSON=$(echo "$ISSUES_JSON $ISSUES_HIGH" | jq -s 'add | unique_by(.number)')
else
    ISSUES_JSON=$(gh issue list --state open --label "$PHASE_LABEL" --json number,title --limit 50)
fi

ISSUE_COUNT=$(echo "$ISSUES_JSON" | jq length)

if [[ "$ISSUE_COUNT" -eq 0 ]]; then
    log_success "No open issues in Phase $PHASE!"
    exit 0
fi

log_info "Found $ISSUE_COUNT open issues:"
echo ""
echo "$ISSUES_JSON" | jq -r '.[] | "  #\(.number) \(.title)"'
echo ""

# Configuration summary
log_info "Configuration:"
echo "  Model: $MODEL"
echo "  Parallel agents: $MAX_PARALLEL"
echo "  Iterations per issue: $ITERATIONS_PER_ISSUE"
echo "  Open PR: $OPEN_PRS"
echo "  Auto-merge: $([[ "$NO_MERGE" == "true" ]] && echo "No" || echo "Yes")"
echo ""

if [[ "$DRY_RUN" == "true" ]]; then
    log_info "DRY RUN - would process these issues in parallel"
    log_info "Worktrees would be created in: $WORKTREE_DIR"
    exit 0
fi

# Confirm
if [[ "$SKIP_CONFIRM" != "true" ]]; then
    if ! confirm "Start $MAX_PARALLEL parallel agents on Phase $PHASE ($ISSUE_COUNT issues)?"; then
        log_info "Aborted"
        exit 0
    fi
fi

# Get default branch
DEFAULT_BRANCH=$(git symbolic-ref refs/remotes/origin/HEAD 2>/dev/null | sed 's@^refs/remotes/origin/@@' || echo "main")

# Clean up any stale worktrees from previous runs
log_info "Cleaning up stale worktrees..."
git worktree prune 2>/dev/null || true
rm -rf "$WORKTREE_DIR" 2>/dev/null || true

# Check for uncommitted changes
if ! git diff --quiet || ! git diff --cached --quiet; then
    log_warn "You have uncommitted changes in your working directory."
    echo ""
    git status --short
    echo ""
    
    if [[ "$SKIP_CONFIRM" == "true" ]]; then
        log_info "Stashing changes automatically..."
        git stash push -m "ralph-parallel: auto-stash before run $RUN_ID"
        STASHED=true
    else
        echo "Options:"
        echo "  1) Stash changes (recommended)"
        echo "  2) Commit changes first"
        echo "  3) Abort"
        read -p "Choice [1]: " stash_choice
        case "${stash_choice:-1}" in
            1)
                git stash push -m "ralph-parallel: auto-stash before run $RUN_ID"
                STASHED=true
                log_success "Changes stashed"
                ;;
            2)
                log_info "Please commit your changes and re-run"
                exit 0
                ;;
            *)
                log_info "Aborted"
                exit 0
                ;;
        esac
    fi
else
    STASHED=false
fi

# Make sure we're up to date
log_info "Updating $DEFAULT_BRANCH..."
git checkout "$DEFAULT_BRANCH" 2>/dev/null || git checkout main 2>/dev/null || git checkout master
git pull --ff-only || git pull --rebase || true

# Create worktree directory
mkdir -p "$WORKTREE_DIR"
mkdir -p "$REPO_ROOT/.ralph/parallel/$RUN_ID"

# Integration branch for merging results
INTEGRATION_BRANCH="ralph/phase-$PHASE-$RUN_ID"
if [[ "$NO_MERGE" != "true" ]]; then
    git checkout -b "$INTEGRATION_BRANCH"
    git checkout "$DEFAULT_BRANCH"
fi

# Track jobs - initialize arrays
declare -A JOB_PIDS=()
declare -A JOB_ISSUES=()
declare -A JOB_BRANCHES=()
declare -A JOB_WORKTREES=()

COMPLETED_ISSUES=()
FAILED_ISSUES=()
ACTIVE_JOBS=0

# Function to run a single agent in a worktree
run_agent() {
    local issue_num=$1
    local issue_title=$2
    local job_id=$3
    
    # Include run ID in branch name to avoid conflicts with previous runs
    local branch_name="ralph/$RUN_ID-$issue_num"
    local worktree_path="$WORKTREE_DIR/$RUN_ID-job$job_id"
    local log_file="$REPO_ROOT/.ralph/parallel/$RUN_ID/job$job_id.log"
    
    {
        echo "[Job $job_id] Starting issue #$issue_num in $worktree_path"
        echo "[Job $job_id] Branch: $branch_name"
        echo "[Job $job_id] Time: $(date)"
        echo ""
        
        # Create worktree
        echo "[Job $job_id] Creating worktree..."
        if ! git worktree add -b "$branch_name" "$worktree_path" "$DEFAULT_BRANCH" 2>&1; then
            echo "[Job $job_id] ERROR: Failed to create worktree"
            return 1
        fi
        
        # Copy ralph scripts to worktree
        echo "[Job $job_id] Setting up ralph in worktree..."
        mkdir -p "$worktree_path/.cursor"
        cp -r "$REPO_ROOT/.cursor/ralph-scripts" "$worktree_path/.cursor/"
        
        # Initialize ralph state in worktree
        mkdir -p "$worktree_path/.ralph"
        cp "$REPO_ROOT/.ralph/guardrails.md" "$worktree_path/.ralph/" 2>/dev/null || true
        echo "0" > "$worktree_path/.ralph/.iteration"
        
        # Load issue in worktree
        echo "[Job $job_id] Loading issue #$issue_num..."
        cd "$worktree_path"
        if ! RALPH_SKIP_CONFIRM=1 "$worktree_path/.cursor/ralph-scripts/ralph-issue.sh" --issue "$issue_num" -y 2>&1; then
            echo "[Job $job_id] ERROR: Failed to load issue"
            cd "$REPO_ROOT"
            return 1
        fi
        
        # Run the loop
        echo "[Job $job_id] Starting ralph loop..."
        echo ""
        "$worktree_path/.cursor/ralph-scripts/ralph-loop.sh" \
            -m "$MODEL" \
            -n "$ITERATIONS_PER_ISSUE" \
            -y 2>&1
        
        local exit_code=$?
        
        echo ""
        echo "[Job $job_id] Completed with exit code $exit_code"
        echo "[Job $job_id] End time: $(date)"
        
        cd "$REPO_ROOT"
        return $exit_code
    } >> "$log_file" 2>&1
}

# Process issues in batches
ISSUE_NUMBERS=($(echo "$ISSUES_JSON" | jq -r '.[].number'))
TOTAL_ISSUES=${#ISSUE_NUMBERS[@]}
CURRENT_INDEX=0
JOB_COUNTER=0

log_info "Starting parallel processing..."
log_info "Logs: .ralph/parallel/$RUN_ID/"
echo ""
echo "Tip: Monitor logs in another terminal with:"
echo "  tail -f .ralph/parallel/$RUN_ID/*.log"
echo ""

while [[ $CURRENT_INDEX -lt $TOTAL_ISSUES ]] || [[ $ACTIVE_JOBS -gt 0 ]]; do
    
    # Start new jobs if we have capacity and issues remaining
    while [[ $ACTIVE_JOBS -lt $MAX_PARALLEL ]] && [[ $CURRENT_INDEX -lt $TOTAL_ISSUES ]]; do
        ISSUE_NUM=${ISSUE_NUMBERS[$CURRENT_INDEX]}
        ISSUE_TITLE=$(echo "$ISSUES_JSON" | jq -r ".[] | select(.number == $ISSUE_NUM) | .title")
        JOB_ID=$((++JOB_COUNTER))
        
        log_info "Starting Job $JOB_ID: Issue #$ISSUE_NUM - $ISSUE_TITLE"
        
        # Run in background
        run_agent "$ISSUE_NUM" "$ISSUE_TITLE" "$JOB_ID" &
        JOB_PIDS[$JOB_ID]=$!
        JOB_ISSUES[$JOB_ID]=$ISSUE_NUM
        JOB_BRANCHES[$JOB_ID]="ralph/$RUN_ID-$ISSUE_NUM"
        JOB_WORKTREES[$JOB_ID]="$WORKTREE_DIR/$RUN_ID-job$JOB_ID"
        
        ((ACTIVE_JOBS++)) || true
        ((CURRENT_INDEX++)) || true
        
        # Small delay between starting jobs to avoid race conditions
        sleep 2
    done
    
    # Show status
    if [[ $ACTIVE_JOBS -gt 0 ]]; then
        log_info "Active jobs: $ACTIVE_JOBS | Completed: ${#COMPLETED_ISSUES[@]} | Failed: ${#FAILED_ISSUES[@]} | Remaining: $((TOTAL_ISSUES - CURRENT_INDEX))"
    fi
    
    # Check for completed jobs
    if [[ $ACTIVE_JOBS -gt 0 ]] && [[ ${#JOB_PIDS[@]} -gt 0 ]]; then
        for job_id in "${!JOB_PIDS[@]}"; do
            pid=${JOB_PIDS[$job_id]}
            
            # Check if process is still running
            if ! kill -0 "$pid" 2>/dev/null; then
                # Process completed, get exit code
                wait "$pid" || true
                exit_code=$?
                
                issue_num=${JOB_ISSUES[$job_id]}
                branch_name=${JOB_BRANCHES[$job_id]}
                worktree_path=${JOB_WORKTREES[$job_id]}
                
                if [[ $exit_code -eq 0 ]]; then
                    log_success "Job $job_id completed: Issue #$issue_num"
                    COMPLETED_ISSUES+=("$issue_num")
                    
                    # Merge to integration branch if enabled
                    if [[ "$NO_MERGE" != "true" ]]; then
                        log_info "Merging $branch_name to $INTEGRATION_BRANCH..."
                        git checkout "$INTEGRATION_BRANCH"
                        
                        # Try merge - if conflicts occur, try to resolve known-conflicting files
                        if git merge "$branch_name" -m "ralph: merge issue #$issue_num" 2>/dev/null; then
                            log_success "Merged successfully"
                        else
                            # Check if conflicts are only in ralph-specific files we can auto-resolve
                            CONFLICT_FILES=$(git diff --name-only --diff-filter=U 2>/dev/null || true)
                            RESOLVABLE=true
                            
                            for file in $CONFLICT_FILES; do
                                case "$file" in
                                    .ralph/*|RALPH_TASK.md)
                                        # These are per-issue files, take theirs (the branch being merged)
                                        git checkout --theirs "$file" 2>/dev/null || true
                                        git add "$file" 2>/dev/null || true
                                        ;;
                                    *)
                                        # Real conflict in actual code
                                        RESOLVABLE=false
                                        ;;
                                esac
                            done
                            
                            if [[ "$RESOLVABLE" == "true" ]] && [[ -n "$CONFLICT_FILES" ]]; then
                                # All conflicts resolved, complete the merge
                                git commit -m "ralph: merge issue #$issue_num (auto-resolved ralph files)" 2>/dev/null || true
                                log_success "Merged with auto-resolved conflicts"
                            else
                                log_warn "Merge conflict in code files - keeping branch separate"
                                git merge --abort || true
                            fi
                        fi
                        git checkout "$DEFAULT_BRANCH"
                    fi
                else
                    log_warn "Job $job_id failed: Issue #$issue_num (exit code: $exit_code)"
                    FAILED_ISSUES+=("$issue_num")
                fi
                
                # Cleanup worktree
                log_info "Cleaning up worktree for job $job_id..."
                git worktree remove "$worktree_path" --force 2>/dev/null || true
                
                # Remove from tracking
                unset 'JOB_PIDS[$job_id]'
                unset 'JOB_ISSUES[$job_id]'
                unset 'JOB_BRANCHES[$job_id]'
                unset 'JOB_WORKTREES[$job_id]'
                ((ACTIVE_JOBS--)) || true
            fi
        done
        
        # Brief sleep before checking again
        sleep 5
    fi
done

# Cleanup worktree directory
rmdir "$WORKTREE_DIR" 2>/dev/null || true

# Summary
echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║              Phase $PHASE Parallel Summary                   ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

log_info "Run ID: $RUN_ID"
log_info "Logs: .ralph/parallel/$RUN_ID/"
echo ""

COMPLETED_COUNT=${#COMPLETED_ISSUES[@]}
FAILED_COUNT=${#FAILED_ISSUES[@]}

if [[ $COMPLETED_COUNT -gt 0 ]]; then
    log_success "Completed ($COMPLETED_COUNT):"
    for num in "${COMPLETED_ISSUES[@]}"; do
        echo "  - Issue #$num"
    done
fi

if [[ $FAILED_COUNT -gt 0 ]]; then
    echo ""
    log_warn "Failed/Incomplete ($FAILED_COUNT):"
    for num in "${FAILED_ISSUES[@]}"; do
        echo "  - Issue #$num (see .ralph/parallel/$RUN_ID/)"
    done
fi

# Open PR if requested
if [[ "$OPEN_PRS" == "true" && "$NO_MERGE" != "true" && $COMPLETED_COUNT -gt 0 ]]; then
    echo ""
    log_info "Opening PR for integration branch..."
    git checkout "$INTEGRATION_BRANCH"
    git push -u origin "$INTEGRATION_BRANCH"
    
    # Build PR body
    PR_COMPLETED=""
    for num in "${COMPLETED_ISSUES[@]}"; do
        PR_COMPLETED="${PR_COMPLETED}- Closes #$num
"
    done
    
    PR_FAILED="None"
    if [[ $FAILED_COUNT -gt 0 ]]; then
        PR_FAILED=""
        for num in "${FAILED_ISSUES[@]}"; do
            PR_FAILED="${PR_FAILED}- #$num (needs manual attention)
"
        done
    fi

    gh pr create \
        --title "Ralph: Phase $PHASE - $PHASE_NAME" \
        --body "## Phase $PHASE: $PHASE_NAME

### Completed Issues
$PR_COMPLETED
### Failed Issues
$PR_FAILED
---
*Generated by Ralph parallel runner*" \
        --base "$DEFAULT_BRANCH"
    
    git checkout "$DEFAULT_BRANCH"
fi

echo ""
REMAINING=$(gh issue list --state open --label "$PHASE_LABEL" --json number | jq length)
log_info "Remaining open issues in Phase $PHASE: $REMAINING"

if [[ $FAILED_COUNT -eq 0 && "$REMAINING" -eq 0 ]]; then
    log_success "Phase $PHASE complete!"
elif [[ "$REMAINING" -gt 0 ]]; then
    log_info "Run again to continue: ralph-parallel.sh --phase $PHASE -j $MAX_PARALLEL"
fi

# Restore stashed changes if we stashed them
if [[ "${STASHED:-false}" == "true" ]]; then
    echo ""
    log_info "Restoring stashed changes..."
    git stash pop || log_warn "Could not restore stash automatically. Run 'git stash pop' manually."
fi
