# Guardrails

Lessons learned from previous iterations. Read this FIRST before starting work.

## Project-Specific Rules

1. **Testing First**: All code changes require tests. Run `go test ./...` before committing.
2. **eBPF Changes**: Test on multiple kernel versions if modifying events/*.go
3. **Permissions**: Always use octal notation (0640 not 640) for file permissions
4. **No fmt.Println**: Use the output package for user-facing messages

## Signs (Lessons from Failures)

(None yet - will be added as we learn)
