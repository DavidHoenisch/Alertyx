# Alertyx Project Roadmap

## Current State Assessment

Alertyx is a Linux eBPF-based endpoint detection tool that was abandoned mid-development. It has solid foundations but needs modernization, bug fixes, and completion of partially implemented features.

### What Works
- Basic CLI structure with cobra
- eBPF event collection for exec, open, listen, readline
- Several detection techniques (MITRE ATT&CK mapped)
- Colored terminal output
- Basic correlation engine

### What Needs Work
- Critical security bugs in mitigation code
- Copy-paste bugs in detection logic
- No test coverage
- Outdated dependencies (gobpf)
- Incomplete Hunt() implementations
- No CI/CD pipeline
- Missing configuration file support

---

## Phase 1: Test Infrastructure Foundation

**Priority: CRITICAL** - Must complete before any other work.

### Issues
- [#1] Set up unit test infrastructure with 70% coverage target
- [#2] Implement fuzz testing for event parsing
- [#3] Set up mutation testing with gremlins
- [#4] Implement CRAP analysis baseline
- [#5] Set up Vagrant-based integration testing
- [#6] Set up GitHub Actions CI pipeline

### Unit Testing Strategy
```bash
go test ./... -cover -coverprofile=coverage.out
go tool cover -html=coverage.out
```

Target packages by priority:
1. `events/` - Critical for security, complex parsing
2. `techs/` - Detection logic correctness
3. `analysis/` - Event analysis accuracy
4. `correlate/` - Correlation logic

### Fuzz Testing
Focus areas:
- Event struct parsing from eBPF maps
- Command line argument parsing
- Configuration file parsing (future)

Tools: Go's built-in fuzzing (`go test -fuzz`)

### Mutation Testing
Use [gremlins](https://github.com/go-gremlins/gremlins) to verify test effectiveness:
```bash
gremlins unleash --tags="" ./...
```

Target: <30% mutant survival rate

### CRAP Analysis
Change Risk Anti-Patterns analysis combines complexity and coverage:
- High complexity + low coverage = high CRAP score = high risk
- Use `gocyclo` for complexity, combine with coverage data

### Integration Testing
Vagrant-based VM testing for actual eBPF operations:
- Ubuntu 22.04 LTS with kernel 5.15+
- Test real eBPF program loading
- Verify event capture accuracy
- Test detection techniques against known-bad scenarios

---

## Phase 2: Critical Bug Fixes

**Priority: HIGH** - Security and correctness issues.

### Issues
- [#7] **SECURITY**: Fix L1002 Mitigate() setting /etc/shadow to 644
- [#8] Fix L1003 copy-paste bug - implement actual eBPF persistence detection
- [#9] Re-enable PPID tracking in eBPF macros
- [#10] Address PWD path resolution (disabled in kernel 7.x)

### L1002 Security Bug
Current code sets `/etc/shadow` to world-readable (644). Must change to 0640:
```go
// WRONG: os.Chmod("/etc/shadow", 0644)
// CORRECT:
os.Chmod("/etc/shadow", 0640)
```

### L1003 Copy-Paste Bug
L1003 (eBPF Module Persistence) contains L1002's logic. Needs complete rewrite to actually detect eBPF persistence.

---

## Phase 3: Modernization

**Priority: HIGH** - Technical debt and maintainability.

### Issues
- [#11] Migrate from gobpf to cilium/ebpf

### gobpf to cilium/ebpf Migration
Current: `github.com/iovisor/gobpf` (deprecated, BCC-dependent)
Target: `github.com/cilium/ebpf` (modern, CO-RE support)

Benefits:
- No BCC runtime dependency
- Better kernel compatibility (CO-RE)
- Active maintenance
- Better performance

Migration approach:
1. Create parallel implementation in new package
2. Migrate one event type at a time
3. Verify identical behavior with integration tests
4. Remove gobpf dependency

---

## Phase 4: Feature Completion

**Priority: MEDIUM** - Complete partially implemented features.

### Issues
- [#12] Implement T1547 Kernel Module Persistence detection
- [#13] Implement Hunt() methods for all techniques

### Hunt() Methods
Each technique should support artifact hunting (scanning without real-time monitoring):
- Search filesystem for IOCs
- Check running processes
- Examine system configuration

---

## Phase 6: Production Readiness

**Priority: MEDIUM** - Operational features for real-world deployment.

### Issues
- [#14] Add YAML configuration file support
- [#15] Add JSON structured output for SIEM integration
- [#16] Create systemd service file for production deployment

### Configuration File
```yaml
# /etc/alertyx/config.yaml
output:
  format: json  # json | text
  file: /var/log/alertyx/events.json
  
monitoring:
  techniques:
    - T1098
    - T1547
    - L1001
    
mitigate:
  auto: false
  whitelist:
    - /usr/bin/expected-binary
```

### JSON Output
For SIEM integration:
```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "technique": "T1098",
  "severity": "high",
  "event": {...},
  "host": "server01"
}
```

### Systemd Service
```ini
[Unit]
Description=Alertyx EDR Agent
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/alertyx monitor --config /etc/alertyx/config.yaml
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

---

## Recommended Execution Order

```
Phase 1 (Testing)     ████████████████████  FIRST - Foundation
     │
     ▼
Phase 2 (Bugs)        ████████████████████  Security critical
     │
     ▼
Phase 3 (Modernize)   ████████████████████  Technical debt
     │
     ▼
Phase 4 (Features)    ████████████████████  Complete functionality
     │
     ▼
Phase 6 (Production)  ████████████████████  Deploy-ready
```

---

## Success Metrics

| Metric | Target |
|--------|--------|
| Test Coverage | >70% |
| Mutation Score | >70% (survival <30%) |
| CRAP Score | <30 for all functions |
| Build Time | <30 seconds |
| Binary Size | <20MB |
| Memory Usage | <100MB runtime |

---

## Resources

- [MITRE ATT&CK](https://attack.mitre.org/) - Technique references
- [cilium/ebpf](https://github.com/cilium/ebpf) - Target eBPF library
- [eBPF.io](https://ebpf.io/) - eBPF documentation
- [Go Testing](https://go.dev/doc/tutorial/fuzz) - Fuzzing guide
