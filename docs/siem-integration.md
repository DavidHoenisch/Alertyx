# SIEM Integration

Alertyx can emit structured detection events as **NDJSON** (newline-delimited JSON) for ingestion by SIEM platforms such as Splunk, Elastic, and other log pipelines.

## Enabling JSON Output

Use the global `--output` flag with the `monitor` command (or any command that reports detections):

```bash
sudo ./Alertyx monitor --output json
```

Valid values:

| Value  | Description                                      |
|--------|--------------------------------------------------|
| `text` | Human-readable colored terminal output (default) |
| `json` | One compact JSON object per detection (NDJSON)   |

Redirect stdout to a file for a log shipper or SIEM agent:

```bash
sudo ./Alertyx monitor --output json >> /var/log/alertyx/detections.ndjson
```

When `--output json` is set:

- Detections are written as NDJSON lines on stdout.
- Informational startup messages and duplicate detections are suppressed from stdout so downstream parsers see only detection records.
- Use `--verbose` only when debugging; verbose lines are not JSON and will break strict NDJSON parsers.

## NDJSON Format

Each detection is a single JSON object on one line, followed by a newline (`\n`). There is no enclosing array and no pretty-printing. This format is compatible with:

- Splunk **HEC** and **sourcetype** `_json` line breaking
- Elastic **Filebeat** `ndjson` decoding
- Generic log forwarders (rsyslog, Fluent Bit, Vector, etc.)

Example line:

```json
{"timestamp":"2024-01-15T10:30:00Z","technique":"Suspicious /etc/shadow Access","technique_id":"L1002","severity":"warn","process":"cat","pid":12345,"ppid":1,"uid":1000,"username":"attacker","pwd":"/home/attacker","details":"/etc/shadow path /home/attacker flags 0","artifacts":["/etc/shadow path /home/attacker flags 0"]}
```

## Event Schema

Each detection maps to a `DetectionEvent` with the following fields:

| Field          | JSON key        | Type     | Description |
|----------------|-----------------|----------|-------------|
| Timestamp      | `timestamp`     | string   | RFC 3339 UTC time when the detection was raised |
| Technique name | `technique`     | string   | Human-readable technique title |
| Technique ID   | `technique_id`  | string   | Alertyx identifier, e.g. `L1002`, `T1098` |
| Severity       | `severity`      | string   | `crit`, `err`, `warn`, or `info` |
| Process        | `process`       | string   | Basename of the process tied to the primary artifact |
| PID            | `pid`           | number   | Process ID of the primary artifact |
| PPID           | `ppid`          | number   | Parent process ID |
| UID            | `uid`           | number   | Effective user ID |
| Username       | `username`      | string   | Username for `uid`, or `?` if lookup fails |
| Working dir    | `pwd`           | string   | Process working directory |
| Details        | `details`       | string   | Primary artifact event description |
| Artifacts      | `artifacts`     | string[] | All correlated artifact event descriptions |

Field names and types are stable for SIEM field extraction and index mappings.

## Severity Mapping

Alertyx detection levels map to JSON `severity` as follows:

| Detection level | JSON `severity` |
|-----------------|-----------------|
| Critical        | `crit`          |
| Error           | `err`           |
| Warning         | `warn`          |
| Other           | `info`          |

Use `severity` for alerting rules and dashboards (for example, alert when `severity` is `crit` or `err`).

## Deployment Patterns

### File + log shipper

1. Run Alertyx with `--output json` and append stdout to a dedicated file.
2. Point Filebeat, Splunk Universal Forwarder, or Fluent Bit at that file.
3. Configure the shipper for **NDJSON** or **JSON** line parsing.

### systemd service

Run Alertyx under systemd and set `StandardOutput=append:/var/log/alertyx/detections.ndjson` in the unit file. See issue #16 for a production service template.

### Syslog

The `--syslog` flag sends human-readable messages to syslog. For SIEM use cases, prefer `--output json` with a file or pipe so field structure is preserved.

## Related Documentation

- Example Splunk and Elastic queries: [siem-queries.md](./siem-queries.md)
- JSON output implementation: `output/detection_event.go`
- Detection mapping: `analysis/detection_event.go`
