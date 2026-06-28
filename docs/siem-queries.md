# Example Splunk and Elastic Queries

This document provides starter queries for Alertyx NDJSON detection events after ingestion into Splunk or Elastic. Field names match the [event schema](./siem-integration.md#event-schema): `timestamp`, `technique`, `technique_id`, `severity`, `process`, `pid`, `ppid`, `uid`, `username`, `pwd`, `details`, and `artifacts`.

## Ingestion Assumptions

Configure your shipper so each line is parsed as JSON and fields are extracted at the top level (not nested under a generic `message` blob).

| Platform | Typical source | Field extraction |
|----------|----------------|------------------|
| Splunk   | Universal Forwarder or HEC, sourcetype `alertyx:detections` with `_json` line breaking | `INDEXED_EXTRACTIONS = json` or HEC with `sourcetype=_json` |
| Elastic  | Filebeat with `ndjson` parser on `/var/log/alertyx/detections.ndjson` | `decode_json_fields` or ingest pipeline `json` processor |

Example Filebeat snippet:

```yaml
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /var/log/alertyx/detections.ndjson
    json.keys_under_root: true
    json.add_error_key: true
    json.message_key: message

output.elasticsearch:
  hosts: ["https://elastic.example.com:9200"]
  index: "alertyx-detections-%{+yyyy.MM.dd}"
```

Example Splunk `props.conf` for a monitored file:

```ini
[alertyx:detections]
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)
TRUNCATE = 999999
KV_MODE = none
INDEXED_EXTRACTIONS = json
TIME_PREFIX = "timestamp":"
TIME_FORMAT = %Y-%m-%dT%H:%M:%S%z
```

---

## Splunk (SPL)

Replace `index=alertyx` and sourcetype names with values from your deployment.

### All detections in the last 24 hours

```spl
index=alertyx sourcetype=alertyx:detections earliest=-24h
| table _time timestamp technique technique_id severity process pid username pwd details
```

### Critical and error severity only

```spl
index=alertyx sourcetype=alertyx:detections severity IN ("crit", "err")
| stats count by severity technique_id technique
| sort - count
```

### Detections for a specific MITRE / Alertyx technique

```spl
index=alertyx sourcetype=alertyx:detections technique_id="L1002"
| sort - _time
| table _time username process pid pwd details
```

### Suspicious access to sensitive paths (details or artifacts)

```spl
index=alertyx sourcetype=alertyx:detections
  (details="*shadow*" OR details="*passwd*" OR mvfind(artifacts, "*shadow*")>=0)
| stats count dc(username) AS users dc(process) AS processes by technique_id technique
```

### Top processes raising detections

```spl
index=alertyx sourcetype=alertyx:detections earliest=-7d
| top limit=20 process by severity
```

### Alert: any critical detection (saved search / notable event)

```spl
index=alertyx sourcetype=alertyx:detections severity="crit"
| eval rule="Alertyx critical detection"
| table _time rule technique technique_id process pid username details
```

Use this SPL as a **Scheduled Search** or **Correlation Search** in Splunk Enterprise Security, triggering when `count > 0`.

### Dashboard panel: detections over time by severity

```spl
index=alertyx sourcetype=alertyx:detections earliest=-30d
| timechart span=1h count by severity
```

---

## Elastic (KQL, Lucene, and EQL)

Replace `alertyx-detections-*` with your index pattern.

### All detections in the last 24 hours (KQL)

```kql
event.dataset: "alertyx.detections" or _index: alertyx-detections-*
```

With time picker set to **Last 24 hours**. In Discover, add columns: `@timestamp`, `technique`, `technique_id`, `severity`, `process`, `username`, `details`.

### Critical and error severity (KQL)

```kql
severity: ("crit" or "err")
```

### Specific technique ID (KQL)

```kql
technique_id: "L1002"
```

### Sensitive file access (Lucene)

```lucene
details:(*shadow* OR *passwd*) OR artifacts:(*shadow* OR *passwd*)
```

### Top offending processes (Elasticsearch aggregation via Dev Tools)

```json
GET alertyx-detections-*/_search
{
  "size": 0,
  "query": {
    "range": {
      "@timestamp": { "gte": "now-7d" }
    }
  },
  "aggs": {
    "by_process": {
      "terms": { "field": "process.keyword", "size": 20 },
      "aggs": {
        "by_severity": { "terms": { "field": "severity.keyword" } }
      }
    }
  }
}
```

### Detections over time (Lens / TSVB)

- **Index pattern:** `alertyx-detections-*`
- **Date field:** `@timestamp` (map from JSON `timestamp` at ingest) or use `timestamp` if not renamed
- **Break down by:** `severity.keyword`
- **Metric:** Count of records

### Alerting rule example (KQL threshold)

Create a **Stack Monitoring** or **Rules** entry:

- **Query:** `severity: "crit"`
- **Time window:** 5 minutes
- **Threshold:** `count > 0`
- **Action:** email, Slack, or case webhook with fields `technique`, `technique_id`, `process`, `username`, `details`

### Event correlation with EQL (same user, multiple techniques)

```eql
sequence by username
  [any where technique_id == "L1002"]
  [any where technique_id == "T1098"]
  within 1 hour
```

Adjust technique IDs to match techniques enabled in your environment.

---

## Field Mapping Tips

| JSON field     | Splunk auto-extract | Elastic mapping suggestion      |
|----------------|---------------------|-----------------------------------|
| `timestamp`    | `_time` via `TIME_PREFIX` | `date` (`@timestamp` if copied at ingest) |
| `technique_id` | `technique_id`      | `keyword`                         |
| `severity`     | `severity`          | `keyword`                         |
| `process`      | `process`           | `keyword` (use `.keyword` for aggs) |
| `details`      | `details`           | `text` with `keyword` subfield    |
| `artifacts`    | multivalue `artifacts{}` | `keyword` array              |

## Related Documentation

- [SIEM Integration](./siem-integration.md) — enabling JSON output, schema, and deployment
- JSON output implementation: `output/detection_event.go`
