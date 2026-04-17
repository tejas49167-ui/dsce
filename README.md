# ML Logs Analyzer

This project is a lightweight threat-analysis pipeline for web traffic. It can ingest either:

- application access logs
- `tshark`-derived HTTP event CSV files
- raw packet captures in `.pcap` / `.pcapng`

All inputs are normalized into the same event schema and pushed through one detection pipeline:

`Raw Events -> Normalization -> Feature Extraction -> Anomaly Detection -> Classification -> Risk Scoring -> Reporting`

## What It Detects

- brute-force login behavior
- SQL injection attempts in request paths and query strings
- reconnaissance / scanning behavior against common sensitive endpoints

## Project Layout

- [main.py](/home/tejas/Desktop/ML_logs_analyzer/main.py:1): pipeline entrypoint
- [src/parse.py](/home/tejas/Desktop/ML_logs_analyzer/src/parse.py:1): app-log, CSV, and pcap normalization
- [src/feature.py](/home/tejas/Desktop/ML_logs_analyzer/src/feature.py:1): per-IP feature engineering
- [src/model.py](/home/tejas/Desktop/ML_logs_analyzer/src/model.py:1): anomaly detection with `IsolationForest`
- [src/report.py](/home/tejas/Desktop/ML_logs_analyzer/src/report.py:1): human-readable threat report
- [demo/app.py](/home/tejas/Desktop/ML_logs_analyzer/demo/app.py:1): sample Flask app that emits access logs

## Installation

Install Python packages:

```bash
pip install -r requirements.txt
```

Install Wireshark CLI tools for packet parsing:

```bash
sudo apt install tshark
```

## How To Run

Run against the default app log:

```bash
python3 main.py
```

Run against a sample realistic application log:

```bash
python3 main.py --input data/raw/demo_sqli_recon.log --format app_log
```

Run against a real packet capture:

```bash
python3 main.py --input data/raw/demo_http_capture.pcap --format pcap
```

Run against a normalized HTTP CSV export:

```bash
python3 main.py --input data/raw/demo_http_capture_events.csv --format tshark_csv
```

## Demo Datasets

- [data/raw/demo_sqli_recon.log](/home/tejas/Desktop/ML_logs_analyzer/data/raw/demo_sqli_recon.log:1): mixed normal traffic, SQLi, and recon
- [data/raw/demo_sql_injection.log](/home/tejas/Desktop/ML_logs_analyzer/data/raw/demo_sql_injection.log:1): SQL injection only
- [data/raw/demo_reconnaissance.log](/home/tejas/Desktop/ML_logs_analyzer/data/raw/demo_reconnaissance.log:1): reconnaissance only
- [data/raw/demo_http_capture.pcap](/home/tejas/Desktop/ML_logs_analyzer/data/raw/demo_http_capture.pcap): packet-capture demo
- [data/raw/demo_http_capture_events.csv](/home/tejas/Desktop/ML_logs_analyzer/data/raw/demo_http_capture_events.csv:1): normalized HTTP events exported from the demo pcap

Generate the demo pcap again if needed:

```bash
python3 scripts/generate_demo_pcap.py
```

## Real-World Direction

This is a strong prototype path for a SIEM-style detector, especially if you want to evolve beyond app logs. In a more production-shaped version, the next good steps would be:

- collect mirrored traffic or load-balancer HTTP logs instead of local-only samples
- enrich events with hostnames, user agents, destination services, and request volumes by time window
- add streaming ingestion instead of batch-only CSV writes
- separate rule-based detections from anomaly-based detections for clearer explainability
- add TLS-termination or reverse-proxy logs so encrypted traffic still exposes request metadata

## Current Note

Packet parsing works best for HTTP traffic that is visible to `tshark`. If your environment is HTTPS-only and you do not capture traffic after TLS termination, packet captures will not expose the full request URI or payload.
