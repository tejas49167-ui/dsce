import pandas as pd
from classify import classify_attack
from risk import calculate_risk


def display_value(value, default="N/A"):
    if pd.isna(value):
        return default
    text = str(value).strip()
    return text if text else default


df = pd.read_csv("data/output/anomalies.csv")

if df.empty:
    with open("reports/threat_report.txt", "w") as f:
        f.write("No suspicious activity detected.\n")
    print("Threat report generated.")
    raise SystemExit(0)

df["anomaly"] = df["anomaly"].astype(int)

suspicious = df[
    (df["anomaly"] == -1) |
    ((df["failed_ratio"] > 0.8) & (df["total_requests"] > 15)) |
    (df["sqli_attempts"] > 0) |
    (df["recon_attempts"] > 1)
]

report_lines = []

for _, row in suspicious.iterrows():

    attack_type = classify_attack(row)
    risk_score, severity = calculate_risk(row)

    report_lines.append(f"""
----------------------------------------
Threat Detected
IP Address      : {row['ip']}
Sources         : {display_value(row.get('sources', 'unknown'), 'unknown')}
Attack Type     : {attack_type}
Total Requests  : {row['total_requests']}
Failed Requests : {row['failed_requests']}
Error Requests  : {row['error_requests']}
Distinct Paths  : {row['distinct_paths']}
Distinct Hosts  : {row.get('distinct_hosts', 0)}
SQLi Signals    : {row['sqli_attempts']}
Recon Signals   : {row['recon_attempts']}
Failure Ratio   : {round(row['failed_ratio'], 2)}
Error Ratio     : {round(row['error_ratio'], 2)}
Request Rate    : {round(row['request_rate'], 2)}
User Agents     : {display_value(row.get('sample_user_agents', ''), 'N/A')}
Risk Score      : {risk_score}/100
Severity Level  : {severity}
----------------------------------------
""")

with open("reports/threat_report.txt", "w") as f:
    f.write("\n".join(report_lines) if report_lines else "No suspicious activity detected.\n")

print("Threat report generated.")
