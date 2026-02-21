import pandas as pd
from classify import classify_attack
from risk import calculate_risk

df = pd.read_csv("data/output/anomalies.csv")

df["anomaly"] = df["anomaly"].astype(int)

suspicious = df[
    (df["anomaly"] == -1) |
    ((df["failed_ratio"] > 0.8) & (df["total_requests"] > 15))
]

report_lines = []

for _, row in suspicious.iterrows():

    attack_type = classify_attack(row)
    risk_score, severity = calculate_risk(row)

    report_lines.append(f"""
----------------------------------------
Threat Detected
IP Address      : {row['ip']}
Attack Type     : {attack_type}
Total Requests  : {row['total_requests']}
Failed Requests : {row['failed_requests']}
Failure Ratio   : {round(row['failed_ratio'], 2)}
Request Rate    : {round(row['request_rate'], 2)}
Risk Score      : {risk_score}/100
Severity Level  : {severity}
----------------------------------------
""")

with open("reports/threat_report.txt", "w") as f:
    f.write("\n".join(report_lines))

print("Threat report generated.")