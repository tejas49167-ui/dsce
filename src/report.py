import pandas as pd


df = pd.read_csv("../data/output/anomalies.csv")


suspicious = df[df["anomaly"] == -1]

report_lines = []

for _, row in suspicious.iterrows():
    ip = row["ip"]
    total = row["total_requests"]
    failed = row["failed_requests"]
    ratio = row["failed_ratio"]

    
    if ratio > 0.7 and total > 10:
        attack_type = "Brute Force Attack"
        severity = "HIGH"
    else:
        attack_type = "Suspicious Activity"
        severity = "MEDIUM"

    report_lines.append(f"""
----------------------------------------
Threat Detected
IP Address      : {ip}
Attack Type     : {attack_type}
Total Requests  : {total}
Failed Requests : {failed}
Failure Ratio   : {round(ratio, 2)}
Severity Level  : {severity}
----------------------------------------
""")

with open("../reports/threat_report.txt", "w") as f:
    f.write("\n".join(report_lines))

print("Threat report generated.")
