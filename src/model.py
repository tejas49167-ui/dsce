import pandas as pd
from sklearn.ensemble import IsolationForest

df = pd.read_csv("data/processed/features.csv")

feature_columns = [
    "total_requests",
    "failed_requests",
    "error_requests",
    "distinct_paths",
    "distinct_hosts",
    "sqli_attempts",
    "recon_attempts",
    "failed_ratio",
    "error_ratio",
    "path_diversity",
    "request_rate",
]

if df.empty:
    df["anomaly"] = []
else:
    X = df[feature_columns]

    if len(df) < 3:
        df["anomaly"] = 1
    else:
        model = IsolationForest(contamination=0.3, random_state=42)
        model.fit(X)
        df["anomaly"] = model.predict(X)

df.to_csv("data/output/anomalies.csv", index=False)

print("Anomaly detection complete.")
print(df)
