import pandas as pd

df = pd.read_csv("data/processed/logs.csv")

df = df.dropna(subset=["status"])
df["status"] = df["status"].astype(int)


df["timestamp"] = pd.to_datetime(df["timestamp"])

grouped = df.groupby("ip")

features = grouped.agg(
    total_requests=("status", "count"),
    failed_requests=("status", lambda x: (x == 401).sum()),
    first_seen=("timestamp", "min"),
    last_seen=("timestamp", "max")
).reset_index()


features["duration"] = (
    features["last_seen"] - features["first_seen"]
).dt.total_seconds()

features["duration"] = features["duration"].replace(0, 1)


features["request_rate"] = (
    features["total_requests"] / features["duration"]
)

# Failure ratio
features["failed_ratio"] = (
    features["failed_requests"] / features["total_requests"]
)

# Keep only necessary columns
features = features[
    ["ip", "total_requests", "failed_requests", "failed_ratio", "request_rate"]
]

features.to_csv("data/processed/features.csv", index=False)

print("Features generated successfully.")
print(features)