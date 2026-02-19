import pandas as pd


df = pd.read_csv("../data/processed/logs.csv")

df["status"] = df["status"].astype(int)


grouped = df.groupby("ip")


features = grouped.agg(
    total_requests=("status", "count"),
    failed_requests=("status", lambda x: (x == 401).sum())
).reset_index()

features["failed_ratio"] = features["failed_requests"] / features["total_requests"]


features.to_csv("../data/processed/features.csv", index=False)

print("Features generated successfully.")
print(features)
