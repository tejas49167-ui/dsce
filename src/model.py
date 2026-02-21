import pandas as pd
from sklearn.ensemble import IsolationForest

df = pd.read_csv("data/processed/features.csv")

X = df[["total_requests", "failed_requests", "failed_ratio", "request_rate"]]

model = IsolationForest(contamination=0.3, random_state=42)
model.fit(X)

df["anomaly"] = model.predict(X)

# Save FULL dataframe including request_rate
df.to_csv("data/output/anomalies.csv", index=False)

print("Anomaly detection complete.")
print(df)