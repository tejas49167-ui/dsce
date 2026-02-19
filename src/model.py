import pandas as pd
from sklearn.ensemble import IsolationForest

df = pd.read_csv("../data/processed/features.csv")

X = df[["total_requests", "failed_requests", "failed_ratio"]]

model = IsolationForest(contamination=0.2, random_state=42)


model.fit(X)

                          
df["anomaly"] = model.predict(X) #(-1 = anomaly, 1 = normal)


df.to_csv("../data/output/anomalies.csv", index=False)

print("Anomaly detection complete.")
print(df)
