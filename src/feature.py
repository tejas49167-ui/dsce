import pandas as pd

# Load structured logs
df = pd.read_csv("../data/processed/logs.csv")

# Convert status to integer (important)

print(df.head())
print(df.tail())
print(df.isna().sum())
