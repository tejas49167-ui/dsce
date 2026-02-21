import pandas as pd

log_file = "data/raw/access.log"
output_file = "data/processed/logs.csv"


columns = ["timestamp", "ip", "method", "path", "status"]


df = pd.read_csv(log_file, names=columns)


df.to_csv(output_file, index=False)

