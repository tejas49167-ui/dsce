def classify_attack(row):
 
    ratio = row["failed_ratio"]
    total = row["total_requests"]
    rate = row["request_rate"]

    if ratio > 0.7 and total > 10 and rate > 0.5:
        return "Brute Force Attack"

    return "Suspicious Activity"