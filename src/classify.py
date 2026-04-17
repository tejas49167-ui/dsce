def classify_attack(row):
    ratio = row["failed_ratio"]
    total = row["total_requests"]
    failed_requests = row.get("failed_requests", 0)
    sqli_attempts = row.get("sqli_attempts", 0)
    recon_attempts = row.get("recon_attempts", 0)
    distinct_paths = row.get("distinct_paths", 0)
    error_ratio = row.get("error_ratio", 0)

    if ratio > 0.7 and total > 10 and failed_requests >= 10:
        return "Brute Force Attack"

    if sqli_attempts >= 1:
        return "SQL Injection Attempt"

    if recon_attempts >= 2 or (distinct_paths >= 6 and error_ratio >= 0.3):
        return "Reconnaissance Activity"

    return "Suspicious Activity"
