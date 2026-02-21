def calculate_risk(row):
    
    ratio_score = row["failed_ratio"] * 50
    volume_score = min(row["total_requests"], 50)  
    rate_score = min(row["request_rate"] * 20, 50)

    risk_score = ratio_score + (volume_score * 0.5) + rate_score

    risk_score = min(int(risk_score), 100)

    if risk_score >= 75:
        severity = "HIGH"
    elif risk_score >= 40:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return risk_score, severity