def detect_anomalies(response):
    issues = []

    if "debug" in response.text.lower():
        issues.append({
            "issue": "Debug mode exposed",
            "severity": "High"
        })

    if "Index of /" in response.text:
        issues.append({
            "issue": "Directory listing enabled",
            "severity": "Medium"
        })

    return issues