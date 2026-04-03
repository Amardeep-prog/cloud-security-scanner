import re

PATTERNS = {
    "AWS Key": r"AKIA[0-9A-Z]{16}",
    "JWT": r"eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+",
    "Email": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"
}

def deep_scan(response):
    issues = []
    text = response.text

    for name, pattern in PATTERNS.items():
        if re.search(pattern, text):
            issues.append({
                "issue": f"Sensitive Data Leak: {name}",
                "severity": "Critical",
                "confidence": "High"
            })

    return issues