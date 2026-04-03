weights = {
    "Critical": 10,
    "High": 7,
    "Medium": 4,
    "Low": 1
}

def calculate_risk(issues):
    total = sum(weights.get(i["severity"], 0) for i in issues)
    max_score = 100

    normalized = min((total / 50) * 100, 100)

    if normalized > 80:
        grade = "F"
    elif normalized > 60:
        grade = "D"
    elif normalized > 40:
        grade = "C"
    elif normalized > 20:
        grade = "B"
    else:
        grade = "A"

    return round(normalized, 2), grade