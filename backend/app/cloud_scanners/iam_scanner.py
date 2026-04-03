async def detect_iam_exposure(response) -> list:
    issues = []

    # ✅ FIX: use original text (not lowercased) for display,
    #         but check on lowercased copy for case-insensitive matching
    text = response.text.lower()

    # ✅ FIX: expanded keyword list to catch more IAM credential patterns
    iam_keywords = [
        "accesskeyid", "accesskey", "secretaccesskey", "secretkey",
        "aws_access_key_id", "aws_secret_access_key", "sessiontoken",
    ]

    if any(keyword in text for keyword in iam_keywords):
        issues.append({
            "issue": "Possible IAM Credential Exposure",
            "severity": "Critical",
            "confidence": "Medium",
            "recommendation": (
                "Do not expose AWS credentials in API responses. "
                "Use IAM roles, environment variables, or secrets managers instead."
            )
        })

    return issues