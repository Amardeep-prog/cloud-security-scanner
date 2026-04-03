import httpx

async def detect_public_s3(url: str):
    issues = []

    if "s3.amazonaws.com" not in url:
        return issues

    try:
        async with httpx.AsyncClient(timeout=5) as client:
            res = await client.get(url)

            if res.status_code == 200 and "<ListBucketResult>" in res.text:
                issues.append({
                    "issue": "Public S3 Bucket Listing Enabled",
                    "severity": "Critical",
                    "confidence": "High",
                    "cloud": "AWS S3",
                    "recommendation": "Disable public bucket listing using IAM policies"
                })

    except:
        pass

    return issues