def detect_cloud(url: str):
    if "amazonaws.com" in url:
        return {"provider": "AWS", "service": "S3/API Gateway"}
    if "azurewebsites.net" in url:
        return {"provider": "Azure", "service": "App Service"}
    if "googleapis.com" in url:
        return {"provider": "GCP", "service": "Cloud API"}
    return {"provider": "Unknown", "service": "Unknown"}