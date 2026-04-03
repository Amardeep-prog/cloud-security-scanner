import httpx

COMMON_SUBDOMAINS = ["api", "dev", "test", "staging", "admin"]

async def find_subdomains(base_url):
    found = []

    domain = base_url.replace("https://", "").replace("http://", "").split("/")[0]

    async with httpx.AsyncClient(timeout=3) as client:
        for sub in COMMON_SUBDOMAINS:
            test_url = f"https://{sub}.{domain}"
            try:
                res = await client.get(test_url)
                if res.status_code < 500:
                    found.append(test_url)
            except:
                pass

    return found