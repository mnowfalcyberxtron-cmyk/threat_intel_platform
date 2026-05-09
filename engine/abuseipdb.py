"""engine/abuseipdb.py — AbuseIPDB Integration for IP Confidence Analysis"""
import os
import aiohttp
import logging

logger = logging.getLogger("engine.abuseipdb")

async def check_ip_confidence(ip: str) -> float:
    """
    Checks AbuseIPDB for a given IP address.
    Returns a confidence multiplier (0.0 to 1.0) based on the abuse score.
    If the API key is not configured or an error occurs, returns 0.5 (neutral).
    """
    # Prefer ABUSEIPDB_API_KEY from environment
    api_key = os.getenv("ABUSEIPDB_API_KEY", "").strip()
    
    if not api_key:
        # API missing, ignore gracefully
        return 0.5
        
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": api_key,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers, params=params, timeout=10) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    # returns a score from 0 to 100
                    score = data.get("data", {}).get("abuseConfidenceScore", 0)
                    logger.info(f"[AbuseIPDB] Verified {ip} with AbuseScore {score}%")
                    # Normalize score to 0.0 - 1.0 scale (so 100% abusive becomes 1.0 multiplier/confidence)
                    return score / 100.0
                elif resp.status == 429:
                    logger.warning(f"[AbuseIPDB] Rate limit exceeded!")
                    return 0.5
                else:
                    logger.warning(f"[AbuseIPDB] Failed checks for {ip} with status {resp.status}")
                    return 0.5
    except Exception as e:
        logger.debug(f"[AbuseIPDB] Network error checking {ip}: {e}")
        return 0.5
