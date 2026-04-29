import httpx
import logging
from typing import Dict, Optional

logger = logging.getLogger(__name__)

async def fetch_epss_scores(cve_ids: list[str]) -> Dict[str, Dict[str, float]]:
    """
    Fetch EPSS scores for a list of CVE IDs.
    Returns a dictionary mapping CVE ID to {"epss": float, "percentile": float}.
    """
    if not cve_ids:
        return {}

    # The API supports querying multiple CVEs via comma-separated list
    cves_param = ",".join(cve_ids)
    url = f"https://api.first.org/data/v1/epss?cve={cves_param}"

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(url)
            response.raise_for_status()
            data = response.json()
            
            result = {}
            for item in data.get("data", []):
                cve = item.get("cve")
                if cve:
                    result[cve] = {
                        "epss": float(item.get("epss", 0.0)),
                        "percentile": float(item.get("percentile", 0.0))
                    }
            return result
    except Exception as e:
        logger.error(f"Failed to fetch EPSS scores: {e}")
        return {}
