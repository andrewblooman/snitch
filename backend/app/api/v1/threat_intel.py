import re
import asyncio
import logging
import httpx
import defusedxml.ElementTree as ET
from email.utils import parsedate_to_datetime
from fastapi import APIRouter, HTTPException

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/threat-intel", tags=["threat-intel"])

FEEDS = [
    {"url": "https://feeds.feedburner.com/TheHackersNews", "name": "The Hacker News"},
    {"url": "https://www.bleepingcomputer.com/feed/", "name": "Bleeping Computer"},
    {"url": "https://www.wiz.io/api/feed/cloud-threat-landscape/rss.xml", "name": "Wiz Cloud"},
    {"url": "https://www.cisa.gov/cybersecurity-advisories/all.xml", "name": "CISA Alerts"},
    {"url": "https://www.shadowserver.org/feed/", "name": "Shadowserver"},
    {"url": "https://krebsonsecurity.com/feed/", "name": "Krebs on Security"},
    {"url": "https://www.darkreading.com/rss.xml", "name": "Dark Reading"}
]

async def fetch_feed(client, feed_info):
    try:
        response = await client.get(feed_info["url"], timeout=10.0)
        response.raise_for_status()
        root = ET.fromstring(response.content)
        
        items = []
        for i, item in enumerate(root.findall(".//item")):
            if i >= 5:
                break
                
            title = item.findtext("title")
            link = item.findtext("link")
            description = item.findtext("description")
            pubDate = item.findtext("pubDate")
            
            # Simple description cleaner (remove HTML tags)
            clean_desc = re.sub(r'<[^>]+>', '', description) if description else ""
            # Decode HTML entities
            clean_desc = clean_desc.replace("&nbsp;", " ").replace("&amp;", "&").replace("&quot;", '"')
            clean_title = title.replace("&nbsp;", " ").replace("&amp;", "&").replace("&quot;", '"') if title else ""
            
            items.append({
                "title": clean_title,
                "link": link,
                "description": clean_desc,
                "pubDate": pubDate,
                "source": feed_info["name"]
            })
        return items
    except Exception as e:
        logger.error("Error fetching feed %s: %s", feed_info['name'], e)
        return []

@router.get("/feed")
async def get_feed():
    try:
        async with httpx.AsyncClient(follow_redirects=True) as client:
            tasks = [fetch_feed(client, f) for f in FEEDS]
            results = await asyncio.gather(*tasks)
            
        all_items = []
        for r in results:
            all_items.extend(r)
            
        # Sort by pubDate descending
        def get_date(item):
            try:
                if item["pubDate"]:
                    return parsedate_to_datetime(item["pubDate"])
            except Exception:
                pass
            from datetime import datetime, timezone
            return datetime.min.replace(tzinfo=timezone.utc)
            
        all_items.sort(key=get_date, reverse=True)
        return {"items": all_items}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch RSS feeds: {str(e)}")

@router.get("/locations")
async def get_locations():
    """
    Analyzes the latest threat feeds and extracts mentioned locations
    with estimated coordinates. Uses Anthropic if available, otherwise fallback.
    """
    try:
        # 1. Get the feeds
        feed_data = await get_feed()
        items = feed_data.get("items", [])[:15] # Top 15 to avoid massive prompts
        
        text_corpus = "\n".join([f"Title: {i['title']}\nDesc: {i['description']}" for i in items])
        
        import json
        from app.services.llm_provider import MockProvider, get_llm_provider

        # 2. Try LLM provider (Anthropic or Ollama)
        provider = get_llm_provider()
        if not isinstance(provider, MockProvider):
            try:
                prompt = (
                    "Analyze the following cybersecurity news items. Extract up to 5 distinct geographic countries or regions "
                    "mentioned as targets or origins of attacks. Return ONLY a strict JSON array of objects. "
                    "Each object must have exactly these keys: 'country' (string), 'lat' (float, latitude), "
                    "'lng' (float, longitude), and 'event' (a 1-sentence summary of the threat there).\n\n"
                    f"News:\n{text_corpus}\n\n"
                    "Output strict JSON array only, no markdown blocks or conversational text."
                )

                result = await provider.complete(prompt, max_tokens=1000)
                text_out = result.text.strip()
                if text_out.startswith("```json"):
                    text_out = text_out.replace("```json", "", 1)
                if text_out.endswith("```"):
                    text_out = text_out[:-3]

                locations = json.loads(text_out.strip())
                return {"locations": locations}
            except Exception as e:
                logger.error("LLM location extraction failed: %s", e)
                # Fall through to fallback
                
        # 3. Fallback Keyword Matcher
        fallback_db = {
            "Russia": (61.5, 105.3, "State-sponsored campaigns or ransomware activity detected."),
            "China": (35.8, 104.1, "APT groups engaged in espionage and IP theft."),
            "North Korea": (40.3, 127.5, "Financially motivated attacks and crypto theft."),
            "Iran": (32.4, 53.6, "Disruptive wiper attacks and espionage."),
            "United States": (37.0, -95.7, "Targeted critical infrastructure or widespread phishing."),
            "Ukraine": (48.3, 31.1, "Target of destructive wipers and state-sponsored espionage."),
            "Israel": (31.0, 34.8, "Targeted by hacktivist DDoS and wiper campaigns.")
        }
        
        found = []
        text_corpus_lower = text_corpus.lower()
        for country, data in fallback_db.items():
            if country.lower() in text_corpus_lower:
                found.append({
                    "country": country,
                    "lat": data[0],
                    "lng": data[1],
                    "event": data[2]
                })
        
        # If nothing found, provide a default set to ensure the visualization works
        if not found:
            found = [
                {"country": "Russia", "lat": 61.5, "lng": 105.3, "event": "General threat actor activity."},
                {"country": "United States", "lat": 37.0, "lng": -95.7, "event": "Target of general campaigns."}
            ]
            
        return {"locations": found[:5]}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to analyze locations: {str(e)}")
