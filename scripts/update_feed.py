import json
import re
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from html import unescape
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
CONFIG = json.loads((ROOT / "sources.json").read_text(encoding="utf-8"))
OUT = ROOT / "site" / "incidents.json"
NOW = datetime.now(timezone.utc)
KEYWORDS = [x.casefold() for x in CONFIG["keywords"]]

def clean(value):
    value = re.sub(r"<[^>]+>", " ", value or "")
    return re.sub(r"\s+", " ", unescape(value)).strip()

def parse_date(value):
    if not value:
        return None
    try:
        try:
            d = parsedate_to_datetime(value)
        except (TypeError, ValueError):
            d = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return d.replace(tzinfo=timezone.utc) if d.tzinfo is None else d.astimezone(timezone.utc)
    except (TypeError, ValueError, OverflowError):
        return None

def local_name(tag):
    return tag.rsplit("}", 1)[-1].lower()

def child_text(item, *names):
    for child in item:
        if local_name(child.tag) in names and child.text:
            return child.text.strip()
    return ""

def fetch_feed(feed):
    parsed_feed = urlparse(feed["url"])
    if parsed_feed.scheme != "https" or parsed_feed.hostname != feed["allowed_host"]:
        raise ValueError("Feed URL host is not on the official-source allowlist")
    req = urllib.request.Request(feed["url"], headers={"User-Agent": "RansamuMoreMoreDigest/1.0 (RSS reader)"})
    with urllib.request.urlopen(req, timeout=25) as response:
        payload = response.read(2_000_000)
    root = ET.fromstring(payload)
    rows = [node for node in root.iter() if local_name(node.tag) in ("item", "entry")]
    found = []
    for item in rows:
        title = clean(child_text(item, "title"))
        link = child_text(item, "link")
        if not link:
            for child in item:
                if local_name(child.tag) == "link":
                    link = child.attrib.get("href") or child.attrib.get("resource", "")
                    break
        published = child_text(item, "pubdate", "published", "updated", "date")
        dt = parse_date(published)
        haystack = (title + " " + clean(child_text(item, "description", "summary", "content"))).casefold()
        if not title or not link or not any(word in haystack for word in KEYWORDS):
            continue
        if dt and dt < NOW - timedelta(days=CONFIG["max_age_days"]):
            continue
        if not link.startswith("https://") or urlparse(link).hostname != feed["allowed_host"]:
            continue
        found.append({
            "name": title,
            "sector": "公式サイバーセキュリティ発表",
            "region": "公式発表",
            "date": dt.date().isoformat() if dt else "日付不明",
            "status": "official",
            "source": feed["name"],
            "issuer": feed["name"],
            "reported_org": None,
            "incident_count": None,
            "detail": "公式フィードに掲載された発表タイトル。対象組織・件数は原文記載時のみ表示。",
            "source_url": link,
            "official_host": feed["allowed_host"],
            "reviewed_at": None,
        })
    return found

all_items = {}
errors = []
successful_feeds = 0
for feed in CONFIG["feeds"]:
    try:
        fetched = fetch_feed(feed)
        successful_feeds += 1
        for item in fetched:
            all_items[item["source_url"]] = item
    except Exception as exc:
        errors.append(f"{feed['name']}: {type(exc).__name__}: {exc}")

if not all_items:
    if successful_feeds == 0:
        raise SystemExit("All official feeds failed; keeping previous published data. " + "; ".join(errors))

items = sorted(all_items.values(), key=lambda row: (row["date"], row["name"]), reverse=True)[:CONFIG["max_items"]]
payload = {"updated_at": NOW.isoformat(), "demo": False, "automation": "official-rss-headlines", "incidents": items}
OUT.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
print(f"Wrote {len(items)} RSS headline records to {OUT}")
if errors:
    print("Feed warnings: " + "; ".join(errors))
