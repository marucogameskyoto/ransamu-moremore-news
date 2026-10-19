import hashlib
import json
import re
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from html import unescape
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

ROOT = Path(__file__).resolve().parents[1]
CONFIG = json.loads((ROOT / "sources.json").read_text(encoding="utf-8"))
OUT = ROOT / "site" / "incidents.json"
NOW = datetime.now(timezone.utc)
NOW_TEXT = NOW.isoformat()
KEYWORDS = [x.casefold() for x in CONFIG["keywords"]]
TRACKING_PARAMS = {"fbclid", "gclid", "ref", "source"}


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
    return tag.rsplit("}", 1)[-1].lower().replace("-", "_")


def child_text(item, *names):
    wanted = {name.replace("-", "_") for name in names}
    for child in item:
        if local_name(child.tag) in wanted and child.text:
            return child.text.strip()
    return ""


def canonical_url(value):
    parsed = urlparse(value)
    query = [
        (key, val)
        for key, val in parse_qsl(parsed.query, keep_blank_values=True)
        if not key.casefold().startswith("utm_") and key.casefold() not in TRACKING_PARAMS
    ]
    path = parsed.path.rstrip("/") or "/"
    return urlunparse((parsed.scheme.lower(), parsed.netloc.lower(), path, "", urlencode(sorted(query)), ""))


def stable_id(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:20]


def report_from_item(item, feed):
    title = clean(item.get("title"))
    dt = parse_date(item.get("date"))
    url = item["url"]
    return {
        "title": title,
        "date": dt.date().isoformat() if dt else "日付不明",
        "source": feed["name"],
        "issuer": feed["name"],
        "source_url": url,
        "canonical_url": canonical_url(url),
        "official_host": feed["allowed_host"],
        "first_seen_at": NOW_TEXT,
        "last_seen_at": NOW_TEXT,
    }


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

        # Cross-URL grouping is allowed only when the official feed supplies an
        # explicit incident/event identifier. Titles and organization names alone
        # are not reliable enough to merge automatically.
        event_key = clean(child_text(item, "incident_id", "event_id", "case_id"))[:120]
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
            "event_key": event_key or None,
            "report": report_from_item({"title": title, "date": published, "url": link}, feed),
        })
    return found


def migrate_event(old):
    event = dict(old)
    reports = event.get("reports")
    if not isinstance(reports, list):
        reports = []
        if old.get("source_url") and old.get("official_host"):
            url = old["source_url"]
            reports.append({
                "title": old.get("name", ""),
                "date": old.get("date", "日付不明"),
                "source": old.get("source", "公式発表"),
                "issuer": old.get("issuer", old.get("source", "公式発表")),
                "source_url": url,
                "canonical_url": canonical_url(url),
                "official_host": old["official_host"],
                "first_seen_at": old.get("last_seen_at", old.get("updated_at", NOW_TEXT)),
                "last_seen_at": old.get("last_seen_at", old.get("updated_at", NOW_TEXT)),
            })
    event["reports"] = reports
    event.setdefault("event_key", None)
    event.setdefault("last_seen_at", old.get("updated_at", NOW_TEXT))
    event.setdefault("updated_at", old.get("updated_at", NOW_TEXT))
    event.setdefault("id", stable_id("url:" + canonical_url(old["source_url"])) if old.get("source_url") else stable_id(json.dumps(old, sort_keys=True)))
    return event


def event_identity(item):
    if item.get("event_key"):
        return "official-event:" + item["event_key"].casefold()
    return "url:" + item["report"]["canonical_url"]


def merge_event(event, item):
    report = item["report"]
    by_url = {canonical_url(row.get("source_url", "")): index for index, row in enumerate(event["reports"]) if row.get("source_url")}
    key = report["canonical_url"]
    if key in by_url:
        previous = event["reports"][by_url[key]]
        report["first_seen_at"] = previous.get("first_seen_at", report["first_seen_at"])
        report["last_seen_at"] = NOW_TEXT
        event["reports"][by_url[key]] = report
    else:
        event["reports"].append(report)

    event["reports"].sort(key=lambda row: (row.get("date", "") if row.get("date") != "日付不明" else "", row.get("source", ""), row.get("source_url", "")))
    newest = max(event["reports"], key=lambda row: (row.get("date", "") if row.get("date") != "日付不明" else "", row.get("last_seen_at", "")))
    event.update({
        "name": newest.get("title") or item["name"],
        "sector": item["sector"],
        "region": item["region"],
        "status": "official",
        "source": newest.get("source", item["source"]),
        "issuer": newest.get("issuer", item["issuer"]),
        "source_url": newest.get("source_url", item["source_url"]),
        "official_host": newest.get("official_host", item["official_host"]),
        "date": newest.get("date", item["date"]),
        "event_key": item.get("event_key") or event.get("event_key"),
        "last_seen_at": NOW_TEXT,
        "updated_at": NOW_TEXT,
        "detail": item["detail"],
    })
    if item.get("reported_org"):
        event["reported_org"] = item["reported_org"]
    if item.get("incident_count") is not None:
        event["incident_count"] = item["incident_count"]
    return event


try:
    previous_payload = json.loads(OUT.read_text(encoding="utf-8"))
    previous_events = [migrate_event(row) for row in previous_payload.get("incidents", [])]
except (OSError, json.JSONDecodeError, TypeError):
    previous_events = []

events = {}
for event in previous_events:
    identity = ("official-event:" + event["event_key"].casefold()) if event.get("event_key") else (
        "url:" + (event["reports"][0].get("canonical_url") if event["reports"] else event["id"])
    )
    events[identity] = event

errors = []
successful_feeds = 0
for feed in CONFIG["feeds"]:
    try:
        fetched = fetch_feed(feed)
        successful_feeds += 1
        for item in fetched:
            identity = event_identity(item)
            event = events.get(identity)
            if event is None:
                event = {
                    "id": stable_id(identity),
                    "event_key": item.get("event_key"),
                    "reports": [],
                    "reported_org": item.get("reported_org"),
                    "incident_count": item.get("incident_count"),
                }
                events[identity] = event
            merge_event(event, item)
    except Exception as exc:
        errors.append(f"{feed['name']}: {type(exc).__name__}: {exc}")

if successful_feeds == 0 and CONFIG["feeds"]:
    raise SystemExit("All official feeds failed; keeping previous published data. " + "; ".join(errors))

retention_days = CONFIG.get("history_days", 90)
cutoff = NOW - timedelta(days=retention_days)
retained = []
for event in events.values():
    last_seen = parse_date(event.get("last_seen_at"))
    if last_seen is None or last_seen >= cutoff:
        retained.append(event)

items = sorted(retained, key=lambda row: (row.get("updated_at", ""), row.get("name", "")), reverse=True)[:CONFIG["max_items"]]
payload = {"updated_at": NOW_TEXT, "demo": False, "automation": "official-rss-events", "incidents": items}
OUT.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
print(f"Wrote {len(items)} grouped official records to {OUT}")
if errors:
    print("Feed warnings: " + "; ".join(errors))

