import hashlib
import json
import re
import time
import urllib.robotparser
import urllib.request
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlparse, parse_qsl, urlencode, urlunparse

ROOT = Path(__file__).resolve().parents[1]
CONFIG = json.loads((ROOT / "sources.json").read_text(encoding="utf-8"))
OUT = ROOT / "site" / "incidents.json"
NOW = datetime.now(timezone.utc)
NOW_TEXT = NOW.isoformat()
TRACKING_PARAMS = {"fbclid", "gclid", "ref", "source"}
GROUPS = {name: [word.casefold() for word in terms] for name, terms in CONFIG.get("match_groups", {}).items()}
INCIDENT_TERMS = GROUPS.get("incident", [])
LEAK_TERMS = GROUPS.get("leak", [])
USER_AGENT = "RansamuMoreMoreDigest/1.0 (official public notice indexer; contact: repository owner)"


def clean(value):
    value = re.sub(r"<[^>]+>", " ", value or "")
    return re.sub(r"\s+", " ", value).strip()


def canonical_url(value):
    parsed = urlparse(value)
    query = [(k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True)
             if not k.casefold().startswith("utm_") and k.casefold() not in TRACKING_PARAMS]
    path = parsed.path.rstrip("/") or "/"
    return urlunparse((parsed.scheme.lower(), parsed.netloc.lower(), path, "", urlencode(sorted(query)), ""))


def stable_id(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:20]


def matches(text, terms):
    folded = (text or "").casefold()
    return any(term in folded for term in terms)


def published_date(text, dates):
    for value in dates:
        if value:
            parsed = parse_date(value)
            if parsed:
                return parsed
    match = re.search(r"(20\d{2})\s*[年./-]\s*(\d{1,2})\s*[月./-]\s*(\d{1,2})", text or "")
    if match:
        try:
            return datetime(int(match.group(1)), int(match.group(2)), int(match.group(3)), tzinfo=timezone.utc)
        except ValueError:
            pass
    return None


def parse_date(value):
    if not value:
        return None
    value = value.strip()
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except (ValueError, OverflowError):
        pass
    try:
        from email.utils import parsedate_to_datetime
        parsed = parsedate_to_datetime(value)
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
    except (TypeError, ValueError, OverflowError):
        return None


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []
        self.text_parts = []
        self.content_parts = []
        self.meta = []
        self._anchor = None
        self._title = False
        self._time = False
        self._main_depth = 0
        self._article_depth = 0
        self._suppressed_depth = 0

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        tag = tag.lower()
        if tag in {"script", "style", "noscript", "svg"}:
            self._suppressed_depth += 1
        if tag == "main":
            self._main_depth += 1
        elif tag == "article":
            self._article_depth += 1
        if tag == "a":
            self._anchor = [attrs.get("href", ""), attrs.get("title", ""), []]
        elif tag == "meta":
            key = (attrs.get("property") or attrs.get("name") or "").casefold()
            if key in {"og:title", "twitter:title", "article:published_time", "date", "dc.date", "description"}:
                self.meta.append((key, attrs.get("content", "")))
        elif tag == "title":
            self._title = True
        elif tag == "time":
            self._time = True
            if attrs.get("datetime"):
                self.meta.append(("date", attrs["datetime"]))

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag in {"script", "style", "noscript", "svg"} and self._suppressed_depth:
            self._suppressed_depth -= 1
        if tag == "main" and self._main_depth:
            self._main_depth -= 1
        elif tag == "article" and self._article_depth:
            self._article_depth -= 1
        if tag == "a" and self._anchor:
            href, title, parts = self._anchor
            self.links.append((href, clean(" ".join([title] + parts))))
            self._anchor = None
        elif tag == "title":
            self._title = False
        elif tag == "time":
            self._time = False

    def handle_data(self, data):
        if self._suppressed_depth:
            return
        if data.strip():
            self.text_parts.append(data.strip())
            if self._main_depth or self._article_depth:
                self.content_parts.append(data.strip())
        if self._anchor is not None:
            self._anchor[2].append(data)
        if self._title:
            self.meta.append(("title", data.strip()))
        if self._time:
            self.meta.append(("date", data.strip()))


def fetch(url, host, robots=None, max_bytes=2_000_000):
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname != host:
        raise ValueError("URL is outside the official host allowlist")
    if robots and not robots.can_fetch(USER_AGENT, url):
        return None, None, "robots.txt disallows this URL"
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml"})
    with urllib.request.urlopen(req, timeout=20) as response:
        final_url = response.geturl()
        if urlparse(final_url).hostname != host:
            raise ValueError("Redirect left the official host allowlist")
        content_type = response.headers.get_content_type()
        if content_type not in {"text/html", "application/xhtml+xml"}:
            return None, None, "not an HTML page"
        charset = response.headers.get_content_charset() or "utf-8"
        payload = response.read(max_bytes + 1)
    if len(payload) > max_bytes:
        raise ValueError("page exceeded size limit")
    parser = PageParser()
    parser.feed(payload.decode(charset, errors="replace"))
    return parser, final_url, None


def load_robots(host):
    robots = urllib.robotparser.RobotFileParser()
    robots.set_url("https://" + host + "/robots.txt")
    try:
        robots.read()
        return robots
    except Exception:
        # If robots.txt cannot be checked, skip this host rather than crawl blindly.
        robots.disallow_all = True
        return robots


def within_prefix(url, prefixes):
    if not prefixes:
        return True
    path = urlparse(url).path
    return any(path.startswith(prefix) for prefix in prefixes)


def discover(source):
    host = source["allowed_host"]
    start = source["start_url"]
    if urlparse(start).hostname != host:
        raise ValueError("Configured listing page host is not allowlisted")
    robots = load_robots(host)
    listing, final_url, skipped = fetch(start, host, robots)
    if skipped:
        return [], skipped
    if not listing:
        return [], "listing page unavailable"
    prefixes = source.get("path_prefixes", [])
    candidates = []
    seen = set()
    for href, label in listing.links:
        target = urljoin(final_url, href)
        parsed = urlparse(target)
        if parsed.scheme != "https" or parsed.hostname != host:
            continue
        if not within_prefix(target, prefixes):
            continue
        if parsed.path.lower().endswith((".pdf", ".jpg", ".png", ".zip", ".doc", ".docx")):
            continue
        # Listing titles may name the incident or the information exposure.
        if not (matches(label, INCIDENT_TERMS) or matches(label, LEAK_TERMS)):
            continue
        canonical = canonical_url(target)
        if canonical in seen or canonical == canonical_url(final_url):
            continue
        seen.add(canonical)
        candidates.append((target, label))
    results = []
    age_days = CONFIG.get("max_age_days", 30)
    for target, label in candidates[:source.get("max_candidates", 30)]:
        time.sleep(source.get("delay_seconds", 1))
        page, final_target, skipped = fetch(target, host, robots)
        if skipped or not page:
            continue
        body = clean(" ".join(page.content_parts or page.text_parts))
        title = next((value for key, value in page.meta if key in {"og:title", "twitter:title", "title"} and value), "") or label
        # Only a detail page that itself confirms both an intrusion and a leak
        # enters the public listing.
        if not matches(title + " " + body, INCIDENT_TERMS):
            continue
        if not matches(title + " " + body, LEAK_TERMS):
            continue
        dt = published_date(body, [value for key, value in page.meta if "date" in key])
        if dt and (dt < NOW - timedelta(days=age_days) or dt > NOW + timedelta(days=1)):
            continue
        url = canonical_url(final_target)
        results.append({
            "identity": "url:" + url,
            "id": stable_id("url:" + url),
            "name": clean(title),
            "sector": "公式発表",
            "region": source.get("region", "日本"),
            "date": dt.date().isoformat() if dt else "日付不明",
            "status": "official",
            "source": source["name"],
            "issuer": source["name"],
            "reported_org": source.get("organization", source["name"]),
            "incident_count": None,
            "detail": "公式サイトの発表ページを巡回して検出。件数などの数値は原文で確認できた場合のみ掲載します。",
            "source_url": url,
            "official_host": host,
            "event_key": None,
            "event_scope": "",
            "report": {
                "title": clean(title),
                "date": dt.date().isoformat() if dt else "日付不明",
                "source": source["name"],
                "issuer": source["name"],
                "source_url": url,
                "canonical_url": url,
                "official_host": host,
                "first_seen_at": NOW_TEXT,
                "last_seen_at": NOW_TEXT,
            },
        })
    return results, None


try:
    previous_payload = json.loads(OUT.read_text(encoding="utf-8"))
    previous_events = previous_payload.get("incidents", [])
except (OSError, json.JSONDecodeError, TypeError):
    previous_payload = {}
    previous_events = []

events = {}
by_url = {}
for event in previous_events:
    reports = event.get("reports") or []
    if reports and not all(isinstance(report, dict) for report in reports):
        reports = []
    if not reports and event.get("source_url"):
        reports = [{"source_url": event["source_url"], "canonical_url": canonical_url(event["source_url"]),
                    "title": event.get("name", ""), "date": event.get("date", "日付不明"),
                    "source": event.get("source", "公式発表"), "issuer": event.get("issuer", event.get("source", "公式発表")),
                    "official_host": event.get("official_host", ""), "first_seen_at": event.get("last_seen_at", NOW_TEXT),
                    "last_seen_at": event.get("last_seen_at", NOW_TEXT)}]
        event["reports"] = reports
    events[event.get("id") or stable_id(json.dumps(event, sort_keys=True))] = event
    for report in reports:
        if report.get("source_url"):
            by_url[canonical_url(report["source_url"])] = event

errors = []
successful_sources = 0
new_records = 0
for source in CONFIG.get("crawl_sources", []):
    try:
        found, warning = discover(source)
        if warning:
            errors.append(source["name"] + ": " + warning)
            continue
        successful_sources += 1
        for item in found:
            key = canonical_url(item["source_url"])
            event = by_url.get(key)
            is_existing_event = event is not None
            if event is None:
                event = {
                    "id": item["id"], "event_key": None, "event_scope": "", "reports": [],
                    "reported_org": item["reported_org"], "incident_count": None,
                }
                events[event["id"]] = event
                by_url[key] = event
                new_records += 1
            old_report = next((row for row in event["reports"] if canonical_url(row.get("source_url", "")) == key), None)
            if old_report:
                item["report"]["first_seen_at"] = old_report.get("first_seen_at", NOW_TEXT)
            item["report"]["last_seen_at"] = NOW_TEXT
            if old_report:
                event["reports"] = [item["report"] if canonical_url(row.get("source_url", "")) == key else row for row in event["reports"]]
            else:
                event["reports"].append(item["report"])
            # Keep curated records intact when the crawler rediscovers one of their
            # source links; a generic crawl summary must not replace verified detail/counts.
            if is_existing_event:
                continue
            event.update({key: item[key] for key in ("name", "sector", "region", "date", "status", "source", "issuer",
                                                       "reported_org", "detail", "source_url", "official_host")})
            event["last_seen_at"] = NOW_TEXT
            event["updated_at"] = NOW_TEXT
    except Exception as exc:
        errors.append(source.get("name", source.get("allowed_host", "source")) + ": " + type(exc).__name__ + ": " + str(exc))

if not successful_sources and CONFIG.get("crawl_sources"):
    raise SystemExit("All configured official-site crawls failed; keeping published data. " + "; ".join(errors))

retention_days = CONFIG.get("history_days", 3650)
cutoff = NOW - timedelta(days=retention_days)
retained = []
for event in events.values():
    last_seen = parse_date(event.get("last_seen_at", event.get("updated_at", "")))
    if last_seen is None or last_seen >= cutoff or event.get("incident_count") is not None:
        retained.append(event)

items = sorted(retained, key=lambda row: (row.get("updated_at", ""), row.get("name", "")), reverse=True)[:CONFIG.get("max_items", 200)]
payload = {
    "updated_at": NOW_TEXT,
    "demo": False,
    "automation": "official-site-crawler",
    "crawl_summary": {"sources_succeeded": successful_sources, "new_records": new_records, "warnings": errors},
    "incidents": items,
}
OUT.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
print(f"Crawled {successful_sources} official listing pages; added {new_records} records; kept {len(items)} records.")
if errors:
    print("Crawler warnings: " + "; ".join(errors))
