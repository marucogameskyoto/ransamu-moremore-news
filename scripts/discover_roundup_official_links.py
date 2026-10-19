import hashlib
import html
import ipaddress
import json
import re
import socket
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
GROUPS = {key: [str(term).casefold() for term in values] for key, values in CONFIG.get("match_groups", {}).items()}
INCIDENT_TERMS = [str(term).casefold() for term in CONFIG.get("publication_incident_terms", GROUPS.get("incident", []))]
LEAK_TERMS = GROUPS.get("leak", [])
USER_AGENT = "RansamuMoreMoreDigest/1.0 (official disclosure index; contact: repository owner)"
TRACKING_PARAMS = {"fbclid", "gclid", "ref", "source"}
PRIMARY_LABELS = tuple(x.casefold() for x in CONFIG.get(
    "primary_source_labels", ["原文", "公式発表", "公式サイト", "公表文"]
))


def clean(value):
    return re.sub(r"\s+", " ", html.unescape(value or "")).strip()


def canonical_url(value):
    parsed = urlparse(value)
    query = [(key, val) for key, val in parse_qsl(parsed.query, keep_blank_values=True)
             if not key.casefold().startswith("utm_") and key.casefold() not in TRACKING_PARAMS]
    path = parsed.path.rstrip("/") or "/"
    return urlunparse((parsed.scheme.lower(), parsed.netloc.lower(), path, "", urlencode(sorted(query)), ""))


def stable_id(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:20]


def matches(text, terms):
    folded = (text or "").casefold()
    return any(term in folded for term in terms)


def parse_date(value):
    if not value:
        return None
    value = value.strip()
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except (ValueError, OverflowError):
        return None


def published_date(text, values):
    for value in values:
        parsed = parse_date(value)
        if parsed:
            return parsed
    found = re.search(r"(20\d{2})\s*[年./-]\s*(\d{1,2})\s*[月./-]\s*(\d{1,2})", text or "")
    if found:
        try:
            return datetime(int(found.group(1)), int(found.group(2)), int(found.group(3)), tzinfo=timezone.utc)
        except ValueError:
            return None
    return None


class DocumentParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []
        self.text_parts = []
        self.meta = []
        self.rows = []
        self.row = None
        self.cell = None
        self.anchor = None
        self.title_active = False
        self.suppressed = 0

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        tag = tag.lower()
        if tag in {"script", "style", "noscript", "svg"}:
            self.suppressed += 1
        if tag == "tr":
            if self.row is not None:
                self.rows.append(self.row)
            self.row = {"cells": []}
            self.cell = None
        elif tag in {"td", "th"} and self.row is not None:
            self.cell = {"parts": [], "links": []}
        if tag == "a":
            self.anchor = {"href": attrs.get("href", ""), "parts": []}
        elif tag == "meta":
            key = (attrs.get("property") or attrs.get("name") or "").casefold()
            if key in {"og:title", "twitter:title", "article:published_time", "date", "dc.date", "pubdate"}:
                self.meta.append((key, attrs.get("content", "")))
        elif tag == "time" and attrs.get("datetime"):
            self.meta.append(("date", attrs["datetime"]))
        elif tag == "title":
            self.title_active = True

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag in {"script", "style", "noscript", "svg"} and self.suppressed:
            self.suppressed -= 1
        if tag == "a" and self.anchor is not None:
            link = (self.anchor["href"], clean(" ".join(self.anchor["parts"])))
            self.links.append(link)
            if self.cell is not None:
                self.cell["links"].append(link)
            self.anchor = None
        elif tag in {"td", "th"} and self.cell is not None and self.row is not None:
            self.cell["text"] = clean(" ".join(self.cell["parts"]))
            self.row["cells"].append(self.cell)
            self.cell = None
        elif tag == "tr" and self.row is not None:
            self.rows.append(self.row)
            self.row = None
            self.cell = None
        elif tag == "title":
            self.title_active = False

    def handle_data(self, data):
        if self.suppressed:
            return
        value = data.strip()
        if value:
            self.text_parts.append(value)
            if self.cell is not None:
                self.cell["parts"].append(value)
            if self.anchor is not None:
                self.anchor["parts"].append(value)
            if self.title_active:
                self.meta.append(("title", value))


def public_hostname(host):
    if not host or host.casefold() in {"localhost", "localhost.localdomain"}:
        return False
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)}
    except OSError:
        return False
    return bool(addresses) and all(ipaddress.ip_address(address).is_global for address in addresses)


ROBOTS = {}


def get_robots(host):
    if host not in ROBOTS:
        parser = urllib.robotparser.RobotFileParser()
        parser.set_url("https://" + host + "/robots.txt")
        try:
            parser.read()
        except Exception:
            parser.disallow_all = True
        ROBOTS[host] = parser
    return ROBOTS[host]


def fetch(url, host, max_bytes=2_000_000):
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname != host or not public_hostname(host):
        raise ValueError("URL is not a public HTTPS page on the expected host")
    robots = get_robots(host)
    if not robots.can_fetch(USER_AGENT, url):
        return None, None, "robots.txt disallows this URL"
    request = urllib.request.Request(url, headers={
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml",
    })
    with urllib.request.urlopen(request, timeout=20) as response:
        final_url = response.geturl()
        if urlparse(final_url).hostname != host:
            raise ValueError("Redirect left the source host")
        if response.headers.get_content_type() not in {"text/html", "application/xhtml+xml"}:
            return None, None, "not an HTML page"
        charset = response.headers.get_content_charset() or "utf-8"
        payload = response.read(max_bytes + 1)
    if len(payload) > max_bytes:
        raise ValueError("page exceeded size limit")
    parser = DocumentParser()
    parser.feed(payload.decode(charset, errors="replace"))
    return parser, final_url, None


def is_primary_label(label):
    value = (label or "").casefold()
    return bool(value) and any(marker in value for marker in PRIMARY_LABELS)


def roundup_candidates(source, parser, final_url):
    rows = []
    seen = set()

    def add(href, label, organization=""):
        target = urljoin(final_url, href)
        parsed = urlparse(target)
        if parsed.scheme != "https" or not parsed.hostname or parsed.hostname == urlparse(final_url).hostname:
            return
        if not is_primary_label(label):
            return
        key = canonical_url(target)
        if key in seen:
            return
        seen.add(key)
        rows.append({
            "url": target,
            "organization": clean(organization),
            "roundup": source["url"],
        })

    for row in parser.rows:
        cells = row.get("cells", [])
        for cell in cells:
            for href, label in cell.get("links", []):
                if not is_primary_label(label):
                    continue
                organization = re.sub(r"[（(]?\s*(原文|公式発表|公式サイト|公表文)\s*[）)]?", "", cell.get("text", ""), flags=re.I)
                organization = re.sub(r"^[0-9年月日/.-]+", "", organization).strip(" ：:｜|・")
                if not organization:
                    organization = next((item.get("text", "") for item in cells
                                         if item.get("text") and not re.fullmatch(r"[0-9年月日/ .-]+", item["text"])), "")
                add(href, label, organization)
    for href, label in parser.links:
        add(href, label)
    return rows


def page_summary(parser, fallback):
    title = next((value for key, value in parser.meta if key in {"og:title", "twitter:title", "title"} and value), "")
    date_values = [value for key, value in parser.meta if "date" in key or key == "pubdate"]
    body = clean(" ".join(parser.text_parts))
    return clean(title) or fallback, body, date_values


try:
    payload = json.loads(OUT.read_text(encoding="utf-8"))
    events = payload.get("incidents", [])
except (OSError, json.JSONDecodeError, TypeError):
    payload, events = {}, []

by_url = {}
for event in events:
    reports = event.get("reports") or []
    if not reports and event.get("source_url"):
        reports = [{"source_url": event["source_url"]}]
    for report in reports:
        if report.get("source_url"):
            by_url[canonical_url(report["source_url"])] = event

errors = []
roundups_succeeded = 0
verified_pages = 0
new_records = 0
candidate_count = 0
for source in CONFIG.get("roundup_sources", []):
    try:
        roundup_host = urlparse(source["url"]).hostname
        if not roundup_host:
            raise ValueError("Roundup URL has no hostname")
        listing, final_url, skipped = fetch(source["url"], roundup_host)
        if skipped or not listing:
            errors.append(source.get("name", roundup_host) + ": " + (skipped or "page unavailable"))
            continue
        roundups_succeeded += 1
        candidates = roundup_candidates(source, listing, final_url)
        candidate_count += len(candidates)
        host_delay = {}
        for candidate in candidates[:source.get("max_candidates", 500)]:
            official_url = candidate["url"]
            if canonical_url(official_url) in by_url:
                continue
            host = urlparse(official_url).hostname
            if not host:
                continue
            last_fetch = host_delay.get(host)
            delay = float(source.get("delay_seconds_per_host", 1))
            if last_fetch is not None:
                wait = delay - (time.monotonic() - last_fetch)
                if wait > 0:
                    time.sleep(wait)
            host_delay[host] = time.monotonic()
            try:
                detail_page, official_url, skipped = fetch(official_url, host)
                if skipped or not detail_page:
                    continue
                title, body, date_values = page_summary(detail_page, candidate.get("organization", "公式発表"))
                if not matches(title + " " + body, INCIDENT_TERMS):
                    continue
                if not matches(title + " " + body, LEAK_TERMS):
                    continue
                dt = published_date(body, date_values)
                if dt and (dt < NOW - timedelta(days=source.get("max_age_days", 3650)) or dt > NOW + timedelta(days=1)):
                    continue
                verified_pages += 1
                canonical = canonical_url(official_url)
                existing = by_url.get(canonical)
                if existing is not None:
                    # Never replace a hand-curated record. Add the primary report
                    # only when the same URL was not already attached to it.
                    reports = existing.setdefault("reports", [])
                    if not any(canonical_url(row.get("source_url", "")) == canonical for row in reports):
                        reports.append({
                            "title": title, "date": dt.date().isoformat() if dt else "日付不明",
                            "source": candidate.get("organization") or host,
                            "issuer": candidate.get("organization") or host,
                            "source_url": canonical, "canonical_url": canonical,
                            "official_host": host, "first_seen_at": NOW_TEXT, "last_seen_at": NOW_TEXT,
                        })
                    existing["last_seen_at"] = NOW_TEXT
                    continue
                org = candidate.get("organization") or title
                item = {
                    "id": stable_id("url:" + canonical),
                    "event_key": None,
                    "event_scope": "",
                    "name": title,
                    "sector": "公式発表",
                    "region": source.get("region", "日本"),
                    "date": dt.date().isoformat() if dt else "日付不明",
                    "status": "official",
                    "source": org,
                    "issuer": org,
                    "reported_org": org,
                    "incident_count": None,
                    "incident_count_label": None,
                    "affected_people": None,
                    "leaked_records": None,
                    "detail": "",
                    "source_url": canonical,
                    "official_host": host,
                    "discovered_from": source["url"],
                    "last_seen_at": NOW_TEXT,
                    "updated_at": NOW_TEXT,
                    "reports": [{
                        "title": title,
                        "date": dt.date().isoformat() if dt else "日付不明",
                        "source": org,
                        "issuer": org,
                        "source_url": canonical,
                        "canonical_url": canonical,
                        "official_host": host,
                        "first_seen_at": NOW_TEXT,
                        "last_seen_at": NOW_TEXT,
                    }],
                }
                events.append(item)
                by_url[canonical] = item
                new_records += 1
            except Exception as exc:
                errors.append(host + ": " + type(exc).__name__ + ": " + str(exc))
    except Exception as exc:
        errors.append(source.get("name", "roundup") + ": " + type(exc).__name__ + ": " + str(exc))

if CONFIG.get("roundup_sources") and roundups_succeeded == 0:
    raise SystemExit("All roundup discovery pages failed; keeping published data. " + "; ".join(errors))

items = sorted(events, key=lambda row: (row.get("updated_at", ""), row.get("date", ""), row.get("name", "")), reverse=True)
items = items[:CONFIG.get("max_items", 1000)]
payload.update({
    "updated_at": NOW_TEXT,
    "demo": False,
    "automation": "official-source-verified-roundup-discovery",
    "discovery_summary": {
        "roundup_pages_succeeded": roundups_succeeded,
        "official_links_found": candidate_count,
        "official_pages_verified": verified_pages,
        "new_records": new_records,
        "warnings": errors,
    },
    "incidents": items,
})
OUT.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
print(f"Verified {verified_pages} official pages from {candidate_count} primary-source links; added {new_records} records.")
if errors:
    print("Discovery warnings: " + "; ".join(errors))
