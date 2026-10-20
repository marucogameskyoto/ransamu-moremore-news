import hashlib
import html
import ipaddress
import json
import re
import socket
import time
import urllib.robotparser
import xml.etree.ElementTree as ET
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


def fetch(url, host, max_bytes=2_000_000, allow_external_redirect=False):
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
        final_host = urlparse(final_url).hostname
        if final_host != host:
            if not allow_external_redirect or not final_host or not public_hostname(final_host):
                raise ValueError("Redirect left the source host")
            if not get_robots(final_host).can_fetch(USER_AGENT, final_url):
                return None, None, "redirect target robots.txt disallows this URL"
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
    if source.get("kind") == "news_lead":
        # Use the newsroom only to discover article links. Never publish or
        # summarize secondary reporting; continue only through a clearly
        # labeled external official-source link and verify that page below.
        lead_host = source.get("allowed_host") or urlparse(final_url).hostname
        prefixes = source.get("path_prefixes", [])
        leads = []
        lead_seen = set()
        for href, label in parser.links:
            target = urljoin(final_url, href)
            parsed = urlparse(target)
            if parsed.scheme != "https" or parsed.hostname != lead_host:
                continue
            if not any(parsed.path.startswith(prefix) for prefix in prefixes):
                continue
            if not (matches(label, INCIDENT_TERMS) or matches(label, LEAK_TERMS)):
                continue
            key = canonical_url(target)
            if key not in lead_seen:
                lead_seen.add(key)
                leads.append((target, label))
        last_fetch = None
        delay = float(source.get("delay_seconds_per_host", 1))
        for article_url, article_label in leads[:source.get("max_candidates", 40)]:
            if last_fetch is not None:
                wait = delay - (time.monotonic() - last_fetch)
                if wait > 0:
                    time.sleep(wait)
            last_fetch = time.monotonic()
            try:
                article, article_final, skipped = fetch(article_url, lead_host)
                if skipped or not article:
                    continue
                article_title = next((value for key, value in article.meta
                                      if key in {"og:title", "twitter:title", "title"} and value), "") or article_label
                article_body = clean(" ".join(article.text_parts))
                article_text = article_title + " " + article_body
                if not matches(article_text, INCIDENT_TERMS) or not matches(article_text, LEAK_TERMS):
                    continue
                article_date = published_date(article_body, [value for key, value in article.meta if "date" in key])
                if article_date and (article_date < NOW - timedelta(days=source.get("max_age_days", 45))
                                     or article_date > NOW + timedelta(days=1)):
                    continue
                for official_href, official_label in article.links:
                    if not is_primary_label(official_label):
                        continue
                    official_url = urljoin(article_final, official_href)
                    official_host = urlparse(official_url).hostname
                    if official_host and official_host != lead_host:
                        add(official_url, official_label)
            except Exception:
                # A secondary lead failing to load must not affect official-source
                # discovery from the other configured roundup sources.
                continue
    return rows


def google_news_candidates(source):
    feed_url = source["url"]
    host = urlparse(feed_url).hostname
    if urlparse(feed_url).scheme != "https" or host != "news.google.com" or not public_hostname(host):
        raise ValueError("Google News RSS URL must use news.google.com over HTTPS")
    if not get_robots(host).can_fetch(USER_AGENT, feed_url):
        raise ValueError("Google News RSS robots.txt disallows this URL")
    request = urllib.request.Request(feed_url, headers={"User-Agent": USER_AGENT, "Accept": "application/rss+xml, application/xml"})
    with urllib.request.urlopen(request, timeout=25) as response:
        payload = response.read(2_000_000)
    root = ET.fromstring(payload)
    candidates, seen = [], set()
    items = [node for node in root.iter() if node.tag.rsplit("}", 1)[-1].lower() == "item"]
    for item in items[:source.get("max_candidates", 40)]:
        fields = {node.tag.rsplit("}", 1)[-1].lower(): clean(node.text or "") for node in item}
        title, link = fields.get("title", ""), fields.get("link", "")
        if not link or not matches(title, INCIDENT_TERMS):
            continue
        try:
            article, article_url, skipped = fetch(link, host, allow_external_redirect=True)
            if skipped or not article:
                continue
            article_host = urlparse(article_url).hostname
            article_title, body, date_values = page_summary(article, title)
            if not matches(article_title + " " + body, INCIDENT_TERMS) or not matches(body, LEAK_TERMS):
                continue
            published = published_date(body, date_values)
            if published and (published < NOW - timedelta(days=source.get("max_age_days", 45)) or published > NOW + timedelta(days=1)):
                continue
            for href, label in article.links:
                if not is_primary_label(label):
                    continue
                target = urljoin(article_url, href)
                parsed = urlparse(target)
                key = canonical_url(target)
                if parsed.scheme == "https" and parsed.hostname and parsed.hostname != article_host and key not in seen:
                    seen.add(key)
                    candidates.append({"url": target, "organization": "", "roundup": feed_url})
        except Exception:
            continue
    return candidates


def page_summary(parser, fallback):
    title = next((value for key, value in parser.meta if key in {"og:title", "twitter:title", "title"} and value), "")
    date_values = [value for key, value in parser.meta if "date" in key or key == "pubdate"]
    body = clean(" ".join(parser.text_parts))
    return clean(title) or fallback, body, date_values


def summarize_official(body, title=""):
    """Build a short factual excerpt only from sentences in the official page."""
    excluded = ("プライバシーポリシー", "個人情報保護方針", "お問い合わせ", "サイトマップ", "cookie")
    title_key = clean(title).casefold()
    sentences = [clean(value) for value in re.split(r"(?<=[。！？])", body or "")]
    ranked = []
    for index, sentence in enumerate(sentences):
        if len(sentence) < 22 or any(term in sentence.casefold() for term in excluded):
            continue
        if title_key and sentence.casefold() == title_key:
            continue
        incident = matches(sentence, INCIDENT_TERMS)
        leak = matches(sentence, LEAK_TERMS)
        if not (incident or leak):
            continue
        score = (3 if incident else 0) + (3 if leak else 0)
        if re.search(r"\d", sentence):
            score += 1
        if any(term in sentence for term in ("確認", "公表", "発表", "可能性", "対象")):
            score += 1
        ranked.append((score, index, sentence))
    ranked.sort(key=lambda item: (-item[0], item[1]))
    chosen = sorted(ranked[:2], key=lambda item: item[1])
    summary = "".join(item[2] for item in chosen)
    if not summary:
        summary = "公式発表ページで不正アクセスまたは情報漏えいに関する事案を公表。"
    if len(summary) > 260:
        summary = summary[:259].rsplit("。", 1)[0] + "。"
    return summary


def extract_record_count(body):
    """Return an unambiguous official record count; people counts are excluded."""
    token = re.compile(r"(?:(?:約|最大|およそ|少なくとも)\s*)?(\d[\d,]*(?:\.\d+)?(?:万\d[\d,]*(?:\.\d+)?)?)\s*(件|レコード|ファイル)")
    record_terms = ("個人情報", "メールアドレス", "会員情報", "情報漏えい", "情報流出", "漏えい", "漏洩", "流出", "レコード", "ファイル", "データ")
    values = set()
    for sentence in re.split(r"[。！？\n]", body or ""):
        if not any(term in sentence for term in record_terms) or "人数" in sentence:
            continue
        for found in token.finditer(sentence):
            raw = found.group(1).replace(",", "")
            if "万" in raw:
                high, _, low = raw.partition("万")
                try:
                    value = int(float(high) * 10000) + (int(low.replace(",", "")) if low else 0)
                except ValueError:
                    continue
            else:
                try:
                    value = int(float(raw))
                except ValueError:
                    continue
            if value >= 0:
                values.add(value)
    return next(iter(values)) if len(values) == 1 else None


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
    if event.get("incident_count") is None and event.get("leaked_records") is None:
        count = extract_record_count(event.get("detail", ""))
        if count is not None:
            event["leaked_records"] = count

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
        if source.get("kind") == "google_news_rss":
            roundups_succeeded += 1
            candidates = google_news_candidates(source)
        else:
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
            canonical = canonical_url(official_url)
            existing = by_url.get(canonical)
            if existing is not None and (existing.get("detail") or not existing.get("discovered_from")):
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
                summary = summarize_official(body, title)
                record_count = extract_record_count(body)
                if existing is not None:
                    # Backfill only crawler-discovered records, using sentences from
                    # the verified official page. Never overwrite curated text.
                    changed = False
                    if not existing.get("detail") and existing.get("discovered_from") and summary:
                        existing["detail"] = summary
                        changed = True
                    if existing.get("incident_count") is None and existing.get("leaked_records") is None and record_count is not None:
                        existing["leaked_records"] = record_count
                        changed = True
                    if changed:
                        existing["updated_at"] = NOW_TEXT
                    if not existing.get("posted_at"):

                        first_seen = sorted(row.get("first_seen_at") for row in existing.get("reports", [])

                                            if row.get("first_seen_at"))

                        existing["posted_at"] = first_seen[0] if first_seen else NOW_TEXT

                        changed = True

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
                    "posted_at": NOW_TEXT,
                    "status": "official",
                    "source": org,
                    "issuer": org,
                    "reported_org": org,
                    "incident_count": None,
                    "incident_count_label": None,
                    "affected_people": None,
                    "leaked_records": record_count,
                    "detail": summary,
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

# Revisit already-listed official links whose factual overview is still missing.
backfill_host_delay = {}
for event in events:
    if event.get("detail") or not event.get("discovered_from") or not event.get("source_url"):
        continue
    official_url = event["source_url"]
    parsed = urlparse(official_url)
    host = parsed.hostname
    if not host or parsed.scheme != "https" or host != event.get("official_host"):
        errors.append(str(host or "unknown host") + ": incomplete article summary has an invalid official URL")
        continue
    delay = float(CONFIG.get("backfill_delay_seconds_per_host", 1))
    last_fetch = backfill_host_delay.get(host)
    if last_fetch is not None:
        wait = delay - (time.monotonic() - last_fetch)
        if wait > 0:
            time.sleep(wait)
    backfill_host_delay[host] = time.monotonic()
    try:
        page, final_url, skipped = fetch(official_url, host)
        if skipped or not page:
            if skipped:
                errors.append(host + ": summary backfill skipped: " + skipped)
            continue
        title, body, date_values = page_summary(page, event.get("name", "公式発表"))
        combined = title + " " + body
        if not matches(combined, INCIDENT_TERMS) or not matches(combined, LEAK_TERMS):
            errors.append(host + ": official page did not verify as an incident and information exposure")
            continue
        event["detail"] = summarize_official(body, title)
        record_count = extract_record_count(body)
        if event.get("incident_count") is None and event.get("leaked_records") is None and record_count is not None:
            event["leaked_records"] = record_count
        published = published_date(body, date_values)
        if event.get("date") in (None, "", "日付不明") and date_values and published:
            event["date"] = published.date().isoformat()
        reports = event.get("reports") or []
        for report in reports:
            if report.get("date") in (None, "", "日付不明") and date_values and published:
                report["date"] = published.date().isoformat()
        event["updated_at"] = NOW_TEXT
        event["last_seen_at"] = NOW_TEXT
    except Exception as exc:
        errors.append(host + ": summary backfill: " + type(exc).__name__ + ": " + str(exc))
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
