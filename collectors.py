"""소스별 수집기. 각 수집기는 Item 리스트를 반환하고, 실패하면 예외를 던집니다."""
from __future__ import annotations

import html
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

import feedparser
import requests

USER_AGENT = "Mozilla/5.0 (compatible; secupick/1.0; +daily security digest)"
TIMEOUT = 20


@dataclass
class Item:
    title: str
    link: str
    source: str
    category: str
    published: datetime | None = None
    summary: str = ""
    kind: str = ""          # kev / vuln / incident / other (분류 결과)
    default_kind: str = ""  # 분류 단어에 안 걸릴 때 쓸 기본값


def _fetch(url: str) -> bytes:
    resp = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT)
    resp.raise_for_status()
    return resp.content


def _clean(text: str, limit: int = 220) -> str:
    text = re.sub(r"<[^>]+>", " ", text or "")
    text = html.unescape(text)
    text = re.sub(r"\s+", " ", text).strip()
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def _entry_time(entry) -> datetime | None:
    for key in ("published_parsed", "updated_parsed"):
        t = entry.get(key)
        if t:
            return datetime(*t[:6], tzinfo=timezone.utc)
    for key in ("published", "updated", "pubDate"):
        raw = entry.get(key)
        if raw:
            try:
                dt = parsedate_to_datetime(raw)
                return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
            except (TypeError, ValueError):
                pass
    return None


def collect_rss(source: dict) -> list[Item]:
    feed = feedparser.parse(_fetch(source["url"]))
    if feed.bozo and not feed.entries:
        raise ValueError(f"RSS 형식을 읽을 수 없음: {feed.bozo_exception}")
    items = []
    for e in feed.entries:
        link = (e.get("link") or "").strip()
        title = _clean(e.get("title", ""), 200)
        if not link or not title:
            continue
        items.append(Item(
            title=title,
            link=link,
            source=source["name"],
            category=source["category"],
            published=_entry_time(e),
            summary=_clean(e.get("summary", "") or e.get("description", "")),
            default_kind=source.get("default_kind", ""),
        ))
    return items


def collect_cisa_kev(source: dict) -> list[Item]:
    import json
    data = json.loads(_fetch(source["url"]))
    items = []
    for v in data.get("vulnerabilities", []):
        try:
            added = datetime.strptime(v["dateAdded"], "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except (KeyError, ValueError):
            continue
        cve = v.get("cveID", "")
        ransomware = v.get("knownRansomwareCampaignUse") == "Known"
        title = f"{cve} · {v.get('vendorProject', '')} {v.get('product', '')}".strip()
        summary = v.get("shortDescription", "")
        if ransomware:
            summary = "[랜섬웨어 악용 확인] " + summary
        if v.get("dueDate"):
            summary += f" (미 연방기관 조치 기한: {v['dueDate']})"
        items.append(Item(
            title=title,
            link=f"https://nvd.nist.gov/vuln/detail/{cve}",
            source=source["name"],
            category=source["category"],
            # KEV는 날짜만 있으므로 해당 날짜 하루 끝으로 잡아 lookback 계산에서 누락되지 않게 함
            published=added.replace(hour=23, minute=59),
            summary=_clean(summary, 300),
            kind="kev",
        ))
    return items


COLLECTORS = {
    "rss": collect_rss,
    "cisa_kev": collect_cisa_kev,
}


def collect(source: dict) -> list[Item]:
    kind = source.get("type", "rss")
    if kind not in COLLECTORS:
        raise ValueError(f"알 수 없는 type: {kind}")
    return COLLECTORS[kind](source)
