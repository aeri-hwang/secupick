"""소스별 수집기. 각 수집기는 Item 리스트를 반환하고, 실패하면 예외를 던집니다."""
from __future__ import annotations

import html
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
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
    related: list = field(default_factory=list)  # 같은 소식을 다룬 다른 기사 [{source, link}]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["published"] = self.published.isoformat() if self.published else None
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Item":
        d = dict(d)
        if d.get("published"):
            d["published"] = datetime.fromisoformat(d["published"])
        return cls(**d)


def _fetch(url: str) -> bytes:
    resp = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT)
    resp.raise_for_status()
    return resp.content


def _clean(text: str, limit: int = 220) -> str:
    text = re.sub(r"<[^>]+>", " ", text or "")
    text = html.unescape(text)
    text = re.sub(r"\s+", " ", text).strip()
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


KST = timezone(timedelta(hours=9))
_TZ_IN_STRING = re.compile(r"([+-]\d{2}:?\d{2}|Z|GMT|UTC|UT|KST|[ECMP][SD]T)\s*$", re.IGNORECASE)


def _entry_time(entry, kst: bool = False, force_kst: bool = False) -> datetime | None:
    """기사 시각을 UTC 로 반환.

    국내 사이트(kst=True)는 RSS 시각 표기가 부정확한 경우가 많아서 보정함:
    1) 시각에 시간대 표시가 없으면 한국 시간으로 간주
    2) 한국 시간을 UTC(+0000)로 잘못 표기해 '미래 시각'이 되면 9시간을 빼서 바로잡음
    force_kst=True 인 소스는 표기와 상관없이 적힌 시각을 한국 시간으로 읽음
    """
    raw = ""
    for key in ("published", "updated", "pubDate"):
        if entry.get(key):
            raw = str(entry.get(key)).strip()
            break

    dt = None
    for key in ("published_parsed", "updated_parsed"):
        t = entry.get(key)
        if t:
            dt = datetime(*t[:6], tzinfo=timezone.utc)
            break
    if dt is None and raw:
        try:
            dt = parsedate_to_datetime(raw)
            dt = dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except (TypeError, ValueError):
            return None
    if dt is None:
        return None

    if force_kst:
        wall = dt.astimezone(timezone.utc) if dt.tzinfo == timezone.utc else dt
        # 적힌 숫자(벽시계 시각)를 그대로 한국 시간으로 해석
        m = re.search(r"(\d{1,2}):(\d{2})(?::(\d{2}))?", raw)
        if m and raw:
            try:
                base = parsedate_to_datetime(raw)
                return base.replace(tzinfo=KST).astimezone(timezone.utc)
            except (TypeError, ValueError):
                pass
        return wall.replace(tzinfo=KST).astimezone(timezone.utc)

    if kst:
        if raw and not _TZ_IN_STRING.search(raw):
            dt = dt.replace(tzinfo=KST).astimezone(timezone.utc) if dt.tzinfo == timezone.utc else dt
        now = datetime.now(timezone.utc)
        if dt > now + timedelta(minutes=15) and dt - timedelta(hours=9) <= now + timedelta(minutes=15):
            dt -= timedelta(hours=9)
    return dt


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
            published=_entry_time(
                e,
                kst=source.get("category") in ("news_kr", "notice_kr"),
                force_kst=bool(source.get("force_kst")),
            ),
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
