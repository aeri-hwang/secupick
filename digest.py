"""글 분류, 중복 기사 묶기, 상태 저장(수집 대기열·보낸 기록)."""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from collectors import Item

KEEP_DAYS = 30          # 보낸/수집한 링크 기록 보관 기간
FIRST_RUN_HOURS = 24    # 첫 실행 때 가져올 범위
OVERLAP_HOURS = 6       # 소스별 마지막 수집 시각보다 이만큼 앞까지 겹쳐서 확인 (공백 방지)
MAX_CATCHUP_DAYS = 7    # 오래 멈췄다 재개할 때 최대 며칠 전까지 따라잡을지
RECENT_DAYS = 3         # 보낸 기사와 같은 소식인지 비교할 기간


# ---------------------------------------------------------------- 분류
def _compile(terms: list[str]) -> re.Pattern | None:
    parts = []
    for t in terms or []:
        t = str(t).strip()
        if not t:
            continue
        if re.fullmatch(r"[A-Za-z0-9 .\-]+", t):
            p = r"(?<![A-Za-z0-9])" + re.escape(t)
            if len(t) <= 4 and t[-1].isalnum():
                p += r"(?![A-Za-z0-9])"
            parts.append(p)
        else:
            parts.append(re.escape(t))
    return re.compile("|".join(parts), re.IGNORECASE) if parts else None


class Classifier:
    def __init__(self, rules: dict):
        self.vuln = _compile(rules.get("vuln"))
        self.incident = _compile(rules.get("incident"))
        self.exclude = _compile(rules.get("exclude"))

    def kind_of(self, it: Item) -> str | None:
        if it.kind:
            return it.kind
        text = f"{it.title} {it.summary}"
        if self.vuln and self.vuln.search(text):
            return "vuln"
        if self.incident and self.incident.search(text):
            return "incident"
        if it.default_kind:
            return it.default_kind
        if self.exclude and self.exclude.search(it.title):
            return None
        return "other"

    def apply(self, items: list[Item]) -> list[Item]:
        out = []
        for it in items:
            k = self.kind_of(it)
            if k:
                it.kind = k
                out.append(it)
        return out


# ---------------------------------------------------------------- 상태
class State:
    """state/ 폴더의 JSON 파일들.

    seen.json    : 이미 대기열에 넣었거나 보낸 링크 (다시 넣지 않기 위함)
    pending.json : 수집했지만 아직 메일로 안 보낸 기사
    meta.json    : 소스별 마지막 수집 성공 시각, 마지막 발송 시각
    recent.json  : 최근 며칠간 보낸 기사의 제목·CVE (다음 메일에서 같은 소식을 또 보내지 않기 위함)
    """

    def __init__(self, folder: Path):
        self.folder = folder
        self.seen: dict[str, str] = self._load("seen.json", {})
        self.pending: list[dict] = self._load("pending.json", [])
        self.meta: dict = self._load("meta.json", {})
        self.recent: list[dict] = self._load("recent.json", [])
        self.meta.setdefault("source_ok", {})

    def _load(self, name, default):
        try:
            return json.loads((self.folder / name).read_text("utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            return default

    def since_for(self, source_name: str) -> datetime:
        now = datetime.now(timezone.utc)
        last = self.meta["source_ok"].get(source_name)
        if not last:
            return now - timedelta(hours=FIRST_RUN_HOURS)
        since = datetime.fromisoformat(last) - timedelta(hours=OVERLAP_HOURS)
        return max(since, now - timedelta(days=MAX_CATCHUP_DAYS))

    def mark_source_ok(self, source_name: str, when: datetime) -> None:
        self.meta["source_ok"][source_name] = when.isoformat()

    def add_pending(self, items: list[Item]) -> int:
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        added = 0
        for it in items:
            if it.link in self.seen:
                continue
            self.seen[it.link] = today
            self.pending.append(it.to_dict())
            added += 1
        return added

    def pending_items(self) -> list[Item]:
        return [Item.from_dict(d) for d in self.pending]

    def clear_pending(self) -> None:
        self.pending = []
        self.meta["last_sent"] = datetime.now(timezone.utc).isoformat()

    def remember_sent(self, leads: list[Item]) -> None:
        now = datetime.now(timezone.utc).isoformat()
        for it in leads:
            titles = [it.title] + [r.get("title", "") for r in it.related]
            text = " ".join(titles) + " " + it.summary
            self.recent.append({
                "titles": [t for t in titles if t],
                "cves": sorted(set(c.upper() for c in _CVE.findall(text))),
                "kind": it.kind,
                "at": now,
            })

    def save(self) -> None:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=KEEP_DAYS)).strftime("%Y-%m-%d")
        self.seen = {k: v for k, v in self.seen.items() if v >= cutoff}
        recent_cut = (datetime.now(timezone.utc) - timedelta(days=RECENT_DAYS)).isoformat()
        self.recent = [r for r in self.recent if r["at"] >= recent_cut]
        self.folder.mkdir(parents=True, exist_ok=True)
        for name, data in (("seen.json", self.seen), ("pending.json", self.pending),
                           ("meta.json", self.meta), ("recent.json", self.recent)):
            (self.folder / name).write_text(json.dumps(data, ensure_ascii=False, indent=1, sort_keys=True), "utf-8")


def filter_recent(items: list[Item], since: datetime) -> list[Item]:
    # 날짜가 없는 글은 아직 안 본 글이면 포함 (seen 으로 중복 방지)
    return [i for i in items if not i.published or i.published >= since]


# ---------------------------------------------------------------- 중복 묶기
_CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_BRACKET = re.compile(r"^\s*[\[\(【][^\]\)】]{1,20}[\]\)】]\s*")
_STOP = {"the", "a", "an", "of", "to", "in", "on", "for", "and", "with", "by", "is", "are", "as", "at", "from",
         "new", "after", "over", "via", "its", "says", "now"}
KIND_RANK = {"kev": 0, "vuln": 1, "incident": 2, "other": 3}
CAT_RANK = {"kev": 0, "notice_kr": 1, "news_kr": 2, "news_global": 3}
SIMILARITY = 0.5


def _features(title: str) -> set[str]:
    t = _BRACKET.sub("", title).lower()
    t = re.sub(r"[^\w\s]", " ", t)
    feats = set()
    for w in t.split():
        if re.fullmatch(r"[a-z0-9_]+", w):
            if w not in _STOP and len(w) > 1:
                feats.add(w)
        else:  # 한글 등: 2글자 단위로 쪼개서 비교 (조사·띄어쓰기 차이에 강함)
            feats.update(w[i:i + 2] for i in range(max(1, len(w) - 1)))
    return feats


def _similar(fa: set, fb: set) -> bool:
    if len(fa) < 3 or len(fb) < 3:
        return False
    inter = len(fa & fb)
    return inter / min(len(fa), len(fb)) >= SIMILARITY and inter / len(fa | fb) >= 0.35


def dedupe(items: list[Item], recent: list[dict] | None = None) -> list[Item]:
    """같은 소식을 다룬 기사를 하나로 묶음.

    - 같은 CVE 번호가 나오면 같은 소식
    - 제목이 충분히 비슷하면(겹치는 단어 비율 50% 이상) 같은 소식
    대표 기사는 KEV > 국내 공지 > 국내 뉴스 > 해외 뉴스, 같으면 먼저 나온 기사.
    나머지는 대표 기사 아래 '같은 소식' 링크로 붙음.
    recent 가 주어지면 최근에 이미 보낸 소식과 같은 묶음은 뺌.
    """
    n = len(items)
    parent = list(range(n))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    cves = [set(c.upper() for c in _CVE.findall(f"{i.title} {i.summary}")) for i in items]
    feats = [_features(i.title) for i in items]
    for a in range(n):
        for b in range(a + 1, n):
            if cves[a] & cves[b]:
                union(a, b)
                continue
            if _similar(feats[a], feats[b]):
                union(a, b)

    groups: dict[int, list[Item]] = {}
    for idx, it in enumerate(items):
        groups.setdefault(find(idx), []).append(it)

    far_past = datetime.min.replace(tzinfo=timezone.utc)
    out = []
    for members in groups.values():
        members.sort(key=lambda i: (CAT_RANK.get(i.category, 9), i.published or far_past))
        lead = members[0]
        lead.kind = min((m.kind for m in members), key=lambda k: KIND_RANK.get(k, 9))
        seen_src = {lead.source}
        for m in members[1:]:
            if m.link == lead.link:
                continue
            lead.related.append({"source": m.source, "link": m.link, "title": m.title})
            seen_src.add(m.source)
        if recent and lead.kind != "kev" and _already_sent(members, recent):
            continue  # 이전 메일에서 이미 보낸 소식 (KEV 등재는 새 소식이므로 항상 보냄)
        out.append(lead)

    out.sort(key=lambda i: i.published or far_past, reverse=True)
    return out


def _already_sent(members: list[Item], recent: list[dict]) -> bool:
    cves = set()
    feats = []
    for m in members:
        cves |= set(c.upper() for c in _CVE.findall(f"{m.title} {m.summary}"))
        feats.append(_features(m.title))
    for r in recent:
        if cves & set(r.get("cves", [])):
            return True
        for t in r.get("titles", []):
            ft = _features(t)
            if any(_similar(f, ft) for f in feats):
                return True
    return False
