"""글 분류, 필터링, 중복 제거(이미 보낸 글 기록)."""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .collectors import Item

KEEP_DAYS = 30  # 보낸 링크 기록을 며칠간 보관할지


def _compile(terms: list[str]) -> re.Pattern | None:
    parts = []
    for t in terms or []:
        t = str(t).strip()
        if not t:
            continue
        if re.fullmatch(r"[A-Za-z0-9 .\-]+", t):
            # 영문: 다른 단어 중간에 걸리지 않게 앞쪽 경계를 둠.
            # 짧은 단어(4자 이하, 예: RCE, APT, bug)는 뒤쪽 경계도 둠.
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
        """분류 결과를 돌려줌. 메일에서 뺄 글이면 None."""
        if it.kind:  # KEV 처럼 수집 단계에서 이미 정해진 경우
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


class SeenStore:
    def __init__(self, path: Path):
        self.path = path
        try:
            self.data: dict[str, str] = json.loads(path.read_text("utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            self.data = {}

    def __contains__(self, link: str) -> bool:
        return link in self.data

    def add(self, links: list[str]) -> None:
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        for link in links:
            self.data[link] = today

    def save(self) -> None:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=KEEP_DAYS)).strftime("%Y-%m-%d")
        self.data = {k: v for k, v in self.data.items() if v >= cutoff}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.data, ensure_ascii=False, indent=0, sort_keys=True), "utf-8")


def select_new(items: list[Item], seen: SeenStore, lookback_hours: int, per_source: int) -> list[Item]:
    cutoff = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)
    out, per_count, links = [], {}, set()
    # 최신 글 우선
    items = sorted(items, key=lambda i: i.published or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
    for it in items:
        if it.link in seen or it.link in links:
            continue
        if it.published and it.published < cutoff:
            continue
        if per_count.get(it.source, 0) >= per_source:
            continue
        per_count[it.source] = per_count.get(it.source, 0) + 1
        links.add(it.link)
        out.append(it)
    return out
