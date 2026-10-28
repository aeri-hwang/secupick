"""Slack 알림 (Incoming Webhook).

메일과 같은 내용(같은 기사, 같은 분류, 같은 시각)을 Slack 채널로도 보냅니다.
SLACK_WEBHOOK_URL 이 설정되어 있을 때만 동작하고, 없으면 아무것도 하지 않습니다.
주소를 여러 개(줄바꿈 또는 쉼표로 구분) 넣으면 모든 곳으로 보냅니다. 예: 개인 DM + 팀 채널
Slack 전송이 실패해도 메일 발송과 기록에는 영향을 주지 않습니다.
"""
from __future__ import annotations

import os
import re
import time
from datetime import timedelta, timezone

import requests

from collectors import Item

KST = timezone(timedelta(hours=9))
MAX_TEXT = 2800      # Slack 블록 하나에 넣을 최대 글자 수 (한도 3000)
MAX_BLOCKS = 45      # 메시지 하나당 최대 블록 수 (한도 50)
MAX_MSG_CHARS = 12000  # 메시지 하나당 글자 수 (길면 Slack 이 잘라서 표시하므로 나눠 보냄)
SUMMARY_LEN = 120
MAX_RELATED = 8     # '같은 소식' 링크를 최대 몇 개까지 보여줄지 (나머지는 '외 N건')


def _esc(text: str) -> str:
    return (text or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _link(url: str, label: str) -> str:
    return f"<{url}|{_esc(label).replace('|', '¦')}>"


def _item_line(it: Item) -> str:
    meta = it.source
    if it.published and it.kind != "kev":
        meta += f" · {it.published.astimezone(KST).strftime('%m/%d %H:%M')}"
    line = f"• *{_link(it.link, it.title)}*\n   _{_esc(meta)}_"
    if it.summary:
        s = it.summary if len(it.summary) <= SUMMARY_LEN else it.summary[:SUMMARY_LEN - 1] + "…"
        line += f"\n   {_esc(s)}"
    if it.related:
        shown = it.related[:MAX_RELATED]
        links = ", ".join(_link(r["link"], r["source"]) for r in shown)
        more = f" 외 {len(it.related) - len(shown)}건" if len(it.related) > len(shown) else ""
        line += f"\n   같은 소식 {len(it.related)}건: {links}{more}"
    return line


def _chunks(lines: list[str]) -> list[str]:
    out, cur = [], ""
    for ln in lines:
        if cur and len(cur) + len(ln) + 2 > MAX_TEXT:
            out.append(cur)
            cur = ""
        cur = f"{cur}\n\n{ln}" if cur else ln
    if cur:
        out.append(cur)
    return out


def build_blocks(items: list[Item], sections: dict, failures: list[tuple[str, str]],
                 subject: str, alert: bool) -> list[dict]:
    blocks: list[dict] = [{"type": "header", "text": {"type": "plain_text", "text": subject[:150]}}]

    warn = []
    if failures:
        lines = "\n".join(f"• *{_esc(n)}*: {_esc(e)}" for n, e in failures)
        warn = [{"type": "section", "text": {"type": "mrkdwn", "text": (
            f":warning: *수집 문제 {len(failures)}곳* — 이 사이트의 새 기사가 빠지고 있을 수 있어요. "
            f"config.yaml 의 url 을 확인하세요.\n{lines}")[:MAX_TEXT]}}]
        if alert:  # 메일과 같이: 낮 알림은 경고를 맨 위에
            blocks += warn

    for key, title in sections.items():
        group = [i for i in items if i.kind == key]
        if not group:
            continue
        blocks.append({"type": "divider"})
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": f"*{_esc(title)}* ({len(group)})"}})
        for text in _chunks([_item_line(i) for i in group]):
            blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": text}})

    if not items and not alert:
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": "지난 메일 이후 새로 올라온 소식이 없습니다."}})

    if warn and not alert:  # 아침 브리핑은 경고를 맨 아래에
        blocks.append({"type": "divider"})
        blocks += warn
    return blocks


def _webhook_urls() -> list[str]:
    """SLACK_WEBHOOK_URL 에 주소를 여러 개 넣을 수 있음 (줄바꿈 또는 쉼표로 구분)."""
    raw = os.environ.get("SLACK_WEBHOOK_URL", "")
    return [u.strip() for u in re.split(r"[\s,]+", raw) if u.strip()]


def _post(url: str, parts: list[list[dict]], subject: str) -> None:
    for n, part in enumerate(parts, 1):
        text = subject if len(parts) == 1 else f"{subject} ({n}/{len(parts)})"
        resp = requests.post(url, json={"text": text, "blocks": part}, timeout=20)
        if resp.status_code != 200:
            raise RuntimeError(f"{resp.status_code} {resp.text[:200]}")
        if n < len(parts):
            time.sleep(1.1)  # Slack 웹훅 속도 제한(초당 1건) 지키기


def send_slack(items: list[Item], sections: dict, failures: list[tuple[str, str]],
               subject: str, alert: bool) -> int:
    """설정된 모든 웹훅으로 전송. 성공한 곳 수를 돌려주고, 한 곳이라도 실패하면 예외."""
    urls = _webhook_urls()
    if not urls:
        return 0
    blocks = build_blocks(items, sections, failures, subject, alert)
    parts, cur, size = [], [], 0
    for b in blocks:
        n = len(b.get("text", {}).get("text", ""))
        if cur and (len(cur) >= MAX_BLOCKS or size + n > MAX_MSG_CHARS):
            parts.append(cur)
            cur, size = [], 0
        cur.append(b)
        size += n
    if cur:
        parts.append(cur)

    ok, errors = 0, []
    for idx, url in enumerate(urls, 1):
        try:  # 한 곳이 실패해도 나머지 곳에는 보냄
            _post(url, parts, subject)
            ok += 1
        except Exception as e:
            errors.append(f"{idx}번째 주소: {e}")
    if errors:
        raise RuntimeError(f"{ok}/{len(urls)}곳 성공, 실패: " + " / ".join(errors))
    return ok
