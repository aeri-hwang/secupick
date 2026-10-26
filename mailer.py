"""HTML 메일 생성과 SMTP 발송."""
from __future__ import annotations

import os
import smtplib
import ssl
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from html import escape

from collectors import Item

KST = timezone(timedelta(hours=9))

INK = "#1d2433"
MUTED = "#5b6475"
LINE = "#e3e6ec"
LINK = "#1f4fd1"
ALERT = "#b42318"


def _time(it: Item) -> str:
    if not it.published:
        return ""
    return it.published.astimezone(KST).strftime("%m/%d %H:%M")


def _item_html(it: Item) -> str:
    meta = escape(it.source)
    t = _time(it)
    if t and it.kind != "kev":
        meta += f" &nbsp;|&nbsp; {t}"
    summary = (
        f'<div style="color:{MUTED};font-size:14px;line-height:1.55;margin-top:4px">{escape(it.summary)}</div>'
        if it.summary else ""
    )
    return (
        f'<tr><td style="padding:12px 0;border-bottom:1px solid {LINE}">'
        f'<a href="{escape(it.link, quote=True)}" style="color:{LINK};font-size:16px;font-weight:600;'
        f'line-height:1.4;text-decoration:none">{escape(it.title)}</a>'
        f'<div style="color:{MUTED};font-size:12px;margin-top:3px">{meta}</div>'
        f"{summary}</td></tr>"
    )


SECTION_COLORS = {"kev": ALERT, "vuln": "#1f5f8b", "incident": "#8a3b12", "other": INK}


def _section(title: str, items: list[Item], color: str) -> str:
    if not items:
        return ""
    rows = "".join(_item_html(i) for i in items)
    return (
        f'<h2 style="font-size:17px;color:{color};margin:28px 0 4px;padding-bottom:6px;'
        f'border-bottom:2px solid {color}">{escape(title)} '
        f'<span style="font-weight:400;color:{MUTED};font-size:14px">{len(items)}</span></h2>'
        f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0">{rows}</table>'
    )


def build_email(items: list[Item], sections: dict, failures: list[tuple[str, str]]) -> tuple[str, str]:
    now = datetime.now(KST)
    date_label = now.strftime("%Y-%m-%d")
    weekday = "월화수목금토일"[now.weekday()]

    groups = {k: [i for i in items if i.kind == k] for k in sections}
    body = "".join(_section(title, groups[k], SECTION_COLORS.get(k, INK)) for k, title in sections.items())

    if not items:
        body += f'<p style="color:{MUTED};font-size:15px;margin:28px 0">지난 실행 이후 새로 올라온 소식이 없습니다.</p>'

    if failures:
        lis = "".join(f"<li><b>{escape(n)}</b>: {escape(e)}</li>" for n, e in failures)
        body += (
            f'<div style="margin-top:32px;padding:12px 14px;background:#f6f7f9;border-radius:6px;'
            f'color:{MUTED};font-size:13px;line-height:1.5"><b style="color:{INK}">수집 실패 {len(failures)}건</b>'
            f' — 주소가 바뀌었거나 해외 접속이 막혔을 수 있어요. config.yaml 의 url 을 확인하세요.'
            f'<ul style="margin:6px 0 0;padding-left:18px">{lis}</ul></div>'
        )

    # 제목에 종류별 개수: 받은편지함에서 바로 파악
    labels = {"kev": "KEV", "vuln": "취약점", "incident": "침해사고", "other": "기타"}
    counts = [f"{labels.get(k, k)} {len(v)}" for k, v in groups.items() if v]
    subject = f"[secupick] {date_label} 보안 브리핑"
    subject += f" · {' / '.join(counts)}" if counts else " · 새 소식 없음"

    summary_line = " / ".join(counts) if counts else "새 소식 없음"
    html = f"""<!doctype html><html><body style="margin:0;background:#ffffff">
<div style="max-width:680px;margin:0 auto;padding:24px 18px;font-family:-apple-system,'Apple SD Gothic Neo','Malgun Gothic','Noto Sans KR',sans-serif;color:{INK}">
  <div style="font-size:24px;font-weight:800;letter-spacing:-0.5px">secupick</div>
  <div style="color:{MUTED};font-size:14px;margin-top:2px">{date_label} ({weekday}) 보안 브리핑 &nbsp;|&nbsp; {summary_line}</div>
  {body}
  <p style="color:{MUTED};font-size:12px;margin-top:36px">secupick 자동 발송 메일. 분류 규칙과 소스는 config.yaml 에서 바꿀 수 있어요.</p>
</div></body></html>"""
    return subject, html


def send_email(subject: str, html: str) -> None:
    host = os.environ.get("SMTP_HOST", "smtp.gmail.com")
    port = int(os.environ.get("SMTP_PORT", "465"))
    user = os.environ["SMTP_USER"]
    password = os.environ["SMTP_PASSWORD"]
    to = [a.strip() for a in os.environ.get("MAIL_TO", user).split(",") if a.strip()]

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = f"secupick <{user}>"
    msg["To"] = ", ".join(to)
    msg.set_content("HTML 메일을 지원하는 메일 앱에서 확인해 주세요.")
    msg.add_alternative(html, subtype="html")

    ctx = ssl.create_default_context()
    if port == 465:
        with smtplib.SMTP_SSL(host, port, context=ctx, timeout=30) as s:
            s.login(user, password)
            s.send_message(msg)
    else:
        with smtplib.SMTP(host, port, timeout=30) as s:
            s.starttls(context=ctx)
            s.login(user, password)
            s.send_message(msg)
