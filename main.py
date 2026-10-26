"""secupick: 보안 뉴스·공지를 빠짐없이 모아 매일 아침 메일로 보내는 프로그램.

사용법
  python main.py collect    수집만 해서 대기열(state/pending.json)에 쌓음  (밤: 3시간마다)
  python main.py send       아침 브리핑: 쌓인 기사를 중복 묶어서 메일 발송  (매일 오전 7시)
  python main.py alert      낮 알림: 새 기사 중 이미 보낸 소식과 겹치지 않는 것이 있으면 바로 발송  (낮: 1시간마다)
  python main.py dry-run    send 와 같지만 메일 대신 preview.html 저장, 상태도 안 바꿈
  python main.py check      소스별로 수집이 되는지만 점검
"""
from __future__ import annotations

import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

import yaml

from collectors import collect
from digest import Classifier, State, dedupe, filter_recent
from mailer import build_email, send_email

ROOT = Path(__file__).parent


def gather(cfg: dict, state: State) -> list[tuple[str, str]]:
    """모든 소스를 수집해 새 기사를 대기열에 넣고, 실패 목록을 돌려줌."""
    classifier = Classifier(cfg.get("classify", {}))
    failures = []

    def run(src):
        try:
            return src, collect(src), None
        except Exception as e:  # 한 소스가 실패해도 나머지는 계속
            return src, [], f"{type(e).__name__}: {e}"[:200]

    started = datetime.now(timezone.utc)
    total_new = 0
    with ThreadPoolExecutor(max_workers=8) as pool:
        for src, got, err in pool.map(run, cfg["sources"]):
            if err:
                failures.append((src["name"], err))
                print(f"  ✗ {src['name']}: {err}")
                continue
            fresh = filter_recent(got, state.since_for(src["name"]))
            added = state.add_pending(classifier.apply(fresh))
            state.mark_source_ok(src["name"], started)
            total_new += added
            print(f"  ✓ {src['name']}: 피드 {len(got)}건, 새로 추가 {added}건")
    print(f"대기열: 새로 {total_new}건 추가, 총 {len(state.pending)}건")
    return failures


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else "send"
    mode = mode.lstrip("-")
    if mode not in ("collect", "send", "alert", "dry-run", "check"):
        print(__doc__)
        return 2

    cfg = yaml.safe_load((ROOT / "config.yaml").read_text("utf-8"))
    state = State(ROOT / "state")

    print("수집 중…")
    failures = gather(cfg, state)

    if mode == "check":
        return 1 if failures else 0
    if mode == "collect":
        state.save()
        return 0

    items = dedupe(state.pending_items(), state.recent)

    if mode == "alert":
        if not items:
            print("새 소식 없음 (알림 안 보냄)")
            state.clear_pending()  # 이미 보낸 소식과 겹친 기사들은 버림
            state.save()
            return 0
        failures = []  # 낮 알림에는 수집 실패 안내를 넣지 않음 (아침 브리핑에서만 안내)

    subject, html = build_email(items, cfg["sections"], failures, alert=(mode == "alert"))

    if mode == "dry-run":
        (ROOT / "preview.html").write_text(html, "utf-8")
        print(f"미리보기 저장: preview.html ({len(html.encode()) // 1024}KB)\n제목: {subject}")
        return 0

    if not items and not cfg.get("send_when_empty", True):
        print("새 소식이 없어 발송하지 않습니다.")
        state.save()
        return 0

    try:
        send_email(subject, html)
    except Exception:
        state.save()  # 발송 실패해도 수집한 기사는 대기열에 남겨 다음 발송 때 보냄
        raise
    print(f"발송 완료: {subject}")
    state.remember_sent(items)
    state.clear_pending()
    state.save()
    return 0


if __name__ == "__main__":
    sys.exit(main())
