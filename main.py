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
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

from collectors import collect
from digest import Classifier, State, dedupe, filter_recent
from mailer import build_email, send_email

ROOT = Path(__file__).parent


ALERT_AFTER = 3  # 낮 알림: 같은 소스가 연속 3번(약 45분) 문제일 때 경고


def gather(cfg: dict, state: State) -> list[tuple[str, str]]:
    """모든 소스를 수집해 새 기사를 대기열에 넣고, 현재 문제가 있는 소스 목록을 돌려줌.

    문제로 보는 경우
    - 수집 실패 (접속 안 됨, 주소 바뀜, RSS 형식 아님)
    - 피드에 글이 하나도 없음
    - 피드의 가장 최근 글이 stale_days 보다 오래됨 (주소가 바뀌어 옛 피드가 멈춰 있는 경우)
    """
    classifier = Classifier(cfg.get("classify", {}))
    problems = []

    def run(src):
        try:
            return src, collect(src), None
        except Exception as e:  # 한 소스가 실패해도 나머지는 계속
            return src, [], f"{type(e).__name__}: {e}"[:200]

    started = datetime.now(timezone.utc)
    total_new = 0
    with ThreadPoolExecutor(max_workers=8) as pool:
        for src, got, err in pool.map(run, cfg["sources"]):
            name = src["name"]
            if not err and not got:
                err = "피드에 글이 없음 (주소가 바뀌었을 수 있음)"
            if not err:
                dated = [i.published for i in got if i.published]
                stale_days = src.get("stale_days", 3)
                if dated and max(dated) < started - timedelta(days=stale_days):
                    newest = max(dated).astimezone(timezone(timedelta(hours=9))).strftime("%Y-%m-%d")
                    err = f"최근 {stale_days}일간 새 글 없음 (마지막 글 {newest}) — 피드가 멈췄을 수 있음"
            if got:  # 문제가 있어도 받은 글은 처리
                fresh = filter_recent(got, state.since_for(name))
                added = state.add_pending(classifier.apply(fresh))
                total_new += added
                if not err:
                    state.mark_source_ok(name, started)
            else:
                added = 0
            if err:
                state.mark_problem(name, err)
                problems.append((name, err))
                print(f"  ✗ {name}: {err}")
            else:
                state.clear_problem(name)
                print(f"  ✓ {name}: 피드 {len(got)}건, 새로 추가 {added}건")
    print(f"대기열: 새로 {total_new}건 추가, 총 {len(state.pending)}건")
    return problems


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else "send"
    mode = mode.lstrip("-")
    if mode not in ("collect", "send", "alert", "dry-run", "check"):
        print(__doc__)
        return 2

    cfg = yaml.safe_load((ROOT / "config.yaml").read_text("utf-8"))
    state = State(ROOT / "state")

    print("수집 중…")
    problems = gather(cfg, state)
    failures = problems  # 아침 브리핑에는 현재 문제 있는 소스를 전부 표시

    if mode == "check":
        return 1 if problems else 0
    if mode == "collect":
        state.save()
        return 0

    items = dedupe(state.pending_items(), state.recent)

    if mode == "alert":
        # 낮 알림: 연속으로 문제가 난 소스만, 한 번씩만 경고 (15분마다 같은 경고가 오지 않게)
        failures = state.new_warnings(ALERT_AFTER)
        if not items and not failures:
            print("새 소식 없음 (알림 안 보냄)")
            state.clear_pending()  # 이미 보낸 소식과 겹친 기사들은 버림
            state.save()
            return 0

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
    if mode == "alert":
        state.mark_warned([n for n, _ in failures])
    state.remember_sent(items)
    state.clear_pending()
    state.save()
    return 0


if __name__ == "__main__":
    sys.exit(main())
