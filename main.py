"""secupick: 매일 보안 뉴스·공지를 모아 메일로 보내는 프로그램.

사용법
  python main.py            수집 → 메일 발송 → 보낸 글 기록
  python main.py --dry-run  수집만 하고 preview.html 로 저장 (메일 안 보냄, 기록 안 함)
  python main.py --check    소스별로 수집이 되는지만 점검
"""
from __future__ import annotations

import argparse
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import yaml

from secupick.collectors import collect
from secupick.digest import Classifier, SeenStore, select_new
from secupick.mailer import build_email, send_email

ROOT = Path(__file__).parent


def gather(sources):
    items, failures = [], []

    def run(src):
        try:
            return src, collect(src), None
        except Exception as e:  # 한 소스가 실패해도 나머지는 계속
            return src, [], f"{type(e).__name__}: {e}"[:200]

    with ThreadPoolExecutor(max_workers=8) as pool:
        for src, got, err in pool.map(run, sources):
            if err:
                failures.append((src["name"], err))
                print(f"  ✗ {src['name']}: {err}")
            else:
                items.extend(got)
                print(f"  ✓ {src['name']}: {len(got)}건")
    return items, failures


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--config", default=str(ROOT / "config.yaml"))
    args = ap.parse_args()

    cfg = yaml.safe_load(Path(args.config).read_text("utf-8"))
    print("수집 중…")
    items, failures = gather(cfg["sources"])
    if args.check:
        return 1 if failures else 0

    seen = SeenStore(ROOT / "state" / "seen.json")
    items = Classifier(cfg.get("classify", {})).apply(items)  # 분류 + 행사·홍보 글 제외
    new = select_new(items, seen, cfg.get("lookback_hours", 30), cfg.get("max_items_per_source", 10))
    print(f"새 소식 {len(new)}건 (실패 소스 {len(failures)}개)")

    if not new and not cfg.get("send_when_empty", True):
        print("새 소식이 없어 발송하지 않습니다.")
        return 0

    subject, html = build_email(new, cfg["sections"], failures)

    if args.dry_run:
        (ROOT / "preview.html").write_text(html, "utf-8")
        print(f"미리보기 저장: preview.html\n제목: {subject}")
        return 0

    send_email(subject, html)
    print(f"발송 완료: {subject}")
    seen.add([i.link for i in new])
    seen.save()
    return 0


if __name__ == "__main__":
    sys.exit(main())
