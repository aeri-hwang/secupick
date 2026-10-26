# secupick

매일 아침 국내외 보안 뉴스, KISA 보안공지, CISA KEV(실제 악용 취약점)를 모아 이메일로 보내 주는 프로그램입니다.
GitHub Actions 에서 돌아가므로 서버도, 매일 승인하는 과정도 필요 없습니다.

## 설치 (처음 한 번, 약 10분)

1. **Gmail 앱 비밀번호 발급**
   Google 계정 → 보안 → 2단계 인증 켜기 → "앱 비밀번호"에서 16자리 비밀번호를 만듭니다.
   (일반 Gmail 비밀번호로는 로그인되지 않습니다.)

2. **GitHub 저장소 만들기**
   GitHub 에서 새 저장소(private 권장)를 만들고 이 폴더의 파일을 전부 올립니다.
   `.github` 폴더도 꼭 함께 올려야 합니다.

3. **Secrets 등록**
   저장소 → Settings → Secrets and variables → Actions → New repository secret
   - `SMTP_USER` : 보내는 Gmail 주소
   - `SMTP_PASSWORD` : 1번에서 만든 앱 비밀번호
   - `MAIL_TO` : 받을 주소 (여러 개면 쉼표로 구분)

4. **첫 실행 테스트**
   저장소 → Actions → "secupick daily" → Run workflow 를 눌러 바로 메일이 오는지 확인합니다.
   이후로는 매일 자동으로 실행됩니다.

## 설정 바꾸기

- **발송 시각**: `.github/workflows/daily.yml` 의 cron (UTC 기준, 한국 시간 -9시간)
  - 오전 7시: `0 22 * * *` (기본값) / 오전 8시: `0 23 * * *` / 오전 9시: `0 0 * * *`
  - GitHub 서버 사정에 따라 수 분~수십 분 늦게 실행될 수 있습니다.
- **분류 규칙(취약점·침해사고 단어), 제외할 글, 소스 추가/삭제**: `config.yaml`
- **소스가 잘 되는지 점검**: `python main.py --check`
- **메일 안 보내고 미리보기만**: `python main.py --dry-run` → `preview.html`

## 동작 방식

1. 모든 소스를 동시에 수집 (한 소스가 실패해도 나머지는 계속)
2. 최근 30시간 이내 글 중 아직 보내지 않은 글만 선택
3. 글을 실제 악용 취약점(KEV) → 새 취약점·보안 업데이트 → 침해사고·공격 → 기타 보안 이슈로 자동 분류, 행사·홍보성 글은 제외
4. 메일 발송 후 보낸 링크를 `state/seen.json` 에 기록해 저장소에 커밋 (다음 날 중복 방지)

수집이 실패한 소스는 메일 맨 아래에 표시됩니다.
국내 사이트가 계속 실패한다면 해외(GitHub 서버) 접속 차단일 수 있으니, 그때는 집 PC 등 국내에서 cron 으로 `python main.py` 를 돌리면 됩니다.
