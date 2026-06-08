# ☁️ Cloud Configuration Security Checker

AWS 클라우드 계정의 보안 설정을 자동으로 점검하고, 취약점과 조치 방법을 알려주는 Python 기반 보안 점검 툴입니다.

---

## 📸 주요 화면

- **보안 점수 게이지**: 0~100점 시각화
- **점검 결과 테이블**: PASS/FAIL 상태별 색상 표시
- **조치 가이드**: 발견된 취약점의 해결 방법 안내
- **리포트 다운로드**: CSV(엑셀) / PDF 형식 지원

---

## 🚀 실행 방법

### 1. 패키지 설치

```bash
pip install -r requirements.txt
```

### 2. AWS 자격증명 설정

```bash
cp .env.example .env
# .env 파일을 열고 실제 AWS Access Key 입력
```

### 3. 앱 실행

```bash
streamlit run app.py
```

브라우저에서 `http://localhost:8501` 로 접속하면 대시보드가 열립니다.

---

## 🎭 AWS 계정 없이 시연하기 (데모 모드)

사이드바의 **"데모 모드"** 체크박스를 활성화하면 실제 AWS API 호출 없이 가상 결과로 UI를 시연할 수 있습니다.

- **취약한 계정 시나리오**: 다수의 FAIL 항목, 낮은 보안 점수
- **안전한 계정 시나리오**: 모두 PASS, 높은 보안 점수

---

## 🔍 점검 항목

| # | 카테고리 | 점검 내용 | 심각도 |
|---|----------|-----------|--------|
| 1 | IAM | 루트 계정 MFA 활성화 여부 | CRITICAL |
| 2 | IAM | 패스워드 정책 강도 (길이, 복잡도, 만료) | HIGH |
| 3 | S3 | 버킷 Block Public Access 4가지 설정 | HIGH |
| 4 | S3 | 버킷 ACL 퍼블릭 권한 부여 여부 | HIGH |
| 5 | EC2 | 보안 그룹 위험 포트 전체 허용 여부 | HIGH |
| 6 | CloudTrail | Trail 존재 및 로깅 활성화 여부 | CRITICAL |
| 7 | CloudTrail | 멀티-리전 Trail 설정 여부 | HIGH |

---

## 📁 프로젝트 구조

```
cloud-security-checker/
├── app.py                      # Streamlit 메인 앱
├── demo_mode.py                # 데모용 가상 결과 데이터
├── requirements.txt            # 패키지 목록
├── .env.example                # 환경 변수 예시
├── checkers/
│   ├── checker_iam.py          # IAM 점검 모듈
│   ├── checker_s3.py           # S3 점검 모듈
│   ├── checker_sg.py           # 보안 그룹 점검 모듈
│   └── checker_cloudtrail.py   # CloudTrail 점검 모듈
├── core/
│   ├── aws_client.py           # AWS 연결 관리
│   └── scoring.py              # 보안 점수 산출
└── utils/
    └── report.py               # CSV/PDF 리포트 생성
```

---

## ⚙️ 필요 AWS 권한 (Read-Only)

이 툴은 **읽기 전용** 권한만 사용합니다. 설정 변경은 일절 수행하지 않습니다.

필요한 AWS 관리형 정책: `SecurityAudit` 또는 `ReadOnlyAccess`


> 2026-1 Python 프로그래밍 기말 프로젝트
> 해당 프로젝트는 2026년 1학기 파이썬 프로그래밍 기말 과제로 진행된 개인 프로젝트입니다.
