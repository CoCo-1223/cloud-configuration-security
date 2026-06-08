# Cloud Configuration Security Checker

충북대학교 2026학년도 1학기 파이썬 프로젝트 개인 기말과제로 제작한 AWS 클라우드 보안 설정 점검 도구입니다.

AWS 계정의 주요 보안 설정을 점검하고 결과를 대시보드와 리포트로 확인할 수 있는 Python 기반 보안 점검 도구입니다. Streamlit으로 화면을 구성했고, boto3를 이용해 AWS 설정을 읽기 전용으로 조회합니다.

## 주요 기능

- AWS 자격증명 연결 확인
- IAM, S3, Security Group, CloudTrail 보안 설정 점검
- PASS, FAIL, WARN, ERROR 상태별 결과 표시
- 심각도 기반 보안 점수 계산
- 발견된 문제에 대한 조치 방법 제공
- CSV 및 PDF 리포트 다운로드
- 실제 AWS 계정 없이 발표할 수 있는 데모 모드 제공

## 점검 항목

| 구분 | 점검 내용 | 심각도 |
| --- | --- | --- |
| IAM | 루트 계정 MFA 활성화 여부 | CRITICAL |
| IAM | IAM 패스워드 정책 설정 여부 및 강도 | HIGH |
| S3 | 버킷 Block Public Access 설정 여부 | HIGH |
| S3 | 버킷 ACL 퍼블릭 권한 여부 | HIGH |
| Security Group | 위험 포트가 전체 인터넷에 공개되어 있는지 확인 | HIGH |
| CloudTrail | Trail 존재 여부 및 로깅 활성화 상태 | CRITICAL |
| CloudTrail | 멀티 리전 로깅 설정 여부 | HIGH |

## 프로젝트 구조

```text
cloud-configuration-security/
├── app.py
├── demo_mode.py
├── requirements.txt
├── .env.example
├── checkers/
│   ├── checker_iam.py
│   ├── checker_s3.py
│   ├── checker_sg.py
│   └── checker_cloudtrail.py
├── core/
│   ├── aws_client.py
│   └── scoring.py
└── utils/
    └── report.py
```

## 파일 설명

| 파일 | 역할 |
| --- | --- |
| `app.py` | Streamlit 화면 구성, 점검 실행 흐름, 결과 출력 |
| `demo_mode.py` | 발표용 가상 점검 결과 데이터 |
| `core/aws_client.py` | boto3 클라이언트 생성 및 AWS 계정 연결 확인 |
| `core/scoring.py` | 심각도 가중치 기반 보안 점수 계산 |
| `checkers/checker_iam.py` | 루트 MFA, IAM 패스워드 정책 점검 |
| `checkers/checker_s3.py` | S3 퍼블릭 접근 차단 및 ACL 점검 |
| `checkers/checker_sg.py` | EC2 보안 그룹 인바운드 규칙 점검 |
| `checkers/checker_cloudtrail.py` | CloudTrail 로깅 상태 점검 |
| `utils/report.py` | CSV, PDF 리포트 생성 |

## 실행 방법

### 1. 패키지 설치

```bash
pip install -r requirements.txt
```

### 2. 앱 실행

```bash
streamlit run app.py
```

실행 후 브라우저에서 아래 주소로 접속합니다.

```text
http://localhost:8501
```

## 사용 방법

1. 사이드바에서 AWS Access Key, Secret Key, 리전을 입력합니다.
2. 점검할 항목을 선택합니다.
3. `보안 점검 시작` 버튼을 누릅니다.
4. 보안 점수, 점검 결과 상세, 조치 가이드를 확인합니다.
5. 필요한 경우 CSV 또는 PDF 리포트를 다운로드합니다.

## 데모 모드

AWS 계정이 없거나 발표 시 실제 계정 정보를 사용하기 어려운 경우 데모 모드를 사용할 수 있습니다.

데모 모드에서는 실제 AWS API를 호출하지 않고, 미리 정의된 가상 결과를 사용합니다.

- 취약한 계정 시나리오: 여러 FAIL 항목과 낮은 보안 점수 표시
- 안전한 계정 시나리오: 대부분 PASS 항목과 높은 보안 점수 표시

## 점수 계산 방식

점수는 단순 PASS 개수가 아니라 심각도별 가중치를 반영해 계산합니다.

| 심각도 | 가중치 |
| --- | --- |
| CRITICAL | 4 |
| HIGH | 2 |
| MEDIUM | 1.5 |
| LOW | 1 |

계산 방식은 다음과 같습니다.

```text
보안 점수 = 통과한 항목의 가중치 합 / 전체 항목의 가중치 합 * 100
```

점수에 따라 A부터 F까지 등급을 부여합니다.

## 필요한 AWS 권한

이 프로젝트는 AWS 설정을 조회만 하며, 리소스를 생성하거나 수정하지 않습니다.

권장 권한:

- `SecurityAudit`
- 또는 `ReadOnlyAccess`

실제 운영 계정에서 사용할 경우 루트 계정 Access Key를 사용하지 말고, 읽기 전용 권한을 가진 IAM 사용자의 Access Key를 사용하는 것을 권장합니다.

## 보안 주의사항

- `.env` 파일에는 실제 AWS 키가 들어가므로 GitHub에 올리면 안 됩니다.
- 이 프로젝트의 `.gitignore`에는 `.env`가 포함되어 있습니다.
- 현재 앱은 `.env` 파일을 직접 읽지 않고, Streamlit 사이드바에 입력한 AWS 키를 실행 중에만 사용합니다.
- 키가 외부에 노출된 경우 AWS 콘솔에서 즉시 Access Key를 비활성화하거나 재발급해야 합니다.

## 사용 기술

- Python
- Streamlit
- boto3
- pandas
- plotly
- fpdf2
