"""
demo_mode.py
------------
AWS 계정 없이 시현(Demo)할 수 있도록 가상의 점검 결과를 반환하는 모듈.

사용 방법:
    app.py 사이드바에서 "데모 모드" 체크박스를 선택하면 이 모듈이 실행됩니다.
    실제 AWS API를 호출하지 않으므로 자격증명 없이도 UI를 발표장에서 시연할 수 있습니다.

시나리오:
    - '취약한 계정' : FAIL 항목이 여러 개, 낮은 점수 → 문제 상황 시연
    - '안전한 계정' : 대부분 PASS, 높은 점수 → 조치 후 상황 시연
"""


def get_vulnerable_results() -> list[dict]:
    """
    취약점이 다수 존재하는 '위험한 계정'의 가상 점검 결과를 반환합니다.
    발표에서 "이런 문제가 있습니다" 단계에 사용합니다.
    """
    return [
        # ── IAM 점검 결과 ──────────────────────────────────────────────────
        {
            "check_id":    "IAM-001",
            "check_name":  "루트 계정 MFA 활성화",
            "status":      "FAIL",
            "severity":    "CRITICAL",
            "description": "루트 계정에 MFA가 설정되어 있지 않습니다!",
            "detail":      "MFA 활성화 상태: 비활성화",
            "remediation": "AWS 콘솔 → IAM → 보안 자격 증명 → MFA 디바이스 할당",
        },
        {
            "check_id":    "IAM-002",
            "check_name":  "IAM 패스워드 정책",
            "status":      "FAIL",
            "severity":    "HIGH",
            "description": "패스워드 정책 미흡 (3개 항목)",
            "detail":      "최소 비밀번호 길이 부족 (8자 < 14자) | 특수문자 요구 미설정 | 비밀번호 만료 기간 미설정",
            "remediation": "AWS 콘솔 → IAM → 계정 설정 → 암호 정책에서 각 항목을 강화하세요.",
        },

        # ── S3 점검 결과 ───────────────────────────────────────────────────
        {
            "check_id":    "S3-001",
            "check_name":  "S3 Block Public Access [my-company-data]",
            "status":      "FAIL",
            "severity":    "HIGH",
            "description": "버킷 'my-company-data': Block Public Access 미설정 항목 존재",
            "detail":      "비활성화된 설정: BlockPublicAcls, IgnorePublicAcls",
            "remediation": "AWS 콘솔 → S3 → 'my-company-data' → 권한 → 퍼블릭 액세스 차단 활성화",
        },
        {
            "check_id":    "S3-002",
            "check_name":  "S3 버킷 ACL [my-company-data]",
            "status":      "FAIL",
            "severity":    "HIGH",
            "description": "버킷 'my-company-data': 퍼블릭 ACL 발견!",
            "detail":      "모든 사람: READ",
            "remediation": "AWS 콘솔 → S3 → 'my-company-data' → 권한 → ACL 편집에서 퍼블릭 권한 제거",
        },
        {
            "check_id":    "S3-001",
            "check_name":  "S3 Block Public Access [backup-bucket-2024]",
            "status":      "PASS",
            "severity":    "HIGH",
            "description": "버킷 'backup-bucket-2024': Block Public Access 모두 활성화",
            "detail":      "4/4 설정 활성화",
            "remediation": "-",
        },
        {
            "check_id":    "S3-002",
            "check_name":  "S3 버킷 ACL [backup-bucket-2024]",
            "status":      "PASS",
            "severity":    "HIGH",
            "description": "버킷 'backup-bucket-2024': 퍼블릭 ACL 없음",
            "detail":      "퍼블릭 권한 부여 없음",
            "remediation": "-",
        },

        # ── 보안 그룹 점검 결과 ────────────────────────────────────────────
        {
            "check_id":    "SG-001",
            "check_name":  "보안 그룹 인바운드 [sg-0a1b2c3d / web-server-sg]",
            "status":      "FAIL",
            "severity":    "HIGH",
            "description": "'web-server-sg': 위험한 퍼블릭 인바운드 규칙 발견!",
            "detail":      "IPv4 전체 허용: TCP 22 (SSH 원격 터미널 접속) | IPv4 전체 허용: TCP 3389 (RDP 윈도우 원격 데스크톱)",
            "remediation": "AWS 콘솔 → EC2 → 보안 그룹 → 인바운드 규칙 편집에서 출발지를 특정 IP로 제한하세요.",
        },
        {
            "check_id":    "SG-001",
            "check_name":  "보안 그룹 인바운드 [sg-9z8y7x6w / db-server-sg]",
            "status":      "PASS",
            "severity":    "HIGH",
            "description": "'db-server-sg': 위험한 퍼블릭 인바운드 규칙 없음",
            "detail":      "내부 VPC에서만 접근 허용",
            "remediation": "-",
        },

        # ── CloudTrail 점검 결과 ───────────────────────────────────────────
        {
            "check_id":    "CT-002",
            "check_name":  "CloudTrail 로깅 상태 [management-trail]",
            "status":      "PASS",   # 취약 시나리오에서도 Trail은 존재 → 점수 조정용
            "severity":    "CRITICAL",
            "description": "Trail 'management-trail': 로깅 활성화 중",
            "detail":      "멀티-리전: 아니오 | 마지막 로그: 방금 전",
            "remediation": "-",
        },
        {
            "check_id":    "CT-003",
            "check_name":  "CloudTrail 멀티-리전 커버리지",
            "status":      "WARN",
            "severity":    "HIGH",
            "description": "멀티-리전 Trail이 없어 일부 리전 활동이 기록되지 않을 수 있습니다.",
            "detail":      "단일 리전 Trail만 존재",
            "remediation": "CloudTrail → Trail 편집 → '모든 리전에 적용' 옵션 활성화",
        },
    ]


def get_secure_results() -> list[dict]:
    """
    모든 보안 설정이 올바른 '안전한 계정'의 가상 점검 결과를 반환합니다.
    발표에서 "이렇게 수정하면 됩니다" 단계에 사용합니다.
    """
    return [
        {
            "check_id": "IAM-001", "check_name": "루트 계정 MFA 활성화",
            "status": "PASS", "severity": "CRITICAL",
            "description": "루트 계정에 MFA가 활성화되어 있습니다.",
            "detail": "MFA 활성화 상태: 정상", "remediation": "-",
        },
        {
            "check_id": "IAM-002", "check_name": "IAM 패스워드 정책",
            "status": "PASS", "severity": "HIGH",
            "description": "패스워드 정책이 모범 사례를 충족합니다.",
            "detail": "최소 길이: 14자 | 복잡도: 충족 | 만료: 90일",
            "remediation": "-",
        },
        {
            "check_id": "S3-001", "check_name": "S3 Block Public Access [my-company-data]",
            "status": "PASS", "severity": "HIGH",
            "description": "버킷 'my-company-data': Block Public Access 모두 활성화",
            "detail": "4/4 설정 활성화", "remediation": "-",
        },
        {
            "check_id": "S3-002", "check_name": "S3 버킷 ACL [my-company-data]",
            "status": "PASS", "severity": "HIGH",
            "description": "버킷 'my-company-data': 퍼블릭 ACL 없음",
            "detail": "퍼블릭 권한 부여 없음", "remediation": "-",
        },
        {
            "check_id": "S3-001", "check_name": "S3 Block Public Access [backup-bucket-2024]",
            "status": "PASS", "severity": "HIGH",
            "description": "버킷 'backup-bucket-2024': Block Public Access 모두 활성화",
            "detail": "4/4 설정 활성화", "remediation": "-",
        },
        {
            "check_id": "S3-002", "check_name": "S3 버킷 ACL [backup-bucket-2024]",
            "status": "PASS", "severity": "HIGH",
            "description": "버킷 'backup-bucket-2024': 퍼블릭 ACL 없음",
            "detail": "퍼블릭 권한 부여 없음", "remediation": "-",
        },
        {
            "check_id": "SG-001", "check_name": "보안 그룹 인바운드 [sg-0a1b2c3d / web-server-sg]",
            "status": "PASS", "severity": "HIGH",
            "description": "'web-server-sg': 위험한 퍼블릭 인바운드 규칙 없음",
            "detail": "SSH/RDP 접근을 사내 IP(10.0.0.0/8)로만 제한함", "remediation": "-",
        },
        {
            "check_id": "SG-001", "check_name": "보안 그룹 인바운드 [sg-9z8y7x6w / db-server-sg]",
            "status": "PASS", "severity": "HIGH",
            "description": "'db-server-sg': 위험한 퍼블릭 인바운드 규칙 없음",
            "detail": "내부 VPC에서만 접근 허용", "remediation": "-",
        },
        {
            "check_id": "CT-002", "check_name": "CloudTrail 로깅 상태 [management-trail]",
            "status": "PASS", "severity": "CRITICAL",
            "description": "Trail 'management-trail': 로깅 활성화 중",
            "detail": "멀티-리전: 예 | 마지막 로그: 방금 전", "remediation": "-",
        },
        {
            "check_id": "CT-003", "check_name": "CloudTrail 멀티-리전 커버리지",
            "status": "PASS", "severity": "HIGH",
            "description": "멀티-리전 Trail이 존재합니다 (모든 리전 활동 기록).",
            "detail": "전체 리전 커버 중", "remediation": "-",
        },
    ]
