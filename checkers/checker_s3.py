"""
checker_s3.py
-------------
[Check 2] S3(Simple Storage Service) 버킷 퍼블릭 접근 점검 모듈

점검 항목
---------
1. 각 버킷의 'Block Public Access' 설정 4가지 항목 모두 활성화 여부
2. 버킷 ACL(Access Control List)에 퍼블릭 읽기/쓰기 권한 존재 여부

왜 중요한가?
-----------
S3 버킷 설정 실수는 가장 흔한 클라우드 보안 사고 원인 중 하나입니다.
퍼블릭으로 열린 버킷은 인터넷의 누구나 파일을 읽거나(최악의 경우 쓰기도)
할 수 있어, 개인정보·기업 기밀 대규모 유출로 이어질 수 있습니다.
"""

from core.aws_client import get_client


def check_s3_public_access() -> list[dict]:
    """
    계정 내 모든 S3 버킷을 순회하며 퍼블릭 접근 설정을 점검합니다.

    점검 방식
    ---------
    1. list_buckets로 전체 버킷 목록 조회
    2. 각 버킷에 대해 두 가지 점검 수행:
       a. get_public_access_block: Block Public Access 4가지 설정 확인
       b. get_bucket_acl: ACL에 AllUsers/AuthenticatedUsers 허용 여부 확인

    Returns
    -------
    list[dict]
        버킷별 점검 결과 딕셔너리의 리스트 (버킷이 없으면 빈 리스트)
    """
    results = []

    try:
        s3 = get_client("s3")

        # list_buckets: 계정의 모든 S3 버킷 이름과 생성일 반환
        buckets = s3.list_buckets().get("Buckets", [])

        if not buckets:
            # 버킷이 하나도 없는 계정은 점검 불필요 → 통과 처리
            return [{
                "check_id":    "S3-000",
                "check_name":  "S3 버킷 퍼블릭 접근",
                "status":      "PASS",
                "severity":    "HIGH",
                "description": "이 계정에는 S3 버킷이 없습니다.",
                "detail":      "버킷 없음",
                "remediation": "-",
            }]

        # 버킷별로 점검 수행
        for bucket in buckets:
            bucket_name = bucket["Name"]

            # ── (a) Block Public Access 설정 점검 ──────────────────────────
            bpa_result = _check_block_public_access(s3, bucket_name)
            results.append(bpa_result)

            # ── (b) ACL 점검 ────────────────────────────────────────────────
            acl_result = _check_bucket_acl(s3, bucket_name)
            results.append(acl_result)

    except Exception as e:
        results.append(_error_result("S3-ERR", "S3 전체 점검", str(e)))

    return results


def _check_block_public_access(s3_client, bucket_name: str) -> dict:
    """
    특정 버킷의 'Block Public Access' 설정 4가지를 모두 점검합니다.

    Block Public Access 4가지 설정
    --------------------------------
    - BlockPublicAcls       : 퍼블릭 ACL 추가 차단
    - IgnorePublicAcls      : 기존 퍼블릭 ACL 무시
    - BlockPublicPolicy     : 퍼블릭 버킷 정책 추가 차단
    - RestrictPublicBuckets : 퍼블릭 버킷 정책 적용 제한

    4가지가 모두 True여야 안전합니다.
    """
    try:
        # get_public_access_block: 버킷별 Block Public Access 설정 조회
        config = s3_client.get_public_access_block(Bucket=bucket_name)
        bpa    = config["PublicAccessBlockConfiguration"]

        # 4가지 항목 각각 확인 후 미설정 항목 수집
        settings = {
            "BlockPublicAcls":       bpa.get("BlockPublicAcls",       False),
            "IgnorePublicAcls":      bpa.get("IgnorePublicAcls",      False),
            "BlockPublicPolicy":     bpa.get("BlockPublicPolicy",     False),
            "RestrictPublicBuckets": bpa.get("RestrictPublicBuckets", False),
        }
        disabled = [k for k, v in settings.items() if not v]

        if not disabled:
            return {
                "check_id":    "S3-001",
                "check_name":  f"S3 Block Public Access [{bucket_name}]",
                "status":      "PASS",
                "severity":    "HIGH",
                "description": f"버킷 '{bucket_name}': Block Public Access 모두 활성화",
                "detail":      "4/4 설정 활성화",
                "remediation": "-",
            }
        else:
            return {
                "check_id":    "S3-001",
                "check_name":  f"S3 Block Public Access [{bucket_name}]",
                "status":      "FAIL",
                "severity":    "HIGH",
                "description": f"버킷 '{bucket_name}': Block Public Access 미설정 항목 존재",
                "detail":      f"비활성화된 설정: {', '.join(disabled)}",
                "remediation": (
                    f"AWS 콘솔 → S3 → '{bucket_name}' → "
                    "권한 → 퍼블릭 액세스 차단 에서 4가지 모두 활성화하세요."
                ),
            }

    except s3_client.exceptions.NoSuchPublicAccessBlockConfiguration:
        # Block Public Access 설정 자체가 없는 경우 = 모두 비활성화와 동일
        return {
            "check_id":    "S3-001",
            "check_name":  f"S3 Block Public Access [{bucket_name}]",
            "status":      "FAIL",
            "severity":    "HIGH",
            "description": f"버킷 '{bucket_name}': Block Public Access 설정 없음 (전체 오픈 가능)",
            "detail":      "Block Public Access 설정 자체가 존재하지 않음",
            "remediation": (
                f"AWS 콘솔 → S3 → '{bucket_name}' → "
                "권한 → 퍼블릭 액세스 차단 활성화"
            ),
        }
    except Exception as e:
        return _error_result("S3-001", f"S3 Block Public Access [{bucket_name}]", str(e))


def _check_bucket_acl(s3_client, bucket_name: str) -> dict:
    """
    특정 버킷의 ACL(Access Control List)에 퍼블릭 권한이 있는지 점검합니다.

    위험한 ACL 대상자
    -----------------
    - http://acs.amazonaws.com/groups/global/AllUsers
      → 인터넷의 모든 사람 (인증 불필요)
    - http://acs.amazonaws.com/groups/global/AuthenticatedUsers
      → 모든 AWS 계정 사용자 (자신의 계정 외 타인도 포함)
    """
    # 위험한 ACL 대상자 URI 정의
    PUBLIC_GRANTEES = {
        "http://acs.amazonaws.com/groups/global/AllUsers",
        "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
    }

    try:
        # get_bucket_acl: 버킷의 소유자 및 권한 부여 목록 반환
        acl    = s3_client.get_bucket_acl(Bucket=bucket_name)
        grants = acl.get("Grants", [])

        # 각 권한 항목에서 위험한 대상자에게 Read/Write가 있는지 확인
        public_grants = []
        for grant in grants:
            grantee = grant.get("Grantee", {})
            uri     = grantee.get("URI", "")
            perm    = grant.get("Permission", "")

            if uri in PUBLIC_GRANTEES:
                # 예: "AllUsers: READ" 형태로 기록
                label = "모든 사람" if "AllUsers" in uri else "모든 AWS 사용자"
                public_grants.append(f"{label}: {perm}")

        if not public_grants:
            return {
                "check_id":    "S3-002",
                "check_name":  f"S3 버킷 ACL [{bucket_name}]",
                "status":      "PASS",
                "severity":    "HIGH",
                "description": f"버킷 '{bucket_name}': 퍼블릭 ACL 없음",
                "detail":      "퍼블릭 권한 부여 없음",
                "remediation": "-",
            }
        else:
            return {
                "check_id":    "S3-002",
                "check_name":  f"S3 버킷 ACL [{bucket_name}]",
                "status":      "FAIL",
                "severity":    "HIGH",
                "description": f"버킷 '{bucket_name}': 퍼블릭 ACL 발견!",
                "detail":      " | ".join(public_grants),
                "remediation": (
                    f"AWS 콘솔 → S3 → '{bucket_name}' → "
                    "권한 → ACL 편집 에서 퍼블릭 권한을 제거하세요."
                ),
            }

    except Exception as e:
        return _error_result("S3-002", f"S3 버킷 ACL [{bucket_name}]", str(e))


def run_all_checks() -> list[dict]:
    """S3 관련 모든 점검을 실행하고 결과 리스트를 반환합니다."""
    return check_s3_public_access()


# ── 내부 헬퍼 함수 ──────────────────────────────────────────────────────────

def _error_result(check_id: str, check_name: str, error_msg: str) -> dict:
    """API 오류 발생 시 반환할 표준 오류 결과 딕셔너리를 생성합니다."""
    return {
        "check_id":    check_id,
        "check_name":  check_name,
        "status":      "ERROR",
        "severity":    "MEDIUM",
        "description": "점검 중 오류가 발생했습니다.",
        "detail":      error_msg,
        "remediation": "AWS 자격증명 및 권한을 확인하세요.",
    }
