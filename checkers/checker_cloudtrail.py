"""
checker_cloudtrail.py
---------------------
[Check 4] AWS CloudTrail 로깅 활성화 여부 점검 모듈

점검 항목
---------
1. CloudTrail Trail이 하나 이상 존재하는지 확인
2. 존재하는 Trail이 현재 활성화(로깅 중)인지 확인
3. 멀티-리전 Trail(전체 리전 커버) 여부 확인

왜 중요한가?
-----------
CloudTrail은 AWS 계정 내 모든 API 호출을 기록하는 감사 로그 서비스입니다.
비활성화되어 있으면 누가, 언제, 무엇을 했는지 전혀 추적할 수 없어
침해 사고 발생 시 원인 분석(포렌식)이 불가능합니다.
보안 규정 준수(컴플라이언스) 측면에서도 필수 요구사항입니다.
"""

from core.aws_client import get_client


def check_cloudtrail_logging() -> list[dict]:
    """
    계정의 CloudTrail 설정을 점검합니다.

    점검 방식
    ---------
    1. describe_trails: 계정의 모든 Trail 목록 조회
    2. get_trail_status: 각 Trail의 현재 로깅 상태 확인

    Returns
    -------
    list[dict]
        CloudTrail 관련 점검 결과 딕셔너리의 리스트
    """
    results = []

    try:
        ct = get_client("cloudtrail")

        # describe_trails: 계정에 설정된 모든 Trail 정보 반환
        # includeShadowTrails=False: 현재 리전의 Trail만 조회
        response = ct.describe_trails(includeShadowTrails=False)
        trails   = response.get("trailList", [])

        # ── Trail 존재 여부 점검 ────────────────────────────────────────────
        if not trails:
            # Trail이 하나도 없으면 즉시 위험 판정
            results.append({
                "check_id":    "CT-001",
                "check_name":  "CloudTrail Trail 존재 여부",
                "status":      "FAIL",
                "severity":    "CRITICAL",  # 로그 자체가 없으면 포렌식 불가
                "description": "CloudTrail Trail이 설정되어 있지 않습니다!",
                "detail":      "Trail 없음 → 모든 API 활동이 기록되지 않습니다.",
                "remediation": (
                    "AWS 콘솔 → CloudTrail → Trail 생성 에서 "
                    "멀티-리전 Trail을 생성하고 S3 버킷에 로그를 저장하세요."
                ),
            })
            return results

        # Trail이 존재하면 각각의 활성화 상태 점검
        multi_region_exists = False  # 멀티-리전 Trail 존재 여부

        for trail in trails:
            trail_name = trail.get("Name", "이름 없음")
            trail_arn  = trail.get("TrailARN", "")
            is_multi   = trail.get("IsMultiRegionTrail", False)

            if is_multi:
                multi_region_exists = True

            # get_trail_status: Trail의 현재 로깅 켜짐/꺼짐 상태 반환
            status_resp = ct.get_trail_status(Name=trail_arn)
            is_logging  = status_resp.get("IsLogging", False)

            # 마지막 로그 전송 시각 (없으면 "기록 없음")
            last_delivery = str(
                status_resp.get("LatestDeliveryTime", "기록 없음")
            )

            if is_logging:
                results.append({
                    "check_id":    "CT-002",
                    "check_name":  f"CloudTrail 로깅 상태 [{trail_name}]",
                    "status":      "PASS",
                    "severity":    "CRITICAL",
                    "description": f"Trail '{trail_name}': 로깅 활성화 중",
                    "detail":      f"멀티-리전: {'예' if is_multi else '아니오'} | 마지막 로그: {last_delivery}",
                    "remediation": "-",
                })
            else:
                results.append({
                    "check_id":    "CT-002",
                    "check_name":  f"CloudTrail 로깅 상태 [{trail_name}]",
                    "status":      "FAIL",
                    "severity":    "CRITICAL",
                    "description": f"Trail '{trail_name}': 로깅이 중지되어 있습니다!",
                    "detail":      f"IsLogging: False | 마지막 로그: {last_delivery}",
                    "remediation": (
                        f"AWS 콘솔 → CloudTrail → '{trail_name}' → "
                        "로깅 시작 버튼을 클릭하세요."
                    ),
                })

        # ── 멀티-리전 Trail 존재 여부 점검 ─────────────────────────────────
        if multi_region_exists:
            results.append({
                "check_id":    "CT-003",
                "check_name":  "CloudTrail 멀티-리전 커버리지",
                "status":      "PASS",
                "severity":    "HIGH",
                "description": "멀티-리전 Trail이 존재합니다 (모든 리전 활동 기록).",
                "detail":      "전체 리전 커버 중",
                "remediation": "-",
            })
        else:
            results.append({
                "check_id":    "CT-003",
                "check_name":  "CloudTrail 멀티-리전 커버리지",
                "status":      "WARN",
                "severity":    "HIGH",
                "description": "멀티-리전 Trail이 없어 일부 리전 활동이 기록되지 않을 수 있습니다.",
                "detail":      "단일 리전 Trail만 존재",
                "remediation": (
                    "AWS 콘솔 → CloudTrail → Trail 편집 → "
                    "'모든 리전에 적용' 옵션을 활성화하세요."
                ),
            })

    except Exception as e:
        results.append(_error_result("CT-001", "CloudTrail 전체 점검", str(e)))

    return results


def run_all_checks() -> list[dict]:
    """CloudTrail 관련 모든 점검을 실행하고 결과 리스트를 반환합니다."""
    return check_cloudtrail_logging()


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
