"""
checker_iam.py
--------------
[Check 1] IAM(Identity and Access Management) 보안 점검 모듈

점검 항목
---------
1. 루트 계정 MFA(다중 인증) 활성화 여부
2. IAM 패스워드 정책 강도 (길이, 복잡도, 만료 등)

왜 중요한가?
-----------
루트 계정은 AWS의 모든 권한을 가진 최고 관리자 계정입니다.
MFA 없이 비밀번호만으로 로그인 가능하다면, 비밀번호 하나가 유출되는 것만으로
전체 클라우드 인프라가 공격자에게 넘어갈 수 있습니다.
"""

from core.aws_client import get_client


def check_root_mfa() -> dict:
    """
    AWS 루트 계정의 MFA(Multi-Factor Authentication) 활성화 여부를 점검합니다.

    MFA란?
    ------
    로그인 시 비밀번호 외에 OTP(일회용 비밀번호) 등 추가 인증을 요구하는 보안 장치.
    설정되어 있지 않으면 비밀번호 탈취만으로 계정 전체 접근이 가능합니다.

    Returns
    -------
    dict
        표준 점검 결과 딕셔너리
    """
    try:
        iam = get_client("iam")

        # get_account_summary: IAM 관련 계정 전체 통계를 반환하는 AWS API
        # AccountMFAEnabled: 루트 계정 MFA 활성화 여부 (1=활성화, 0=비활성화)
        summary = iam.get_account_summary()["SummaryMap"]
        mfa_enabled = summary.get("AccountMFAEnabled", 0)

        if mfa_enabled == 1:
            # MFA가 켜져 있으면 정상(PASS)
            return {
                "check_id":    "IAM-001",
                "check_name":  "루트 계정 MFA 활성화",
                "status":      "PASS",
                "severity":    "CRITICAL",
                "description": "루트 계정에 MFA가 활성화되어 있습니다.",
                "detail":      "MFA 활성화 상태: 정상",
                "remediation": "-",
            }
        else:
            # MFA가 꺼져 있으면 위험(FAIL)
            return {
                "check_id":    "IAM-001",
                "check_name":  "루트 계정 MFA 활성화",
                "status":      "FAIL",
                "severity":    "CRITICAL",   # 루트 MFA 미설정은 최고 위험도
                "description": "루트 계정에 MFA가 설정되어 있지 않습니다!",
                "detail":      "MFA 활성화 상태: 비활성화",
                "remediation": (
                    "AWS 콘솔 → IAM → 보안 자격 증명 → "
                    "MFA 디바이스 할당 에서 MFA를 활성화하세요."
                ),
            }

    except Exception as e:
        # API 호출 자체가 실패한 경우 (권한 없음 등)
        return _error_result("IAM-001", "루트 계정 MFA 활성화", str(e))


def check_password_policy() -> dict:
    """
    IAM 계정 전체에 적용된 패스워드 정책을 점검합니다.

    점검 기준 (AWS 보안 모범 사례 기반)
    -----------------------------------
    - 최소 길이 14자 이상
    - 대/소문자, 숫자, 특수문자 모두 요구
    - 비밀번호 재사용 방지 (최근 24개 이상)
    - 비밀번호 만료 기간 90일 이하

    Returns
    -------
    dict
        표준 점검 결과 딕셔너리
    """
    try:
        iam = get_client("iam")

        # get_account_password_policy: 계정 수준 IAM 패스워드 정책 조회
        response = iam.get_account_password_policy()
        policy   = response["PasswordPolicy"]

        issues = []  # 발견된 문제점 리스트

        # 각 항목을 AWS 모범 사례와 비교
        min_len = policy.get("MinimumPasswordLength", 0)
        if min_len < 14:
            issues.append(f"최소 비밀번호 길이 부족 ({min_len}자 < 14자)")

        if not policy.get("RequireUppercaseCharacters", False):
            issues.append("대문자 요구 미설정")

        if not policy.get("RequireLowercaseCharacters", False):
            issues.append("소문자 요구 미설정")

        if not policy.get("RequireNumbers", False):
            issues.append("숫자 요구 미설정")

        if not policy.get("RequireSymbols", False):
            issues.append("특수문자 요구 미설정")

        reuse = policy.get("PasswordReusePrevention", 0)
        if reuse < 24:
            issues.append(f"비밀번호 재사용 방지 부족 ({reuse}회 < 24회)")

        # 만료 기간: 설정 없으면 무제한(0으로 처리)
        max_age = policy.get("MaxPasswordAge", 0)
        if max_age == 0 or max_age > 90:
            issues.append(f"비밀번호 만료 기간 미설정 또는 초과 (현재: {'미설정' if max_age == 0 else f'{max_age}일'})")

        if not issues:
            return {
                "check_id":    "IAM-002",
                "check_name":  "IAM 패스워드 정책",
                "status":      "PASS",
                "severity":    "HIGH",
                "description": "패스워드 정책이 모범 사례를 충족합니다.",
                "detail":      f"최소 길이: {min_len}자",
                "remediation": "-",
            }
        else:
            return {
                "check_id":    "IAM-002",
                "check_name":  "IAM 패스워드 정책",
                "status":      "FAIL",
                "severity":    "HIGH",
                "description": f"패스워드 정책 미흡 ({len(issues)}개 항목)",
                "detail":      " | ".join(issues),
                "remediation": (
                    "AWS 콘솔 → IAM → 계정 설정 → 암호 정책 에서 "
                    "각 항목을 강화하세요."
                ),
            }

    except iam.exceptions.NoSuchEntityException:
        # 패스워드 정책 자체가 설정되지 않은 경우
        return {
            "check_id":    "IAM-002",
            "check_name":  "IAM 패스워드 정책",
            "status":      "FAIL",
            "severity":    "HIGH",
            "description": "계정 수준 IAM 패스워드 정책이 전혀 설정되어 있지 않습니다.",
            "detail":      "정책 없음",
            "remediation": "AWS 콘솔 → IAM → 계정 설정에서 패스워드 정책을 설정하세요.",
        }
    except Exception as e:
        return _error_result("IAM-002", "IAM 패스워드 정책", str(e))


def run_all_checks() -> list[dict]:
    """IAM 관련 모든 점검을 실행하고 결과 리스트를 반환합니다."""
    return [
        check_root_mfa(),
        check_password_policy(),
    ]


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
