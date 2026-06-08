"""
checker_sg.py
-------------
[Check 3] EC2 보안 그룹(Security Group) 과도한 인바운드 허용 점검 모듈

점검 항목
---------
인터넷 전체(0.0.0.0/0 또는 ::/0)에서 위험한 포트로의 인바운드 허용 여부

왜 중요한가?
-----------
보안 그룹은 AWS EC2 인스턴스의 방화벽 역할을 합니다.
SSH(22)나 RDP(3389) 포트가 인터넷 전체에 열려 있으면,
전 세계 어디서든 무차별 대입(Brute-force) 공격을 시도할 수 있습니다.
실제로 인터넷에는 24시간 이런 포트를 스캐닝하는 봇이 존재합니다.
"""

from core.aws_client import get_client

# 인터넷 전체를 의미하는 CIDR 표기법 (IPv4, IPv6)
PUBLIC_CIDRS = {"0.0.0.0/0", "::/0"}

# 위험도가 높은 포트 목록과 설명
DANGEROUS_PORTS = {
    22:   "SSH (원격 터미널 접속)",
    3389: "RDP (윈도우 원격 데스크톱)",
    23:   "Telnet (암호화되지 않은 원격 접속)",
    445:  "SMB (윈도우 파일 공유, 랜섬웨어 전파 경로)",
    1433: "MSSQL (SQL Server 데이터베이스)",
    3306: "MySQL/MariaDB (데이터베이스)",
    5432: "PostgreSQL (데이터베이스)",
    6379: "Redis (인메모리 DB, 인증 없이 접근 가능한 경우 많음)",
    27017:"MongoDB (NoSQL DB)",
}


def check_security_groups() -> list[dict]:
    """
    계정의 모든 EC2 보안 그룹을 순회하며 위험한 인바운드 규칙을 점검합니다.

    점검 방식
    ---------
    1. describe_security_groups로 전체 보안 그룹 목록 조회
    2. 각 그룹의 인바운드 규칙(IpPermissions)을 순회
    3. 출발지가 0.0.0.0/0 or ::/0 이면서 위험 포트인 규칙 탐지

    Returns
    -------
    list[dict]
        보안 그룹별 점검 결과 딕셔너리의 리스트
    """
    results = []

    try:
        ec2 = get_client("ec2")

        # describe_security_groups: 계정 내 모든 보안 그룹 정보 반환
        response = ec2.describe_security_groups()
        groups   = response.get("SecurityGroups", [])

        for sg in groups:
            sg_id   = sg["GroupId"]
            sg_name = sg.get("GroupName", "이름 없음")
            sg_desc = sg.get("Description", "")

            # 이 보안 그룹에서 발견된 위험 규칙 목록
            dangerous_rules = []

            # IpPermissions: 인바운드(들어오는) 트래픽 규칙 리스트
            for rule in sg.get("IpPermissions", []):
                port_info = _get_port_description(rule)

                # IPv4 출발지 확인
                for ip_range in rule.get("IpRanges", []):
                    if ip_range.get("CidrIp") in PUBLIC_CIDRS:
                        if _is_dangerous_port(rule):
                            dangerous_rules.append(f"IPv4 전체 허용: {port_info}")

                # IPv6 출발지 확인
                for ipv6_range in rule.get("Ipv6Ranges", []):
                    if ipv6_range.get("CidrIpv6") in PUBLIC_CIDRS:
                        if _is_dangerous_port(rule):
                            dangerous_rules.append(f"IPv6 전체 허용: {port_info}")

            # 결과 기록
            check_name = f"보안 그룹 인바운드 [{sg_id} / {sg_name}]"
            if not dangerous_rules:
                results.append({
                    "check_id":    "SG-001",
                    "check_name":  check_name,
                    "status":      "PASS",
                    "severity":    "HIGH",
                    "description": f"'{sg_name}': 위험한 퍼블릭 인바운드 규칙 없음",
                    "detail":      sg_desc,
                    "remediation": "-",
                })
            else:
                results.append({
                    "check_id":    "SG-001",
                    "check_name":  check_name,
                    "status":      "FAIL",
                    "severity":    "HIGH",
                    "description": f"'{sg_name}': 위험한 퍼블릭 인바운드 규칙 발견!",
                    "detail":      " | ".join(dangerous_rules),
                    "remediation": (
                        f"AWS 콘솔 → EC2 → 보안 그룹 → '{sg_id}' → "
                        "인바운드 규칙 편집에서 출발지를 "
                        "특정 IP 또는 VPN IP로 제한하세요."
                    ),
                })

    except Exception as e:
        results.append(_error_result("SG-001", "보안 그룹 전체 점검", str(e)))

    return results


def run_all_checks() -> list[dict]:
    """보안 그룹 관련 모든 점검을 실행하고 결과 리스트를 반환합니다."""
    return check_security_groups()


# ── 내부 헬퍼 함수 ──────────────────────────────────────────────────────────

def _get_port_description(rule: dict) -> str:
    """
    보안 그룹 규칙 딕셔너리에서 포트 정보를 사람이 읽기 쉬운 문자열로 변환합니다.
    예: "TCP 22 (SSH)" 또는 "TCP 80-8080"
    """
    protocol = rule.get("IpProtocol", "-1")

    if protocol == "-1":
        # -1은 '모든 트래픽 허용'을 의미하는 AWS 특수값
        return "모든 포트/프로토콜 전체 허용"

    from_port = rule.get("FromPort", 0)
    to_port   = rule.get("ToPort",   0)

    # 단일 포트 vs 범위 포트
    if from_port == to_port:
        desc = DANGEROUS_PORTS.get(from_port, "")
        port_str = f"{protocol.upper()} {from_port}"
        return f"{port_str} ({desc})" if desc else port_str
    else:
        return f"{protocol.upper()} {from_port}-{to_port}"


def _is_dangerous_port(rule: dict) -> bool:
    """
    해당 규칙이 위험 포트에 해당하는지 확인합니다.
    모든 포트 허용(-1) 또는 DANGEROUS_PORTS에 포함된 포트이면 True 반환.
    """
    protocol  = rule.get("IpProtocol", "")
    from_port = rule.get("FromPort", 0)
    to_port   = rule.get("ToPort",   0)

    # 모든 트래픽 허용 규칙은 무조건 위험
    if protocol == "-1":
        return True

    # 포트 범위 내에 위험 포트가 하나라도 포함되면 위험
    for port in DANGEROUS_PORTS:
        if from_port <= port <= to_port:
            return True

    return False


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
