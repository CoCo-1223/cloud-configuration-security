"""
scoring.py
----------
각 보안 점검 결과를 종합해 0~100점 사이의 '보안 점수'를 산출하는 모듈.

점수 계산 방식: 심각도 가중 비율
---------------------------------
각 항목에 심각도별 가중치를 부여한 뒤,
  score = (통과 항목 가중치 합) / (전체 항목 가중치 합) × 100

이렇게 하면 항목 수가 많아도 점수가 0에 수렴하는 문제가 없고,
"몇 %의 항목을 통과했는가"로 직관적으로 설명할 수 있습니다.

심각도별 가중치
---------------
- CRITICAL : 4  (가장 중요, 미통과 시 점수에 가장 큰 영향)
- HIGH     : 2
- MEDIUM   : 1.5
- LOW      : 1
"""

# 심각도별 가중치 테이블
SEVERITY_WEIGHT = {
    "CRITICAL": 4,
    "HIGH":     2,
    "MEDIUM":   1.5,
    "LOW":      1,
}

# 점수에 따른 등급 테이블 (상한 포함)
GRADE_TABLE = [
    (90, "A", "우수"),
    (70, "B", "양호"),
    (50, "C", "주의"),
    (30, "D", "위험"),
    ( 0, "F", "심각"),
]


def calculate_score(results: list[dict]) -> dict:
    """
    점검 결과 리스트를 받아 종합 보안 점수와 등급을 반환합니다.

    Parameters
    ----------
    results : list[dict]
        각 검사 모듈이 반환한 결과 딕셔너리의 리스트.
        각 딕셔너리는 반드시 "status"와 "severity" 키를 포함해야 합니다.

    Returns
    -------
    dict
        {
          "score"       : int,    # 0~100 최종 점수
          "grade"       : str,    # A~F 등급
          "grade_label" : str,    # 한글 등급 설명
          "pass_count"  : int,    # 통과 항목 수
          "fail_count"  : int,    # 실패 항목 수
          "total_count" : int,    # 전체 항목 수
        }
    """
    pass_weight  = 0.0   # 통과한 항목들의 가중치 합
    total_weight = 0.0   # 전체 항목들의 가중치 합
    pass_count   = 0
    fail_count   = 0

    for result in results:
        status   = result.get("status",   "PASS")
        severity = result.get("severity", "LOW")

        # 해당 항목의 가중치 결정 (정의되지 않은 심각도는 LOW로 처리)
        weight = SEVERITY_WEIGHT.get(severity, 1)
        total_weight += weight

        if status == "PASS":
            pass_count  += 1
            pass_weight += weight   # 통과 항목의 가중치만 누적
        else:
            fail_count += 1

    # 항목이 하나도 없으면 100점 처리
    if total_weight == 0:
        score = 100
    else:
        # 가중 통과 비율을 0~100점으로 환산
        score = round(pass_weight / total_weight * 100)

    # 등급 결정
    grade, grade_label = "F", "심각"
    for threshold, g, label in GRADE_TABLE:
        if score >= threshold:
            grade, grade_label = g, label
            break

    return {
        "score":       score,
        "grade":       grade,
        "grade_label": grade_label,
        "pass_count":  pass_count,
        "fail_count":  fail_count,
        "total_count": len(results),
    }
