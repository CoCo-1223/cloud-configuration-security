"""
report.py
---------
점검 결과를 CSV 또는 PDF 파일로 출력하는 리포트 생성 모듈.
Streamlit 대시보드의 '리포트 다운로드' 버튼에서 호출됩니다.
"""

import io
import datetime
import pandas as pd
from fpdf import FPDF


def results_to_dataframe(results: list[dict]) -> pd.DataFrame:
    """
    점검 결과 리스트를 pandas DataFrame으로 변환합니다.
    CSV 다운로드 및 테이블 표시에 사용됩니다.

    Parameters
    ----------
    results : list[dict]
        각 체커 모듈이 반환한 결과 딕셔너리의 리스트

    Returns
    -------
    pd.DataFrame
        점검 결과 테이블 (열: 점검ID, 점검항목, 상태, 심각도, 설명, 조치방법)
    """
    # 표시에 필요한 컬럼만 추출 (키 순서대로)
    rows = []
    for r in results:
        rows.append({
            "점검 ID":   r.get("check_id",    "-"),
            "점검 항목": r.get("check_name",  "-"),
            "상태":      r.get("status",      "-"),
            "심각도":    r.get("severity",    "-"),
            "설명":      r.get("description", "-"),
            "상세 내용": r.get("detail",      "-"),
            "조치 방법": r.get("remediation", "-"),
        })
    return pd.DataFrame(rows)


def to_csv_bytes(results: list[dict]) -> bytes:
    """
    점검 결과를 UTF-8 BOM 인코딩 CSV 바이트로 반환합니다.
    BOM을 포함해야 엑셀에서 한글이 깨지지 않습니다.

    Returns
    -------
    bytes
        CSV 파일 내용 (바이트)
    """
    df = results_to_dataframe(results)
    # utf-8-sig: BOM 포함 UTF-8 (엑셀 호환)
    return df.to_csv(index=False, encoding="utf-8-sig").encode("utf-8-sig")


def to_pdf_bytes(results: list[dict], score_info: dict) -> bytes:
    """
    점검 결과와 보안 점수를 포함한 PDF 리포트를 생성합니다.

    Parameters
    ----------
    results    : list[dict]  점검 결과 리스트
    score_info : dict        scoring.py가 반환한 점수 딕셔너리

    Returns
    -------
    bytes
        PDF 파일 내용 (바이트)
    """
    pdf = FPDF()
    pdf.add_page()

    # ── 한글 폰트 설정 ───────────────────────────────────────────────────────
    # NanumGothic 폰트가 없으면 기본 폰트(라틴 전용)를 사용합니다.
    # 한글 지원이 필요하면 NanumGothic.ttf 를 프로젝트 루트에 복사하세요.
    try:
        pdf.add_font("NanumGothic", "", "NanumGothic.ttf", uni=True)
        font_name = "NanumGothic"
    except Exception:
        font_name = "Arial"  # 한글 미지원 폴백

    # ── 표지 ─────────────────────────────────────────────────────────────────
    pdf.set_font(font_name, size=20)
    pdf.cell(0, 15, "Cloud Security Check Report", ln=True, align="C")

    pdf.set_font(font_name, size=11)
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    pdf.cell(0, 8, f"Generated: {now}", ln=True, align="C")
    pdf.ln(5)

    # ── 보안 점수 요약 ────────────────────────────────────────────────────────
    pdf.set_font(font_name, size=13)
    pdf.cell(0, 10, "[ Security Score Summary ]", ln=True)
    pdf.set_font(font_name, size=11)
    pdf.cell(0, 7, f"Score : {score_info.get('score', '-')} / 100", ln=True)
    pdf.cell(0, 7, f"Grade : {score_info.get('grade', '-')} ({score_info.get('grade_label', '-')})", ln=True)
    pdf.cell(0, 7, f"Pass  : {score_info.get('pass_count', '-')} items", ln=True)
    pdf.cell(0, 7, f"Fail  : {score_info.get('fail_count', '-')} items", ln=True)
    pdf.ln(5)

    # ── 점검 결과 테이블 ──────────────────────────────────────────────────────
    pdf.set_font(font_name, size=13)
    pdf.cell(0, 10, "[ Check Results ]", ln=True)
    pdf.set_font(font_name, size=9)

    for r in results:
        # 항목별 박스 출력
        status   = r.get("status", "-")
        name     = r.get("check_name",  "-")[:60]   # 너무 길면 자름
        desc     = r.get("description", "-")[:80]
        fix      = r.get("remediation", "-")[:80]

        # 상태별 텍스트 색상
        if status == "PASS":
            pdf.set_text_color(0, 128, 0)   # 초록
        elif status in ("FAIL", "ERROR"):
            pdf.set_text_color(200, 0, 0)   # 빨강
        else:
            pdf.set_text_color(200, 120, 0) # 주황

        pdf.cell(0, 6, f"[{status}] {name}", ln=True)
        pdf.set_text_color(0, 0, 0)         # 검정으로 복원
        pdf.cell(0, 5, f"  {desc}", ln=True)
        if status != "PASS":
            pdf.cell(0, 5, f"  -> {fix}", ln=True)
        pdf.ln(2)

    # PDF 바이트 반환
    return bytes(pdf.output())
