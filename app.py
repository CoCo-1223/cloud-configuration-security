"""
app.py
------
Cloud Configuration Security Checker - Streamlit 메인 애플리케이션

실행 방법:
    streamlit run app.py

구조:
    - 사이드바: AWS 자격증명 입력 및 점검 실행 버튼
    - 메인 화면:
        1. 보안 점수 게이지 + 요약 카드
        2. 점검 결과 테이블 (상태별 색상 강조)
        3. 실패 항목 상세 조치 가이드
        4. CSV / PDF 리포트 다운로드
"""

import os
import datetime
import streamlit as st
import plotly.graph_objects as go
import pandas as pd

# 자체 모듈 임포트
from core.aws_client   import verify_connection
from core.scoring      import calculate_score
from checkers          import checker_iam, checker_s3, checker_sg, checker_cloudtrail
from utils.report      import to_csv_bytes, to_pdf_bytes
from demo_mode         import get_vulnerable_results, get_secure_results


# ── 페이지 기본 설정 ──────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Cloud Security Checker",
    page_icon=":shield:",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
    :root {
        --bg: #f7f8fa;
        --panel: #ffffff;
        --line: #dde2e8;
        --text-muted: #667085;
        --brand: #1f6feb;
        --danger: #d92d20;
        --warning: #b54708;
        --success: #067647;
    }

    .stApp {
        background: var(--bg);
        color: #1d2939;
    }

    [data-testid="stSidebar"] {
        background: #111827;
        color: #f9fafb;
    }

    [data-testid="stSidebar"] h1,
    [data-testid="stSidebar"] h2,
    [data-testid="stSidebar"] h3,
    [data-testid="stSidebar"] label,
    [data-testid="stSidebar"] p,
    [data-testid="stSidebar"] span {
        color: #f9fafb;
    }

    [data-testid="stSidebar"] .stCaption {
        color: #cbd5e1;
    }

    h1, h2, h3 {
        letter-spacing: 0;
    }

    h1 {
        font-size: 2.1rem;
        margin-bottom: 0.35rem;
    }

    h2 {
        font-size: 1.35rem;
        margin-top: 1.4rem;
    }

    h3 {
        font-size: 1rem;
        margin-top: 0.75rem;
    }

    .section-label {
        color: var(--text-muted);
        font-size: 0.78rem;
        font-weight: 700;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        margin-bottom: 0.35rem;
    }

    .hero-copy {
        color: var(--text-muted);
        font-size: 1.02rem;
        line-height: 1.65;
        max-width: 760px;
        margin-bottom: 1.25rem;
    }

    .quiet-panel {
        background: var(--panel);
        border: 1px solid var(--line);
        border-radius: 8px;
        margin-bottom: 12px;
        padding: 18px 20px;
        min-height: 132px;
    }

    .quiet-panel strong {
        display: block;
        color: #101828;
        font-size: 0.98rem;
        margin-bottom: 8px;
    }

    .quiet-panel span {
        color: var(--text-muted);
        font-size: 0.92rem;
        line-height: 1.55;
    }

    .callout {
        background: #eef4ff;
        border-left: 4px solid var(--brand);
        border-radius: 6px;
        color: #344054;
        padding: 13px 16px;
        margin: 14px 0 18px;
    }

    .risk-line {
        align-items: center;
        border-bottom: 1px solid var(--line);
        display: flex;
        justify-content: space-between;
        padding: 9px 0;
    }

    .risk-line:last-child {
        border-bottom: 0;
    }

    .risk-line span:first-child {
        color: #344054;
        font-weight: 650;
    }

    .risk-line span:last-child {
        color: var(--text-muted);
    }

    .status-critical { color: var(--danger); }
    .status-high { color: var(--warning); }
    .status-medium { color: #ca8504; }
    .status-low { color: var(--success); }

    div.stButton > button,
    div.stDownloadButton > button {
        border-radius: 6px;
        font-weight: 650;
    }

    div[data-testid="stMetric"] {
        background: var(--panel);
        border: 1px solid var(--line);
        border-radius: 8px;
        padding: 14px 16px;
    }

    div[data-testid="stMetricLabel"] {
        color: var(--text-muted);
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# ══════════════════════════════════════════════════════════════════════════════
# 사이드바 : 자격증명 입력 & 점검 실행
# ══════════════════════════════════════════════════════════════════════════════

with st.sidebar:
    st.title("Security Checker")
    st.markdown("---")

    st.subheader("AWS 연결")

    # 입력값을 session_state에 저장하면 재실행 시에도 유지됩니다
    access_key = st.text_input(
        "Access Key ID",
        type="password",
        placeholder="AKIAIOSFODNN7EXAMPLE",
        help="AWS IAM ReadOnly 사용자의 Access Key를 입력하세요.",
    )
    secret_key = st.text_input(
        "Secret Access Key",
        type="password",
        placeholder="wJalrXUtnFEMI/...",
        help="절대로 루트 계정 키를 입력하지 마세요.",
    )
    region = st.selectbox(
        "리전(Region)",
        ["ap-northeast-2", "us-east-1", "us-west-2", "eu-west-1"],
        index=0,
        help="점검할 AWS 리전을 선택하세요. (S3는 글로벌 적용)",
    )

    st.markdown("---")

    # 점검 항목 선택 (기본값: 전체 선택)
    st.subheader("점검 범위")
    run_iam = st.checkbox("IAM 계정 보안",        value=True)
    run_s3  = st.checkbox("S3 퍼블릭 접근",       value=True)
    run_sg  = st.checkbox("보안 그룹(방화벽)",     value=True)
    run_ct  = st.checkbox("CloudTrail 로깅",       value=True)

    st.markdown("---")

    # 데모 모드 토글 (AWS 계정 없이 발표 시연용)
    demo_mode = st.checkbox(
        "데모 모드 (AWS 계정 불필요)",
        value=False,
        help="체크하면 가상의 점검 결과로 UI를 시연합니다. 발표 시 유용합니다.",
    )
    if demo_mode:
        demo_scenario = st.radio(
            "시나리오 선택",
            ["취약한 계정 (문제 상황)", "안전한 계정 (조치 후)"],
            help="발표 스토리에 맞춰 선택하세요.",
        )

    st.markdown("---")

    # 점검 시작 버튼
    start_btn = st.button("보안 점검 시작", type="primary", use_container_width=True)

    st.markdown("---")
    st.caption("Read-Only 권한만 사용합니다. 설정 변경 작업은 수행하지 않습니다.")


# ══════════════════════════════════════════════════════════════════════════════
# 메인 화면 헤더
# ══════════════════════════════════════════════════════════════════════════════

st.markdown('<div class="section-label">AWS account audit</div>', unsafe_allow_html=True)
st.title("Cloud Configuration Security Checker")
st.markdown(
    '<div class="hero-copy">AWS 계정의 IAM, S3, Security Group, CloudTrail 설정을 점검하고 '
    "위험 항목과 조치 내용을 한 화면에서 확인합니다.</div>",
    unsafe_allow_html=True,
)

# 점검 전 기본 화면
if not start_btn:
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("점검 항목", "4가지 카테고리")
    col2.metric("점검 세부 항목", "8+ 항목")
    col3.metric("소요 시간", "약 10~30초")
    col4.metric("필요 권한", "Read-Only")

    st.markdown(
        '<div class="callout">왼쪽 사이드바에서 AWS 자격증명과 점검 범위를 확인한 뒤 보안 점검을 시작하세요.</div>',
        unsafe_allow_html=True,
    )

    # 각 점검 항목 소개 카드
    st.markdown("### 점검 항목")
    c1, c2 = st.columns(2)
    with c1:
        st.markdown(
            """
            <div class="quiet-panel">
                <strong>IAM 계정 보안</strong>
                <span>루트 계정 MFA와 패스워드 정책을 확인합니다. 계정 탈취 위험을 줄이는 기본 통제 항목입니다.</span>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.markdown(
            """
            <div class="quiet-panel">
                <strong>S3 퍼블릭 접근</strong>
                <span>버킷의 Public Access Block과 ACL 상태를 확인해 의도하지 않은 공개 설정을 찾습니다.</span>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with c2:
        st.markdown(
            """
            <div class="quiet-panel">
                <strong>Security Group</strong>
                <span>SSH, RDP 등 민감한 포트가 전체 인터넷에 열려 있는지 확인합니다.</span>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.markdown(
            """
            <div class="quiet-panel">
                <strong>CloudTrail 로깅</strong>
                <span>Trail 존재 여부, 로깅 활성화, 멀티 리전 설정을 확인해 추적 가능성을 점검합니다.</span>
            </div>
            """,
            unsafe_allow_html=True,
        )
    st.stop()  # 점검 전에는 여기서 렌더링 중단


# ══════════════════════════════════════════════════════════════════════════════
# 점검 실행 로직
# ══════════════════════════════════════════════════════════════════════════════

all_results: list[dict] = []

# ── 데모 모드: 가상 결과 사용 ─────────────────────────────────────────────────
if demo_mode:
    st.info("데모 모드: 실제 AWS 호출 없이 가상의 점검 결과를 표시합니다.")
    with st.spinner("점검 시뮬레이션 중..."):
        import time; time.sleep(1.5)  # 실제 점검처럼 약간의 지연 연출

    if demo_scenario == "취약한 계정 (문제 상황)":
        all_results = get_vulnerable_results()
        st.warning("시나리오: 다수의 보안 취약점이 발견된 계정")
    else:
        all_results = get_secure_results()
        st.success("시나리오: 모든 보안 설정이 올바른 계정")

# ── 실제 AWS 점검 ─────────────────────────────────────────────────────────────
else:
    # 자격증명을 환경 변수에 임시 설정 (boto3가 자동으로 읽음)
    os.environ["AWS_ACCESS_KEY_ID"]     = access_key
    os.environ["AWS_SECRET_ACCESS_KEY"] = secret_key
    os.environ["AWS_DEFAULT_REGION"]    = region

    # 연결 확인
    with st.spinner("AWS 계정 연결 확인 중..."):
        conn = verify_connection()

    if not conn["success"]:
        st.error(f"AWS 연결 실패: {conn['error']}")
        st.info("자격증명을 다시 확인하고 재시도해 주세요.")
        st.stop()

    st.success(
        f"AWS 연결 성공 | 계정: `{conn['account_id']}` | "
        f"리전: `{region}` | 시각: {datetime.datetime.now().strftime('%H:%M:%S')}"
    )

    progress_bar = st.progress(0, text="점검 준비 중...")

    if run_iam:
        progress_bar.progress(10, text="IAM 보안 점검 중...")
        all_results.extend(checker_iam.run_all_checks())

    if run_s3:
        progress_bar.progress(35, text="S3 버킷 점검 중...")
        all_results.extend(checker_s3.run_all_checks())

    if run_sg:
        progress_bar.progress(60, text="보안 그룹 점검 중...")
        all_results.extend(checker_sg.run_all_checks())

    if run_ct:
        progress_bar.progress(85, text="CloudTrail 로깅 점검 중...")
        all_results.extend(checker_cloudtrail.run_all_checks())

    progress_bar.progress(100, text="점검 완료")

if not all_results:
    st.warning("점검 항목을 하나 이상 선택해 주세요.")
    st.stop()

# 점수 계산
score_info = calculate_score(all_results)


# ══════════════════════════════════════════════════════════════════════════════
# 보안 점수 대시보드
# ══════════════════════════════════════════════════════════════════════════════

st.markdown("## 보안 점수")

col_gauge, col_summary = st.columns([1, 2])

with col_gauge:
    # ── Plotly 게이지 차트 ────────────────────────────────────────────────────
    score = score_info["score"]

    # 점수 구간별 게이지 색상 결정
    if score >= 90:
        gauge_color = "#2ecc71"   # 초록
    elif score >= 70:
        gauge_color = "#3498db"   # 파랑
    elif score >= 50:
        gauge_color = "#f39c12"   # 주황
    else:
        gauge_color = "#e74c3c"   # 빨강

    fig = go.Figure(go.Indicator(
        mode  = "gauge+number+delta",
        value = score,
        delta = {"reference": 70, "increasing": {"color": "#2ecc71"}},
        title = {"text": f"보안 점수<br><span style='font-size:0.8em'>{score_info['grade']}등급 ({score_info['grade_label']})</span>"},
        gauge = {
            "axis":  {"range": [0, 100], "tickwidth": 1},
            "bar":   {"color": gauge_color},
            "steps": [
                {"range": [0,  30], "color": "#fadbd8"},  # 위험 구간 (연빨강)
                {"range": [30, 50], "color": "#fde8d8"},  # 주의 구간 (연주황)
                {"range": [50, 70], "color": "#fef9e7"},  # 양호 구간 (연노랑)
                {"range": [70, 90], "color": "#eafaf1"},  # 우수 구간 (연초록)
                {"range": [90,100], "color": "#d5f5e3"},  # 최우수 (초록)
            ],
            "threshold": {
                "line":  {"color": "red", "width": 4},
                "thickness": 0.75,
                "value": 70,  # 권고 최소 점수 기준선
            },
        }
    ))
    fig.update_layout(height=280, margin=dict(t=40, b=10, l=20, r=20))
    st.plotly_chart(fig, use_container_width=True)

with col_summary:
    # ── 요약 지표 카드 4개 ────────────────────────────────────────────────────
    st.markdown("### 점검 요약")
    m1, m2, m3, m4 = st.columns(4)

    m1.metric(
        "종합 점수",
        f"{score_info['score']}점",
        help="100점 만점. CRITICAL 실패 시 -40점, HIGH -20점",
    )
    m2.metric(
        "등급",
        f"{score_info['grade']} ({score_info['grade_label']})",
    )
    m3.metric(
        "통과",
        f"{score_info['pass_count']}개",
    )
    m4.metric(
        "실패/경고",
        f"{score_info['fail_count']}개",
        delta=f"-{score_info['fail_count']}" if score_info['fail_count'] > 0 else None,
        delta_color="inverse",
    )

    # 위험 수준별 카운트 표시
    st.markdown("---")
    st.markdown("**위험도별 실패 현황**")

    # 심각도별로 FAIL/WARN/ERROR 항목 집계
    severity_counts = {}
    for r in all_results:
        if r["status"] != "PASS":
            sev = r.get("severity", "UNKNOWN")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

    if severity_counts:
        sev_colors = {
            "CRITICAL": "status-critical",
            "HIGH":     "status-high",
            "MEDIUM":   "status-medium",
            "LOW":      "status-low",
        }
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            if sev in severity_counts:
                css_class = sev_colors.get(sev, "")
                st.markdown(
                    f'<div class="risk-line"><span class="{css_class}">{sev}</span>'
                    f"<span>{severity_counts[sev]}개</span></div>",
                    unsafe_allow_html=True,
                )
    else:
        st.success("모든 항목이 정상입니다.")


# ══════════════════════════════════════════════════════════════════════════════
# 점검 결과 상세 테이블
# ══════════════════════════════════════════════════════════════════════════════

st.markdown("---")
st.markdown("## 점검 결과 상세")

# 상태 필터 선택
status_filter = st.multiselect(
    "상태 필터",
    options=["PASS", "FAIL", "WARN", "ERROR"],
    default=["FAIL", "WARN", "ERROR"],  # 기본값: 문제 있는 것만 표시
    help="보고 싶은 상태를 선택하세요.",
)

# 필터 적용
filtered = [r for r in all_results if r["status"] in status_filter] if status_filter else all_results

if not filtered:
    st.success("선택한 상태에 해당하는 항목이 없습니다.")
else:
    # 테이블 데이터 구성
    table_data = []
    for r in filtered:
        table_data.append({
            "상태":      r["status"],
            "심각도":    r["severity"],
            "점검 항목": r["check_name"],
            "설명":      r["description"],
        })

    df_display = pd.DataFrame(table_data)
    st.dataframe(df_display, use_container_width=True, hide_index=True)


# ══════════════════════════════════════════════════════════════════════════════
# 실패 항목 조치 가이드 (아코디언 형태)
# ══════════════════════════════════════════════════════════════════════════════

fail_items = [r for r in all_results if r["status"] in ("FAIL", "WARN")]

if fail_items:
    st.markdown("---")
    st.markdown("## 조치 가이드")
    st.markdown("문제가 발견된 항목의 조치 방법입니다.")

    for item in fail_items:
        # expander: 접었다 펼 수 있는 UI 컴포넌트
        with st.expander(f"{item['severity']} · {item['check_name']}"):
            st.markdown(f"**문제 설명:** {item['description']}")
            st.markdown(f"**상세 내용:** `{item['detail']}`")

            # 심각도에 따른 강조 스타일
            if item["severity"] == "CRITICAL":
                st.error(f"즉각 조치 필요: {item['remediation']}")
            elif item["severity"] == "HIGH":
                st.warning(f"조기 조치 권고: {item['remediation']}")
            else:
                st.info(f"조치 권고: {item['remediation']}")


# ══════════════════════════════════════════════════════════════════════════════
# 리포트 다운로드
# ══════════════════════════════════════════════════════════════════════════════

st.markdown("---")
st.markdown("## 리포트 다운로드")

now_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

col_csv, col_pdf = st.columns(2)

with col_csv:
    # CSV 다운로드 버튼
    csv_bytes = to_csv_bytes(all_results)
    st.download_button(
        label="CSV 다운로드",
        data=csv_bytes,
        file_name=f"security_report_{now_str}.csv",
        mime="text/csv",
        use_container_width=True,
    )

with col_pdf:
    # PDF 다운로드 버튼
    try:
        pdf_bytes = to_pdf_bytes(all_results, score_info)
        st.download_button(
            label="PDF 다운로드",
            data=pdf_bytes,
            file_name=f"security_report_{now_str}.pdf",
            mime="application/pdf",
            use_container_width=True,
        )
    except Exception as e:
        st.warning(f"PDF 생성 중 오류 발생: {e}\n(fpdf2 설치 여부를 확인하세요)")


# ══════════════════════════════════════════════════════════════════════════════
# 푸터
# ══════════════════════════════════════════════════════════════════════════════

st.markdown("---")
st.caption(
    "Cloud Configuration Security Checker | "
    "Python 프로그래밍 기말 프로젝트 | "
    "이 툴은 읽기 전용 작업만 수행하며 설정 변경을 하지 않습니다."
)
