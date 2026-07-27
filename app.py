import datetime
import os
from urllib.parse import parse_qs, urlparse
import dotenv
import pandas as pd
import requests
import streamlit as st
from streamlit.errors import StreamlitSecretNotFoundError

# Nạp các biến môi trường từ file .env
dotenv.load_dotenv()


# ==============================================================================
# 1. BẢO MẬT CONFIGS & HẰNG SỐ ẨN NGẦM (HIDDEN CONFIGS)
# ==============================================================================
def get_secret(key, default_val=""):
    """Lấy biến môi trường an toàn, không gây sập app nếu thiếu secrets.toml"""
    try:
        if key in st.secrets:
            return st.secrets[key]
    except StreamlitSecretNotFoundError:
        pass

    env_val = os.getenv(key)
    if env_val:
        return env_val

    return default_val


# MÁY CHỦ SSO VÀ ENDPOINT BÁO CÁO ĐÃ ĐƯỢC FIX CỨNG NGẦM (ẨN KHỎI UI)
BASE_SSO_DOMAIN = get_secret("SSO_DOMAIN", "https://tttm.dongnai.gov.vn")
REPORT_ENDPOINT = get_secret(
    "REPORT_ENDPOINT", "https://tttm.dongnai.gov.vn/cmsapi/api/Report/overall2"
)
DEFAULT_USER = get_secret("SSO_USER", "")
DEFAULT_PASS = get_secret("SSO_PASS", "")

# ==============================================================================
# 2. CẤU HÌNH TRANG & STYLESHEET IOC DARK THEME
# ==============================================================================
st.set_page_config(
    page_title="IOC Đồng Nai - Giám Sát Hạ Tầng Truyền Thanh",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

st.markdown(
    """
<style>
    .stApp { background-color: #06101e; color: #e2e8f0; }
    
    .ioc-header {
        display: flex; justify-content: space-between; align-items: center;
        background: #0d1b2a; padding: 12px 20px; border-radius: 8px;
        border-bottom: 2px solid #1b263b; margin-bottom: 15px;
    }
    .ioc-title { color: #e0a96d; font-size: 20px; font-weight: bold; text-transform: uppercase; }
    .ioc-time { color: #fca311; font-size: 13px; font-weight: 600; }

    .kpi-card {
        background: #0d1b2b; border: 1px solid #1e293b; border-radius: 8px;
        padding: 12px; text-align: center; height: 100%;
        box-shadow: inset 0 0 10px rgba(0,0,0,0.5);
    }
    .kpi-card-danger { border: 2px solid #ef4444; background: rgba(239, 68, 68, 0.08); }
    .kpi-card-warning { border: 2px solid #f59e0b; background: rgba(245, 158, 11, 0.08); }
    
    .kpi-title { font-size: 12px; color: #94a3b8; font-weight: 600; text-transform: uppercase; margin-bottom: 6px; }
    .kpi-val-blue { font-size: 26px; font-weight: 800; color: #3b82f6; }
    .kpi-val-green { font-size: 26px; font-weight: 800; color: #10b981; }
    .kpi-val-red { font-size: 26px; font-weight: 800; color: #ef4444; }
    .kpi-val-yellow { font-size: 26px; font-weight: 800; color: #f59e0b; }
</style>
""",
    unsafe_allow_html=True,
)

# Quản lý Session Token trong bộ nhớ
if "final_jwt_token" not in st.session_state:
    st.session_state["final_jwt_token"] = ""
if "token_expires_at" not in st.session_state:
    st.session_state["token_expires_at"] = None

# ==============================================================================
# 3. SIDEBAR - FORM ĐĂNG NHẬP GỌN (ĐÃ ẨN SSO DOMAIN & ENDPOINT)
# ==============================================================================
with st.sidebar:
    st.title("🔑 ĐĂNG NHẬP HỆ THỐNG")

    with st.form("login_form"):
        user_input = st.text_input("Tài khoản", value=DEFAULT_USER)
        pass_input = st.text_input(
            "Mật khẩu", value=DEFAULT_PASS, type="password"
        )
        submit_login = st.form_submit_button(
            "⚡ Đăng nhập SSO", type="primary", use_container_width=True
        )

    # Nút Xóa phiên làm việc (Logout)
    if st.session_state["final_jwt_token"]:
        if st.button(
            "🔒 Đăng Xuất (Xóa Session)", use_container_width=True
        ):
            st.session_state["final_jwt_token"] = ""
            st.session_state["token_expires_at"] = None
            st.rerun()

    # Xử lý Logic xác thực SSO tự động theo Domain đã giấu ngầm
    if submit_login:
        base = BASE_SSO_DOMAIN.rstrip("/")
        payload = {"accountUserName": user_input, "accountPassword": pass_input}
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        with st.spinner("Đang xác thực bảo mật..."):
            try:
                # Bước 1: Login
                res_login = requests.post(
                    f"{base}/ssoapi/api/Accounts/Login",
                    json=payload,
                    headers=headers,
                    timeout=15,
                    verify=True,
                )
                if res_login.status_code == 200:
                    l_data = res_login.json()
                    l_token = (
                        l_data.get("data", {}).get("accessToken")
                        if isinstance(l_data.get("data"), dict)
                        else l_data.get("accessToken")
                    )

                    if l_token:
                        # Bước 2: AllowedAccess
                        res_acc = requests.get(
                            f"{base}/ssoapi/api/Applications/AllowedAccess",
                            json=payload,
                            headers={"Authorization": f"Bearer {l_token}"},
                            timeout=15,
                            verify=True,
                        )
                        if res_acc.status_code == 200:
                            acc_data = res_acc.json()
                            redirect_url = ""
                            if isinstance(acc_data, dict):
                                inner = acc_data.get("data") or acc_data
                                redirect_url = (
                                    inner[0].get("applicationRedirectUrl")
                                    if isinstance(inner, list)
                                    and len(inner) > 0
                                    else inner.get("applicationRedirectUrl", "")
                                )

                            code_val = None
                            if redirect_url:
                                parsed = urlparse(redirect_url)
                                query = parse_qs(parsed.query)
                                if "code" in query:
                                    code_val = query["code"][0]
                                elif (
                                    parsed.fragment and "?" in parsed.fragment
                                ):
                                    code_val = parse_qs(
                                        parsed.fragment.split("?", 1)[1]
                                    ).get("code", [None])[0]

                            if code_val:
                                # Bước 3: Auth
                                res_auth = requests.get(
                                    f"https://tttm.dongnai.gov.vn/cmsapi/api/Accounts/Auth?code={code_val}",
                                    json=payload,
                                    headers=headers,
                                    timeout=15,
                                    verify=True,
                                )
                                if res_auth.status_code == 200:
                                    final_tok = (
                                        res_auth.json()
                                        .get("data", {})
                                        .get(
                                            "accessToken",
                                            res_auth.json().get("accessToken"),
                                        )
                                    )
                                    st.session_state["final_jwt_token"] = (
                                        final_tok
                                    )
                                    st.session_state["token_expires_at"] = (
                                        datetime.datetime.now()
                                        + datetime.timedelta(minutes=60)
                                    )
                                    st.success("✅ Xác thực SSO Thành Công!")
                                else:
                                    st.error("Lỗi Auth Code!")
                            else:
                                st.error("Không bóc tách được 'code' từ URL!")
                        else:
                            st.error("Lỗi AllowedAccess!")
                    else:
                        st.error("Không lấy được Token Đăng nhập ở Bước 1!")
                else:
                    st.error("Lỗi Đăng nhập SSO! Vui lòng kiểm tra lại tài khoản/mật khẩu.")
            except Exception as e:
                st.error(f"❌ Lỗi kết nối: {e}")

# Tự động hủy Token khi hết hạn
if st.session_state["token_expires_at"]:
    if datetime.datetime.now() > st.session_state["token_expires_at"]:
        st.session_state["final_jwt_token"] = ""
        st.session_state["token_expires_at"] = None
        st.sidebar.warning("⚠️ Phiên làm việc đã hết hạn. Vui lòng đăng nhập lại!")

# ==============================================================================
# 4. GIAO DIỆN CHÍNH IOC DASHBOARD
# ==============================================================================

now_str = datetime.datetime.now().strftime("%d-%m-%Y %H:%M")
st.markdown(
    f"""
<div class="ioc-header">
    <div class="ioc-title">📡 IOC ĐỒNG NAI - GIÁM SÁT HẠ TẦNG TRUYỀN THÔNG CƠ SỞ</div>
    <div class="ioc-time">Thời gian đồng bộ dữ liệu: {now_str}</div>
</div>
""",
    unsafe_allow_html=True,
)

# THANH BỘ LỌC CẤP HÀNH CHÍNH & NÚT CẬP NHẬT
col_f1, col_f2, col_f3, col_f4, col_f5 = st.columns([2.5, 2, 2, 2, 1])

with col_f1:
    depth_map = {
        0: "Cấp Tỉnh/Thành phố (Overall)",
        1: "Cấp Xã / Phường / Thị trấn",
        2: "Cấp Cụm Loa Chi Tiết",
    }
    depth_option = st.selectbox(
        "Lọc cấp hành chính",
        options=[0, 1, 2],
        format_func=lambda x: depth_map[x],
        index=1,
    )
with col_f2:
    start_date = st.date_input("Từ ngày", datetime.date(2026, 7, 1))
with col_f3:
    end_date = st.date_input("Đến ngày", datetime.date(2026, 7, 24))
with col_f4:
    search_kw = st.text_input("Tìm đơn vị / Xã / Phường", value="")
with col_f5:
    st.write("")
    st.write("")
    btn_refresh = st.button(
        "🔄 Cập nhật IOC", type="primary", use_container_width=True
    )

token_active = st.session_state.get("final_jwt_token", "")

# KHU VỰC HIỂN THỊ DỮ LIỆU BÁO CÁO REALTIME
if not token_active:
    st.error(
        "🔒 Vui lòng mở Menu bên trái (Sidebar), nhập Tài khoản & Mật khẩu và bấm **⚡ Đăng nhập SSO** để kết nối hệ thống."
    )
else:
    params = {
        "pageSize": 100,
        "current": 1,
        "total": 1,
        "search": search_kw,
        "totalPages": 1,
        "hasNext": "false",
        "hasPrevious": "false",
        "DeviceType": 0,
        "depth": depth_option,
        "StartTime": f"{start_date} 00:00:00",
        "EndTime": f"{end_date} 23:59:59",
    }

    headers = {
        "Authorization": f"Bearer {token_active}",
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"
        ),
    }

    with st.spinner("Đang phân tích dữ liệu phủ sóng hạ tầng..."):
        try:
            res = requests.get(
                REPORT_ENDPOINT,
                params=params,
                headers=headers,
                timeout=60,
                verify=True,
            )

            if res.status_code == 200:
                json_resp = res.json()
                paged_data = json_resp.get("data", {}).get("pagedData", [])

                if paged_data:
                    df_raw = pd.DataFrame(paged_data)

                    # Chuẩn hóa kiểu dữ liệu
                    for num_col in [
                        "totalRadioDevice",
                        "totalConnectRadioDevice",
                        "totalDisConnectRadioDevice",
                        "totalTurnRadioSchedule",
                        "totalScheduleRadioDevice",
                        "totalScheduleApproveRadioDevice",
                    ]:
                        if num_col in df_raw.columns:
                            df_raw[num_col] = pd.to_numeric(
                                df_raw[num_col], errors="coerce"
                            ).fillna(0)

                    # Lọc nút cha tổng hợp để tránh nhân đôi số liệu
                    if "parentAreaId" in df_raw.columns and depth_option > 0:
                        df_calc = df_raw[df_raw["parentAreaId"].notnull()].copy()
                        if df_calc.empty:
                            df_calc = df_raw.copy()
                    else:
                        df_calc = df_raw.copy()

                    # BÓC TÁCH DỮ LIỆU ANALYTICS CỐT LÕI
                    total_units = len(df_calc)
                    invested_df = df_calc[df_calc["totalRadioDevice"] > 0]
                    uninvested_df = df_calc[df_calc["totalRadioDevice"] == 0]

                    invested_count = len(invested_df)
                    uninvested_count = len(uninvested_df)

                    coverage_rate = (
                        (invested_count / total_units * 100)
                        if total_units > 0
                        else 0
                    )

                    sum_radio = int(df_calc["totalRadioDevice"].sum())
                    sum_connect = int(df_calc["totalConnectRadioDevice"].sum())
                    sum_disconnect = int(
                        df_calc["totalDisConnectRadioDevice"].sum()
                    )

                    # --- 1. THẺ CHỈ SỐ METRIC CARDS ---
                    st.markdown(
                        "#### 📊 TỔNG QUAN PHỦ SÓNG HẠ TẦNG VÀ CẢNH BÁO ĐẦU TƯ"
                    )

                    k1, k2, k3, k4, k5 = st.columns(5)
                    with k1:
                        st.markdown(
                            f"""<div class="kpi-card">
                                <div class="kpi-title">Tổng số đơn vị</div>
                                <div class="kpi-val-blue">{total_units} <span style="font-size:14px">đơn vị</span></div>
                            </div>""",
                            unsafe_allow_html=True,
                        )

                    with k2:
                        st.markdown(
                            f"""<div class="kpi-card">
                                <div class="kpi-title">Đã trang bị cụm loa</div>
                                <div class="kpi-val-green">{invested_count} <span style="font-size:13px">({coverage_rate:.1f}%)</span></div>
                            </div>""",
                            unsafe_allow_html=True,
                        )

                    with k3:
                        st.markdown(
                            f"""<div class="kpi-card kpi-card-danger">
                                <div class="kpi-title">⚠️ Chưa đầu tư (Trống)</div>
                                <div class="kpi-val-red">{uninvested_count} <span style="font-size:13px">đơn vị</span></div>
                            </div>""",
                            unsafe_allow_html=True,
                        )

                    with k4:
                        st.markdown(
                            f"""<div class="kpi-card">
                                <div class="kpi-title">Tổng số cụm loa</div>
                                <div class="kpi-val-blue">{sum_radio:,} <span style="font-size:13px">cụm</span></div>
                            </div>""",
                            unsafe_allow_html=True,
                        )

                    with k5:
                        st.markdown(
                            f"""<div class="kpi-card kpi-card-warning">
                                <div class="kpi-title">Cụm Mất Kết Nối</div>
                                <div class="kpi-val-yellow">{sum_disconnect:,} <span style="font-size:13px">cụm</span></div>
                            </div>""",
                            unsafe_allow_html=True,
                        )

                    st.write("")

                    # --- 2. BIỂU ĐỒ TRỰC QUAN IOC ---
                    col_chart1, col_chart2 = st.columns([1.2, 1])

                    with col_chart1:
                        st.markdown(
                            "##### 📈 Tương quan Trang bị Hạ tầng Truyền thanh"
                            " theo Đơn vị"
                        )
                        if "tenNguon" in df_calc.columns:
                            chart_data = df_calc.set_index("tenNguon")[
                                [
                                    "totalConnectRadioDevice",
                                    "totalDisConnectRadioDevice",
                                ]
                            ]
                            chart_data.columns = [
                                "Loa Online",
                                "Loa Offline (Lỗi)",
                            ]
                            st.bar_chart(chart_data, height=330)

                    with col_chart2:
                        st.markdown(
                            "##### 🎯 Cơ cấu Tỷ lệ Phủ sóng Chuyển đổi số"
                        )
                        structure_df = pd.DataFrame(
                            {
                                "Đã trang bị cụm loa": [invested_count],
                                "Chưa đầu tư (Vùng trống)": [uninvested_count],
                            },
                            index=["Số lượng đơn vị"],
                        )
                        st.bar_chart(
                            structure_df,
                            height=330,
                            color=["#10b981", "#ef4444"],
                        )

                    # --- 3. BẢNG CẢNH BÁO ĐÔN ĐỐC (THIẾT BỊ = 0) ---
                    st.divider()
                    st.markdown(
                        f"##### 🚨 BẢNG DANH SÁCH {uninvested_count} ĐƠN VỊ CẦN"
                        " ĐÔN ĐỐC ĐẦU TƯ THIẾT BỊ (THIẾT BỊ = 0)"
                    )

                    if not uninvested_df.empty:
                        uninvested_disp = uninvested_df[
                            ["tenNguon", "areaCode", "totalTurnRadioSchedule"]
                        ].copy()
                        uninvested_disp.columns = [
                            "Đơn Vị Chưa Đầu Tư",
                            "Mã Hành Chính",
                            "Lượt Phát Hiện Tại",
                        ]
                        uninvested_disp["Trạng Thái Đầu Tư"] = (
                            "🔴 CHƯA TRANG BỊ CỤM LOA"
                        )

                        st.dataframe(
                            uninvested_disp,
                            use_container_width=True,
                            hide_index=True,
                        )
                    else:
                        st.success(
                            "🎉 100% các Xã/Phường trong khu vực đã được đầu"
                            " tư hạ tầng truyền thanh!"
                        )

                    # --- 4. BẢNG CHI TIẾT TỔNG HỢP ---
                    st.divider()
                    st.markdown(
                        "##### 📋 Chi Tiết Trạng Thái Toàn Bộ Đơn Vị Hành"
                        " Chính"
                    )

                    rename_cols = {
                        "tenNguon": "Đơn Vị Quản Lý",
                        "areaCode": "Mã Hành Chính",
                        "totalRadioDevice": "Tổng Cụm Loa",
                        "totalConnectRadioDevice": "Loa Online",
                        "totalDisConnectRadioDevice": "Loa Offline",
                        "totalTurnRadioSchedule": "Lượt Phát",
                        "totalScheduleApproveRadioDevice": "Lịch Duyệt",
                    }

                    disp_cols = [
                        c for c in rename_cols.keys() if c in df_calc.columns
                    ]
                    st.dataframe(
                        df_calc[disp_cols].rename(columns=rename_cols),
                        use_container_width=True,
                        hide_index=True,
                    )

                    st.download_button(
                        label="📥 BÁO CÁO ĐÔN ĐỐC ĐẦU TƯ (EXCEL/CSV)",
                        data=df_calc.to_csv(index=False).encode("utf-8-sig"),
                        file_name=(
                            f"Danh_Sach_Don_Vi_Chua_Dau_Tu_Depth_{depth_option}.csv"
                        ),
                        mime="text/csv",
                    )
                else:
                    st.warning("⚠️ Không tìm thấy bản ghi nào trong dữ liệu.")
            else:
                st.error(
                    f"❌ Lỗi gọi API Báo cáo overall2 (HTTP Status:"
                    f" {res.status_code})"
                )
        except Exception as e:
            st.error(f"⚠️ Lỗi kết nối: {e}")