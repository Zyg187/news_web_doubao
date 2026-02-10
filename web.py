import secrets
from typing import Any, Dict, Optional, Tuple

import mysql.connector
import streamlit as st
from passlib.context import CryptContext

# -------------------------
# 配置区：改成你的 MySQL 连接信息
# -------------------------
MYSQL_HOST = "127.0.0.1"
MYSQL_PORT = 3306
MYSQL_USER = "root"
MYSQL_PASSWORD = "zyg520..."
MYSQL_DATABASE = "news_app"

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")


def get_conn():
    return mysql.connector.connect(
        host=MYSQL_HOST,
        port=MYSQL_PORT,
        user=MYSQL_USER,
        password=MYSQL_PASSWORD,
        database=MYSQL_DATABASE,
        autocommit=True,
    )


# -------------------------
# 配置常量
# -------------------------
TIME_RANGE_OPTIONS = [
    ("1天内", "1day"),
    ("7天内", "7day"),
    ("30天内", "30day"),
]

DEFAULT_CFG: Dict[str, Any] = {
    "time_range": "7d",
    "output_format": "标题 | 时间 | 摘要 | 来源 | 链接",
    "query": "",
    "rounds": 2,
    "show_thinking": False,  # 只作为开关，不展示内容
}


def _normalize_cfg(cfg: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(DEFAULT_CFG)
    if isinstance(cfg, dict):
        for k in DEFAULT_CFG.keys():
            if k in cfg:
                out[k] = cfg.get(k)

    # time_range 校验
    valid_ranges = {v for _, v in TIME_RANGE_OPTIONS}
    if out.get("time_range") not in valid_ranges:
        out["time_range"] = DEFAULT_CFG["time_range"]

    # rounds 校验
    try:
        r = int(out.get("rounds", DEFAULT_CFG["rounds"]))
    except Exception:
        r = DEFAULT_CFG["rounds"]
    out["rounds"] = max(1, min(5, r))

    # 字段长度保护
    out["output_format"] = str(out.get("output_format", DEFAULT_CFG["output_format"]))[:500]
    out["query"] = str(out.get("query", ""))[:2000]
    out["show_thinking"] = bool(out.get("show_thinking", False))

    return out


# -------------------------
# 用户相关：注册/登录（改：用 employee 表）
# -------------------------
def create_user(employee_id: str, real_name: str, password: str) -> Tuple[bool, str]:
    employee_id = employee_id.strip()
    real_name = real_name.strip()
    if not employee_id or not real_name or not password:
        return False, "工号/姓名/密码不能为空"

    password_hash = pwd_context.hash(password)

    # 注册时同时写入默认配置
    cfg = _normalize_cfg({})
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO employee
              (employee_id, real_name, password_hash, time_range, output_format, query, rounds, show_thinking)
            VALUES
              (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                employee_id,
                real_name,
                password_hash,
                cfg["time_range"],
                cfg["output_format"],
                cfg["query"],
                int(cfg["rounds"]),
                1 if cfg["show_thinking"] else 0,
            ),
        )
        cur.close()
        conn.close()
        return True, "注册成功"
    except mysql.connector.errors.IntegrityError:
        return False, "该工号已注册"
    except Exception as e:
        return False, f"注册失败：{e}"


def authenticate(employee_id: str, password: str) -> Tuple[bool, Optional[int], str]:
    employee_id = employee_id.strip()
    if not employee_id or not password:
        return False, None, "工号/密码不能为空"

    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT id, password_hash FROM employee WHERE employee_id = %s",
            (employee_id,),
        )
        row = cur.fetchone()
        cur.close()
        conn.close()

        if not row:
            return False, None, "工号不存在"
        user_id, password_hash = row
        if not pwd_context.verify(password, password_hash):
            return False, None, "密码错误"
        return True, int(user_id), "登录成功"
    except Exception as e:
        return False, None, f"登录失败：{e}"


# -------------------------
# 配置相关：读取/保存（改：从 employee 表直接读写列）
# -------------------------
def load_user_config(user_id: int) -> Dict[str, Any]:
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT time_range, output_format, query, rounds, show_thinking
            FROM employee
            WHERE id = %s
            """,
            (user_id,),
        )
        row = cur.fetchone()
        cur.close()
        conn.close()

        if not row:
            return dict(DEFAULT_CFG)

        cfg = {
            "time_range": row[0],
            "output_format": row[1],
            "query": row[2],
            "rounds": int(row[3]) if row[3] is not None else DEFAULT_CFG["rounds"],
            "show_thinking": bool(row[4]),
        }
        return _normalize_cfg(cfg)
    except Exception:
        return dict(DEFAULT_CFG)


def save_user_config(user_id: int, cfg: Dict[str, Any]) -> Tuple[bool, str]:
    try:
        normalized = _normalize_cfg(cfg)

        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            UPDATE employee
            SET time_range=%s, output_format=%s, query=%s, rounds=%s, show_thinking=%s
            WHERE id=%s
            """,
            (
                normalized["time_range"],
                normalized["output_format"],
                normalized["query"],
                int(normalized["rounds"]),
                1 if normalized["show_thinking"] else 0,
                user_id,
            ),
        )
        cur.close()
        conn.close()
        return True, "保存成功"
    except Exception as e:
        return False, f"保存失败：{e}"


# -------------------------
# UI：登录页
# -------------------------
def render_login():
    page = st.session_state.get("auth_page", "login")

    if st.session_state.pop("show_register_success", None):
        st.success("注册成功！请登录")

    if page == "login":
        st.title("登录")
        employee_id = st.text_input("工号", key="login_employee_id")
        password = st.text_input("Password", type="password", key="login_password")

        col1, col2 = st.columns(2)
        with col1:
            if st.button("登录", type="primary"):
                ok, user_id, msg = authenticate(employee_id, password)
                if not ok:
                    st.error(msg)
                else:
                    st.session_state["token"] = secrets.token_urlsafe(24)
                    st.session_state["user_id"] = user_id
                    st.success(msg)
                    st.rerun()

        with col2:
            if st.button("去注册"):
                st.session_state["auth_page"] = "register"
                st.rerun()

    elif page == "register":
        st.title("注册")
        r_employee_id = st.text_input("工号", key="reg_employee_id")
        r_real_name = st.text_input("姓名", key="reg_real_name")
        r_password = st.text_input("Password", type="password", key="reg_password")

        col1, col2 = st.columns(2)
        with col1:
            if st.button("注册"):
                ok, msg = create_user(r_employee_id, r_real_name, r_password)
                if ok:
                    st.session_state["show_register_success"] = True
                    st.session_state["auth_page"] = "login"
                    st.rerun()
                else:
                    st.error(msg)

        with col2:
            if st.button("返回登录"):
                st.session_state["auth_page"] = "login"
                st.rerun()


# -------------------------
# UI：配置页（总览：第一行3个；第二行：输出格式 + 搜索内容）
# -------------------------
def render_config():
    user_id = st.session_state.get("user_id")
    if not user_id:
        st.error("未登录")
        st.session_state.pop("token", None)
        st.rerun()

    cfg = load_user_config(user_id)

    st.markdown(
        """
        <style>
          .block-container {padding-top: 1.8rem; padding-bottom: 2rem; max-width: 900px;}
          .cfg-title {font-size: 2rem; font-weight: 800; margin: 0 0 .25rem 0;}
          .cfg-sub {opacity: .72; margin: 0 0 1rem 0;}

          .summary-card {
            border-radius: 16px;
            padding: 14px 16px;
            margin: 6px 0 14px 0;
            border: 1px solid rgba(255,255,255,0.10);
            background: linear-gradient(135deg, rgba(79,70,229,0.18), rgba(16,185,129,0.14));
          }
          .summary-grid-3 {
            display: grid;
            grid-template-columns: repeat(3, minmax(0, 1fr));
            gap: 10px;
            margin-bottom: 10px;
          }
          .summary-item {
            background: rgba(0,0,0,0.18);
            border: 1px solid rgba(255,255,255,0.08);
            border-radius: 14px;
            padding: 10px 12px;
          }
          .summary-label {font-size: 0.75rem; opacity: .75; margin-bottom: 2px;}
          .summary-value {font-size: 1.05rem; font-weight: 700; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;}

          .cfg-card {
            background: rgba(255,255,255,0.03);
            border: 1px solid rgba(255,255,255,0.08);
            border-radius: 16px;
            padding: 16px;
            margin-bottom: 14px;
          }
          .action-card {
            background: rgba(255,255,255,0.03);
            border: 1px solid rgba(255,255,255,0.08);
            border-radius: 16px;
            padding: 12px 16px;
            margin-top: 6px;
          }

          @media (max-width: 900px) {
            .summary-grid-3 {grid-template-columns: 1fr;}
          }
        </style>
        """,
        unsafe_allow_html=True,
    )

    st.markdown('<div class="cfg-title">新闻配置</div>', unsafe_allow_html=True)
    st.markdown('<div class="cfg-sub">修改配置会实时刷新上方总览；点击保存才会写入数据库。</div>', unsafe_allow_html=True)

    # 初始化 session_state（首次进入）
    if "cfg_time_range" not in st.session_state:
        st.session_state["cfg_time_range"] = cfg.get("time_range", DEFAULT_CFG["time_range"])
    if "cfg_rounds" not in st.session_state:
        st.session_state["cfg_rounds"] = int(cfg.get("rounds", DEFAULT_CFG["rounds"]))
    if "cfg_output_format" not in st.session_state:
        st.session_state["cfg_output_format"] = cfg.get("output_format", DEFAULT_CFG["output_format"])
    if "cfg_query" not in st.session_state:
        st.session_state["cfg_query"] = cfg.get("query", "")
    if "cfg_show_thinking" not in st.session_state:
        st.session_state["cfg_show_thinking"] = bool(cfg.get("show_thinking", False))

    # 总览实时值
    def _label_time_range(v: str) -> str:
        return {"1d": "1天内", "7d": "7天内", "30d": "30天内"}.get(v, v)

    summary_time = _label_time_range(st.session_state["cfg_time_range"])
    summary_rounds = str(st.session_state["cfg_rounds"])
    summary_thinking = "开启" if st.session_state["cfg_show_thinking"] else "关闭"

    fmt = (st.session_state["cfg_output_format"] or "").strip()
    summary_fmt = fmt if fmt else "（未填写）"
    if len(summary_fmt) > 22:
        summary_fmt = summary_fmt[:22] + "…"

    q = (st.session_state["cfg_query"] or "").strip().replace("\n", " ")
    summary_query = q if q else "（未填写）"
    if len(summary_query) > 60:
        summary_query = summary_query[:60] + "…"

    st.markdown(
        f"""
        <div class="summary-card">
          <div class="summary-grid-3">
            <div class="summary-item">
              <div class="summary-label">搜索时间限制</div>
              <div class="summary-value">{summary_time}</div>
            </div>
            <div class="summary-item">
              <div class="summary-label">搜索轮次</div>
              <div class="summary-value">{summary_rounds}</div>
            </div>
            <div class="summary-item">
              <div class="summary-label">模型思考</div>
              <div class="summary-value">{summary_thinking}</div>
            </div>
          </div>

          <div class="summary-grid-3">
            <div class="summary-item">
              <div class="summary-label">输出格式</div>
              <div class="summary-value">{summary_fmt}</div>
            </div>
            <div class="summary-item" style="grid-column: span 2;">
              <div class="summary-label">搜索内容</div>
              <div class="summary-value">{summary_query}</div>
            </div>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # ---------- 主配置卡片 ----------
    st.markdown('<div class="cfg-card">', unsafe_allow_html=True)

    row1_left, row1_right = st.columns([1, 1])
    with row1_left:
        value_options = [v for _, v in TIME_RANGE_OPTIONS]
        label_map = {v: lbl for lbl, v in TIME_RANGE_OPTIONS}
        st.selectbox(
            "搜索时间限制",
            options=value_options,
            key="cfg_time_range",
            format_func=lambda v: label_map.get(v, v),
            help="按不同时间限制搜索",
        )

    with row1_right:
        st.slider(
            "搜索轮次（1~5）",
            min_value=1,
            max_value=5,
            step=1,
            key="cfg_rounds",
            help="轮次越高越倾向多轮追问/补全；也更耗时",
        )

    st.text_input(
        "输出格式",
        key="cfg_output_format",
        max_chars=500,
        help="短文本描述：例如 标题 | 时间 | 摘要 | 来源 | 链接",
    )

    st.text_area(
        "搜索内容（关键词/主题）",
        key="cfg_query",
        height=110,
        help="建议用空格/换行分隔多个关键词或主题词",
    )

    st.toggle(
        "模型思考（开关）",
        key="cfg_show_thinking",
        help="仅记录开/关状态，不展示思考内容",
    )

    st.markdown("</div>", unsafe_allow_html=True)

    # 保存对象（最新 session_state）
    new_cfg = {
        "time_range": st.session_state["cfg_time_range"],
        "output_format": st.session_state["cfg_output_format"],
        "query": st.session_state["cfg_query"],
        "rounds": int(st.session_state["cfg_rounds"]),
        "show_thinking": bool(st.session_state["cfg_show_thinking"]),
    }

    # ---------- 底部操作条 ----------
    st.markdown('<div class="action-card">', unsafe_allow_html=True)
    c1, c2, c3 = st.columns([1, 1, 1])
    with c1:
        if st.button("完成（保存）", type="primary", use_container_width=True):
            ok, msg = save_user_config(user_id, new_cfg)
            if ok:
                st.success(msg)
            else:
                st.error(msg)
    with c3:
        if st.button("退出登录", use_container_width=True):
            st.session_state.pop("token", None)
            st.session_state.pop("user_id", None)
            for k in ["cfg_time_range", "cfg_rounds", "cfg_output_format", "cfg_query", "cfg_show_thinking"]:
                st.session_state.pop(k, None)
            st.rerun()
    st.markdown("</div>", unsafe_allow_html=True)


# -------------------------
# 主入口：两页逻辑（登录 / 配置）
# -------------------------
def main():
    st.set_page_config(page_title="News Config", layout="centered")

    st.markdown(
        """
    <style>
    div[data-testid="stToolbar"] {display: none;}
    section[data-testid="stSidebar"] [role="button"] {display: none;}
    </style>
    """,
        unsafe_allow_html=True,
    )

    if "token" not in st.session_state:
        render_login()
    else:
        render_config()


if __name__ == "__main__":
    main()
