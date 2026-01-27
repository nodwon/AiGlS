import streamlit as st
import os
import sys
from dotenv import load_dotenv

# 프로젝트 루트 경로 추가 (모듈 import 뻐킹 에러)
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../')))

from src.agents.openai_agents import Swarm, set_global_callback
from src.agents.agent_setup import manager  # Sherlog (Manager Agent)

# 환경 변수 로드
load_dotenv()

st.set_page_config(page_title="Sherlog", page_icon="🕵️", layout="wide")

# 메인 타이틀
st.title("🕵️‍♂️ Sherlog")
st.caption("AI 웹 서버 보안 어시스턴트")

# 세션 상태 초기화
if "messages" not in st.session_state:
    st.session_state["messages"] = [{"role": "assistant", "content": "안녕하세요! 웹 서버 보안 관제 팀장 Sherlog입니다."}]

if "client" not in st.session_state:
    st.session_state["client"] = Swarm()


# 채팅 기록 표시
for msg in st.session_state.messages:
    # 시스템 메시지와 숨김 처리된 메시지는 건너뜀
    if msg["role"] != "system" and not msg.get("is_hidden"):
        with st.chat_message(msg["role"]):
            st.write(msg["content"])
            
            # [기능 개선] 특정 메시지에 종속된 CSV 다운로드 버튼
            item = msg.get("csv_data")
            if item:
                with open(item, "rb") as file:
                    st.download_button(
                        label="📥 분석 리포트 다운로드 (CSV)",
                        data=file,
                        file_name="analysis_report.csv",
                        mime="text/csv",
                        key=f"down_{msg.get('timestamp', 'autogen')}" # 유니크 키 필요
                    )

# 파일 업로드 (채팅창 상단 아이콘 스타일) - [위치 이동] 채팅창 바로 위로 배치
with st.popover("📎 로그 첨부", help="분석할 로그 파일을 업로드하세요"):
    uploaded_file = st.file_uploader("파일 선택", type=["log", "txt"], label_visibility="collapsed")

# 사용자 입력 처리
prompt = st.chat_input("셜록에게 질문하세요")

if prompt:
    st.session_state.messages.append({"role": "user", "content": prompt})
    st.rerun()

# 파일 업로드 로직
if uploaded_file:
    # 1. 파일을 임시 경로에 저장
    temp_dir = "SecurityLogAi/src/agents/temp_logs"
    os.makedirs(temp_dir, exist_ok=True)
    file_path = os.path.join(temp_dir, "upload.log")
    
    # 파일이 새로 업로드되었거나 교체되었을 때만 저장 및 알림
    # Streamlit은 리런될 때마다 uploaded_file이 유지되므로, session_state로 중복 처리 방지
    if "last_uploaded_file" not in st.session_state or st.session_state["last_uploaded_file"] != uploaded_file.name:
        with open(file_path, "wb") as f:
            f.write(uploaded_file.getbuffer())
        
        st.session_state["last_uploaded_file"] = uploaded_file.name
        st.toast(f"✅ 파일이 업로드되었습니다: {uploaded_file.name}", icon="📂")
        
        # 2. 에이전트에게 상황 인지 (System Message Injection)
        # 사용자가 "분석해줘"라고 할 때까지 기다리도록 지침 주입
        system_context = f"User has uploaded a log file at: {os.path.abspath(file_path)}. Do NOT analyze it immediately. Wait for the user to explicitly ask for analysis (e.g., 'Analyze this log')."
        
        st.session_state.messages.append({
            "role": "system", 
            "content": system_context
        })

# 마지막 메시지가 사용자라면 에이전트 실행
if st.session_state.messages[-1]["role"] == "user":
    with st.chat_message("assistant"):
        message_placeholder = st.empty()
        full_response = ""
        
        # CSV 파일의 수정 시간 확인 (분석 전)
        csv_path = "SecurityLogAi/src/agents/temp_logs/analysis_report.csv"
        before_mtime = 0
        if os.path.exists(csv_path):
            before_mtime = os.path.getmtime(csv_path)
        
        # 상태 표시창
        status_container = st.status("🕵️ Sherlog이 생각 중입니다...", expanded=True)
        
        # 콜백 함수 정의
        def ui_callback(event, data):
            NOISY_TOOLS = ["ml_detect_tool", "regex_detect_tool"]
            
            if event == "agent_start":
                agent_name = data
                status_container.write(f"**🔄 에이전트 전환: {agent_name}**")
                if agent_name == "Sentinel":
                    status_container.update(label="🛡️ Sentinel이 로그를 정밀 분석 중입니다...", state="running")
                elif agent_name == "Analyst":
                    status_container.update(label="🧠 Analyst가 심층 분석 및 대응책 모색 중입니다...", state="running")
                
            elif event == "tool_start":
                tool_name = data.get("name")
                if tool_name in NOISY_TOOLS: return
                if tool_name in ["consult_sentinel", "consult_analyst", "ask_analyst"]:
                     status_container.write(f"  ↳ 📞 하위 에이전트 호출: `{tool_name}`")
                else:
                     status_container.write(f"  ↳ 🛠️ 도구 실행: `{tool_name}`")
            
            elif event == "tool_end":
                tool_name = data.get("name")
                if tool_name in NOISY_TOOLS: return
                result = data.get("result")
                with status_container.expander(f"실행 결과 ({tool_name})"):
                    st.code(result)

        set_global_callback(ui_callback)
        
        try:
            response = st.session_state["client"].run(
                agent=manager,
                messages=st.session_state.messages
            )
            
            full_response = response.content
            message_placeholder.markdown(full_response)
            status_container.update(label="✅ 답변 완료", state="complete", expanded=False)

        except Exception as e:
            status_container.update(label="❌ 오류 발생", state="error")
            st.error(f"Error: {str(e)}")
        finally:
            set_global_callback(None) 
            
            # [CSV 버튼 로직 개선] 
            # 분석 후 파일이 새로 생겼거나 수정되었는지 확인 (mtime 비교)
            assistant_msg = {"role": "assistant", "content": full_response}
            
            if os.path.exists(csv_path):
                after_mtime = os.path.getmtime(csv_path)
                # 파일이 이번 턴에 수정되었다면 버튼 추가
                if after_mtime > before_mtime:
                     assistant_msg["csv_data"] = csv_path
                     import time
                     assistant_msg["timestamp"] = time.time()
            
            st.session_state.messages.append(assistant_msg)
            st.rerun()
