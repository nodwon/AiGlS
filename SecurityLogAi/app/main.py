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

# 파일 업로드 로직 (자동 실행 트리거)
# 파일 업로드 로직 (자동 실행 트리거)
if uploaded_file and "file_processed" not in st.session_state:
    # 1. 파일을 임시 경로에 저장 (Sentinel이 읽을 수 있게)
    # [설정] 로그 파일 저장소 이동 -> src/agents/temp_logs
    temp_dir = "SecurityLogAi/src/agents/temp_logs"
    os.makedirs(temp_dir, exist_ok=True)
    file_path = os.path.join(temp_dir, "upload.log")
    
    with open(file_path, "wb") as f:
        f.write(uploaded_file.getbuffer())
        
    # 2. 에이전트에게 명령 (파일 경로 전달)
    # 이제 Sentinel이 알아서 batch_analysis_tool을 꺼내 들 것입니다.
    # [수정] 사용자 요청에 따라 "다음 경로... 분석해줘" 같은 기계적인 메시지는 UI에 노출하지 않음
    user_msg_content = f"다음 경로에 있는 로그 파일을 전수 분석해줘: {os.path.abspath(file_path)}"
    
    st.session_state.messages.append({
        "role": "user", 
        "content": user_msg_content,
        "is_hidden": True # UI 렌더링 시 숨김 처리용 플래그
    })
    st.session_state["file_processed"] = True
    st.rerun()

# 마지막 메시지가 사용자라면 에이전트 실행 (자동/수동 공통)
if st.session_state.messages[-1]["role"] == "user":
    with st.chat_message("assistant"):
        message_placeholder = st.empty()
        full_response = ""
        
        # 상태 표시창 (에이전트 활동 시각화)
        status_container = st.status("🕵️ Sherlog이 분석을 시작합니다...", expanded=True)
        
        # 콜백 함수 정의 (상태창 업데이트용)
        def ui_callback(event, data):
            # 너무 자주 호출되는 툴은 UI에 표시하지 않음 (노이즈 제거)
            NOISY_TOOLS = ["ml_detect_tool", "regex_detect_tool"]
            
            if event == "agent_start":
                # 에이전트 전환 알림
                agent_name = data
                status_container.write(f"**🔄 에이전트 전환: {agent_name}**")
                if agent_name == "Sentinel":
                    status_container.update(label="🛡️ Sentinel이 로그를 정밀 분석 중입니다...", state="running")
                elif agent_name == "Analyst":
                    status_container.update(label="🧠 Analyst가 심층 분석 및 대응책 모색 중입니다...", state="running")
                
            elif event == "tool_start":
                # 도구 실행 알림
                tool_name = data.get("name")
                
                # 시끄러운 툴은 생략
                if tool_name in NOISY_TOOLS:
                    return

                # 내부 핸드오프 도구는 굳이 인자를 보여줄 필요가 없을 수 있음
                if tool_name in ["consult_sentinel", "consult_analyst"]:
                     status_container.write(f"  ↳ 📞 하위 에이전트 호출: `{tool_name}`")
                else:
                     status_container.write(f"  ↳ 🛠️ 도구 실행: `{tool_name}`")
            
            elif event == "tool_end":
                tool_name = data.get("name")
                
                # 시끄러운 툴 결과는 생략 (최종 리포트에서 확인하세요)
                if tool_name in NOISY_TOOLS:
                    return

                result = data.get("result")
                # 결과는 너무 길 수 있으니 expander로
                with status_container.expander(f"실행 결과 ({tool_name})"):
                    st.code(result)

        # 전역 콜백 설정
        set_global_callback(ui_callback)
        
        try:
            response = st.session_state["client"].run(
                agent=manager,
                messages=st.session_state.messages
            )
            
            full_response = response.content
            message_placeholder.markdown(full_response)
            status_container.update(label="✅ 분석 완료", state="complete", expanded=False)
            
            # 응답 저장 (아래 finally 블록에서 처리함)
            # st.session_state.messages.append({"role": "assistant", "content": full_response})

        except Exception as e:
            status_container.update(label="❌ 오류 발생", state="error")
            st.error(f"Error: {str(e)}")
        finally:
            set_global_callback(None) # 콜백 해제
            
            # [UI 개선] 글로벌 버튼 대신, 마지막 메시지에 CSV 경로 메타데이터 추가
            # 분석 요청(숨겨진 메시지)에 대한 응답인 경우에만 버튼을 생성
            csv_path = "SecurityLogAi/src/agents/temp_logs/analysis_report.csv"
            assistant_msg = {"role": "assistant", "content": full_response}
            
            # 직전 메시지(User)가 '파일 분석 요청(is_hidden)'이었는지 확인
            last_user_msg = st.session_state.messages[-1]
            is_analysis_request = last_user_msg.get("is_hidden", False)
            
            if is_analysis_request and os.path.exists(csv_path):
                 assistant_msg["csv_data"] = csv_path
                 # 버튼 키 충돌 방지용 타임스탬프
                 import time
                 assistant_msg["timestamp"] = time.time()
            
            st.session_state.messages.append(assistant_msg)
            st.rerun() # 리런해야 위쪽 루프에서 버튼이 그려짐
