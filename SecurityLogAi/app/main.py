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

# 사이드바 설정
with st.sidebar:
    st.header("⚙️ 설정")
    api_key = st.text_input("OpenAI API Key", type="password", value=os.getenv("OPENAI_API_KEY", ""))
    if api_key:
        os.environ["OPENAI_API_KEY"] = api_key # 추후에 없엘 예정
    
    st.divider()
    st.subheader("📋 시스템 상태")
    st.info(f"Main Agent: {manager.name}")
    st.success("System Ready")

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
    if msg["role"] != "system":
        with st.chat_message(msg["role"]):
            st.write(msg["content"])

# 파일 업로더
uploaded_file = st.file_uploader("로그 파일 업로드 (.log, .txt)", type=["log", "txt"])

# 사용자 입력 처리
if prompt := st.chat_input("셜록에게 질문하세요"):
    # 사용자 메시지 표시
    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)

    # 에이전트 실행
    with st.chat_message("assistant"):
        message_placeholder = st.empty()
        full_response = ""
        
        # 상태 표시창 (에이전트 활동 시각화)
        status_container = st.status("🕵️ Sherlog이 분석을 시작합니다...", expanded=True)
        
        # 콜백 함수 정의 (상태창 업데이트용)
        def ui_callback(event, data):
            if event == "agent_start":
                # 에이전트 전환 알림
                agent_name = data
                status_container.write(f"**🔄 에이전트 전환: {agent_name}**")
                if agent_name == "Sentinel":
                    status_container.update(label="🛡️ Sentinel이 로그를 분석 중입니다...", state="running")
                elif agent_name == "Analyst":
                    status_container.update(label="🧠 Analyst가 심층 분석 중입니다...", state="running")
                
            elif event == "tool_start":
                # 도구 실행 알림
                tool_name = data.get("name")
                args = data.get("arguments")
                
                # 내부 핸드오프 도구는 굳이 인자를 보여줄 필요가 없을 수 있음 (너무 길어서)
                if tool_name in ["consult_sentinel", "consult_analyst"]:
                     status_container.write(f"  ↳ 📞 하위 에이전트 호출: `{tool_name}`")
                else:
                     status_container.write(f"  ↳ 🛠️ 도구 실행: `{tool_name}`")
                     with status_container.expander(f"입력 데이터 ({tool_name})"):
                         st.json(args)
            
            elif event == "tool_end":
                tool_name = data.get("name")
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
            
            # 응답 저장
            st.session_state.messages.append({"role": "assistant", "content": full_response})

        except Exception as e:
            status_container.update(label="❌ 오류 발생", state="error")
            st.error(f"Error: {str(e)}")
        finally:
            set_global_callback(None) # 콜백 해제

# 파일 업로드 로직
if uploaded_file and "file_processed" not in st.session_state:
    # 파일 내용 읽기
    log_content = uploaded_file.read().decode("utf-8")
    
    # 텍스트가 너무 길면 잘라내기 -> 나중에 파싱과정에서 수정할 예정 ml팀과 피쳐 협업
    if len(log_content) > 2000:
        log_content = log_content[:2000] + "\n...(생략)..."
        
    user_msg = f"다음 로그 파일을 분석해줘:\n\n```\n{log_content}\n```"
    
    # 세션에 메시지 추가 및 재시작
    st.session_state.messages.append({"role": "user", "content": user_msg})
    st.session_state["file_processed"] = True
    st.rerun()
