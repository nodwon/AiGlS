import streamlit as st
import os
import sys
from dotenv import load_dotenv

# 프로젝트 루트 경로 추가 (모듈 import 뻐킹 에러)
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../')))

from src.agents.openai_agents import Swarm
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
        
        # Swarm 실행 및 콜백 (스트림 처리 시뮬레이션)
        # 현재 openai_agents.py의 run 메서드는 스트리밍을 완벽히 지원하지 않음
        # 도구 실행 로그를 시각화하기 위해 약간의 개조가 필요함
        # 여기서는 결과만 받아서 처리
        
        try:
            response = st.session_state["client"].run(
                agent=manager,
                messages=st.session_state.messages
            )
            
            # 응답 처리
            if response.tool_calls:
                # 도구 호출이 있었다면 (사실상 run 내부에서 처리되므로 최종 응답만 옴)
                # 만약 run 메서드 내부 과정을 보고 싶다면 openai_agents.py 수정 필요
                # 현재는 최종 응답만 출력
                pass

            full_response = response.content
            message_placeholder.markdown(full_response)
            status_container.update(label="✅ 분석 완료", state="complete", expanded=False)
            
            # 응답 저장
            st.session_state.messages.append({"role": "assistant", "content": full_response})

        except Exception as e:
            status_container.update(label="❌ 오류 발생", state="error")
            st.error(f"Error: {str(e)}")

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
