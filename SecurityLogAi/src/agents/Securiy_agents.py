import os
from dotenv import load_dotenv
from src.agents.openai_agents import Agent, Swarm
from src.agents.tools import detect_attack_tool, search_threat_tool

# 환경 변수 로드 (.env 파일에 API 키와 모델 경로가 있어야 합니다)
load_dotenv()

## ===========================================================
## 1. 하위 에이전트 호출용 도구 (Handoff Tools)
## ===========================================================

def consult_sentinel(log_text: str) -> str:
    """Sentinel 에이전트에게 로그 분석을 의뢰합니다."""
    swarm = Swarm()
    response = swarm.run(
        agent=sentinel,
        messages=[{"role": "user", "content": f"다음 로그를 분석해줘: {log_text}"}]
    )
    return response.content

def consult_analyst(attack_info: str) -> str:
    """Analyst 에이전트에게 위협 트렌드 및 대응 방안 분석을 의뢰합니다."""
    swarm = Swarm()
    response = swarm.run(
        agent=analyst,
        messages=[{"role": "user", "content": f"다음 위협을 분석해줘: {attack_info}"}]
    )
    return response.content

## ===========================================================
## 2. 개별 에이전트 정의 (Sentinel, Analyst)
## ===========================================================

# [Sentinel] 탐지 전문 에이전트
sentinel = Agent(
    name="Sentinel",
    instructions="""당신은 보안 탐지 엔진 'Sentinel'입니다. 
    'detect_attack_tool'을 실행하여 로그의 공격 여부와 확신도를 객관적으로 보고하세요. 
    사적인 의견은 배제하고 데이터 수치에 집중하세요.""",
    tools=[detect_attack_tool]
)

# [Analyst] 심층 분석 전문 에이전트
analyst = Agent(
    name="Analyst",
    instructions="""당신은 위협 인텔리전스 분석가 'Analyst'입니다. 
    'search_threat_tool'을 사용하여 탐지된 공격의 최신 트렌드와 구체적인 기술적 대응 방안(CVE, 패치 방법 등)을 조사하세요.""",
    tools=[search_threat_tool]
)

## ===========================================================
## 3. 메인 관리자 에이전트 (Sherlog)
## ===========================================================

# [Sherlog] 전체 프로세스 조율 및 보고서 작성
sherlog = Agent(
    name="Sherlog",
    instructions="""당신은 수석 보안 분석가 'Sherlog'입니다.
    
    [워크플로우]
    1. 사용자의 로그가 들어오면 'consult_sentinel'을 호출합니다.
    2. Sentinel이 공격(is_attack: True)이라고 하면 'consult_analyst'를 호출합니다.
    3. 모든 정보를 종합하여 '🔍 보안 분석 보고서' 형식으로 최종 답변을 작성하세요.
    
    [보고서 형식]
    ## 1. 로그 분석 결과 (공격명, 위험도)
    ## 2. 잠재적 위협 (성공 시 피해 시나리오)
    ## 3. 관련 보안 트렌드 (최신 동향)
    ## 4. 대응 및 조치 방안 (즉각 조치 & 근본 대책)
    """,
    tools=[consult_sentinel, consult_analyst]
)