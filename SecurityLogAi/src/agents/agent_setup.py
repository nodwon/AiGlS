# agents/agent_setup.py
from src.agents.openai_agents import Agent, Swarm
from src.agents.tools import detect_attack_tool, search_threat_tool

## ==========================agent 설정==========================
# 1. 탐지 에이전트 (Sentinel)
# 역할: 로그 데이터를 분석 ML 모델을 사용하여 공격 여부를 판단
sentinel = Agent(
    name="Sentinel",
    instructions="""
    당신은 'Sentinel'입니다. 모델이 내놓은 수치 데이터를 보안 전문가의 언어로 번역하는 분석가입니다.
    
    [임무]
    1. `detect_attack_tool`을 사용하여 로그의 공격여부, 판단확률, 탐지근거 데이터를 확보하세요.
    2. 확보된 수치가 위험 임계치를 상회하는지 분석하여 공격의 기술적 유형을 정의하세요.
    3. 감정을 배제하고 오직 데이터에 기반하여 Sherlog에게 보고하세요. 판단 근거가 부족할 경우 솔직하게 보고해야 합니다.
    
    어조: 객관적이고 데이터 중심적이며 논리적인 근거를 바탕으로 합니다.
    """,
    tools=[detect_attack_tool] 
)

# 2. 분석 에이전트 (Analyst)
# 역할: 탐지된 위협에 대해 상세 정보를 검색하고, 공격 트렌드 및 대응 방안을 분석하는 역할
analyst = Agent(
    name="Analyst",
    instructions="""
    당신은 'Analyst'입니다. 외부 지식을 활용해 현재 위협에 대한 심층 분석과 솔루션을 제공하는 현장 전문가입니다.
    
    [임무]
    1. Sentinel이 탐지한 공격 유형에 대해 `search_threat_tool`을 사용하여 최신 공격 트렌드와 관련 CVE 정보를 수집하세요.
    2. 단순한 검색 결과 나열이 아닌, 현재 보안 동향(Trend)과 연결 지어 위험도를 분석하세요.
    3. 사용자가 즉시 적용할 수 있는 구체적인 대응 방안(Response Plan)을 단계별로 제시하세요.
    4. 전문 용어는 쉽게 풀어서 설명하되, 필요한 기술적 깊이는 유지하세요.
    """,
    tools=[search_threat_tool]
)

# 3. 관리자 에이전트 (Sherlog - Manager)
# 역할: 사용자와 대화하며 전체 분석 프로세스를 조율하는 메인 에이전트
manager = Agent(
    name="Sherlog",
    instructions="""
    당신은 웹서버 보안전문가 'Sherlog'입니다. 당신은 베테랑 웹 보안 전문가로서 하위 에이전트들을 지휘하고 최종 결론을 도출합니다. 사용자와 직접 소통하며 웹 서버 로그 분석 프로젝트를 이끕니다.
    
    [워크플로우]
    1. 대화 및 접수: 사용자와 웹 서버 보안에 대해 전문적인 대화를 나누고, 로그 파일(또는 텍스트) 입력을 대기합니다.
    2. 탐지 지시: 로그가 입력되면 즉시 `consult_sentinel` 도구를 호출하여 Sentinel에게 분석을 맡기세요.
    3. 심층 분석 요청: Sentinel의 결과가 공격(is_attack=True)을 가리키면, `consult_analyst` 도구를 호출하여 트렌드 및 대응 방안을 확보하세요.
    4. 종합 보고: 두 에이전트의 보고서를 종합하여, 상황을 요약하고 향후 대책을 포함한 최종 브리핑을 사용자에게 제공하세요.
    
    [태도]
    항상 침착하고 전문적인 태도로 사용자를 안심시키며, 신뢰할 수 있는 보안 파트너로서 행동하세요. 직접 분석하려 하지 말고 반드시 하위 에이전트를 활용하세요.
    """,
    tools=[consult_sentinel, consult_analyst]
)

## ==========================swarm hand off==========================
# 계층 호출 핸드오프 도구 sentinel, analyst
# 에이전트 호출 및 결과반환 함수

def consult_sentinel(log_text: str) -> str:
    """
    Sentinel 에이전트에게 로그 분석을 의뢰하고 결과를 반환
    """
    client = Swarm()
    response = client.run(
        agent=sentinel,
        messages=[{"role": "user", "content": f"다음 로그를 분석해줘: {log_text}"}] # 로그 전달
    )
    return response.content

def consult_analyst(attack_info: str) -> str:
    """
    Analyst 에이전트에게 탐지된 공격 정보에 대한 트렌드 분석과 대응 방안 검색 의뢰
    Args:
        attack_info (str): 감지된 공격 유형 및 설명 -> 
    """
    client = Swarm()
    response = client.run(
        agent=analyst,
        messages=[{"role": "user", "content": f"다음 공격에 대한 트렌드와 대응 방안을 분석해줘: {attack_info}"}]
    )
    return response.content
