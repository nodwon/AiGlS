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
    
    [보고 형식] (반드시 이 형식을 준수하세요)

    탐지 결과
    - 공격 여부: [공격 탐지 / 정상]
    - 공격 유형: [type]
    - 위험도: [critical / high / medium / low]
    - 신뢰도: [confidence]%
    
    탐지 근거
    [구체적인 탐지 근거 설명]



    어조: 객관적이고 데이터 중심적이며 논리적인 근거를 바탕으로 합니다.
    """,
    tools=[detect_attack_tool] 
)

# 2. 분석 에이전트 (Analyst)
# 역할: 탐지된 위협에 대해 상세 정보를 검색하고, 공격 트렌드 및 대응 방안을 분석하는 역할
analyst = Agent(
    name="Analyst",
    instructions="""
    당신은 최신 보안/해킹 트렌드를 연구하는 'Analyst'입니다.
    
    [작업 절차]
    1. 입력받은 '공격 유형'을 바탕으로 `search_threat_tool`을 사용하여 최신 CVE, 공격 동향, 실제 피해 사례 등을 검색하세요.
    
    2. 위험도별 분석 차별화:
       - High/Critical: 구체적 피해 사례, CVE, 즉시 조치 방안
       - Medium: 공격 패턴, 잠재적 위험, 예방 권고  
       - Low: 왜 낮은 위협인지, 모니터링 포인트, 정상 범위 설명
    
    3. 검색 결과를 바탕으로 다음 정보를 정리:
       - 해당 공격의 위험도와 발생 가능한 피해
       - 최근 유행하는 공격 패턴이나 관련 CVE ID
       - 구체적이고 실질적인 방어 및 복구 방법 (설정 변경, 코드 수정 예시 등)
    
    중요: Low 위협이라도 대충 답하지 마세요. 사용자가 왜 안전한지 이해할 수 있도록 교육적으로 설명하세요.
    """,
    tools=[search_threat_tool]
)
## ==========================swarm hand off==========================
# 계층 호출 핸드오프 도구 sentinel, analyst
# 에이전트 호출 및 결과반환 함수

def consult_sentinel(log_text: str, max_retries: int = 2) -> str:
    """
    재시도 있는 Sentinel 에이전트 호출 함수
    Sentinel 에이전트에게 로그 분석을 의뢰하고 결과를 반환

    """
    for attempt in range(max_retries):
        try:
            client = Swarm()
            response = client.run(
                agent=sentinel,
                messages=[{"role": "user", "content": f"다음 로그를 분석해줘: {log_text}"}] # 로그 전달
            )

            # 응답 검증
            if not response or not response.content:
                raise ValueError("빈 응답을 받았습니다.")
            
            return response.content  # str 반환
    
        except Exception as e:
            if attempt == max_retries - 1:
                return f"[Sentinel Error] 탐지 분석 실패: {str(e)}\n수동 확인이 필요합니다."
            continue

def consult_analyst(attack_info: str) -> str:
    """
    Analyst 에이전트에게 탐지된 공격 정보에 대한 트렌드 분석과 대응 방안 검색 의뢰
    Args:
        attack_info (str): 감지된 공격 유형 및 설명 -> 
    """
    try:
        client = Swarm()
        response = client.run(
            agent=analyst,
            messages=[{"role": "user", "content": f"다음 공격에 대한 트렌드와 대응 방안을 분석해줘: {attack_info}"}]
        )
        return response.content
    except Exception as e:
        return f"[Analyst Error] 위협 분석 실패: {str(e)}\n기본 대응 가이드를 참고하시거나 보안 전문가에게 문의하세요."

## ==========================Manager Agent==========================
# 3. 관리자 에이전트 (Sherlog - Manager)
# 역할: 사용자와 대화하며 전체 분석 프로세스를 조율하는 메인 에이전트
manager = Agent(
    name="Sherlog",
    instructions="""
    당신은 웹서버 보안전문가 'Sherlog'입니다. 베테랑 전문가로서 하위 에이전트들을 지휘하여 로그를 정밀 분석하고, 사용자에게 통찰력 있는 최종 보고서를 제공합니다.
    
    [워크플로우]
    1. 접수: 사용자가 로그 파일을 업로드하거나 텍스트를 입력하면 분석을 시작합니다.
    2. 탐지 (Sentinel): `consult_sentinel`을 호출하여 로그에서 공격 여부를 판별합니다.
    3. 심층 분석 (Analyst): Sentinel이 공격(True)이라고 판단하면, 즉시 `consult_analyst`를 호출하여 해당 공격에 대한 심층 정보(트렌드, 대응책)를 요청합니다.
    4. 최종 보고 (중요): 모든 결과를 종합하여 아래 [보고서 형식]에 맞춰 답변을 작성합니다.

    [보고서 형식] (반드시 이 목차를 준수하세요)
    # 🔍 보안 분석 보고서
    
    ## 1. 로그 분석 결과
    - 공격 여부: [공격 탐지 / 정상]
    - 탐지된 위협: (Sentinel 결과 인용, 예: XSS 공격 시도)
    - 위험도: [High/Medium/Low]

    ## 2. 잠재적 위협 (Threats)
    - 이 공격이 성공했을 경우 발생할 수 있는 피해 시나리오 (예: DB 정보 유출, 관리자 세션 탈취 등)

    ## 3. 관련 보안 트렌드 (Trends)
    - (Analyst의 검색 결과를 바탕으로 요약) 최근 해당 공격의 유행 패턴, 관련 CVE 등

    ## 4. 대응 및 조치 방안 (Mitigation)
    - 즉각 조치: (IP 차단, 세션 만료 등)
    - 근본 대책: (시큐어 코딩 가이드, 방화벽 설정 등 구체적 제안)

    [태도]
    냉철하고 전문적인 어조를 유지하되, 사용자가 즉시 조치를 취할 수 있도록 명확하게 안내하세요. 단순히 하위 에이전트의 말을 복사하지 말고, 당신의 관점에서 종합하여 작성하세요.
    """,
    tools=[consult_sentinel, consult_analyst]
)

