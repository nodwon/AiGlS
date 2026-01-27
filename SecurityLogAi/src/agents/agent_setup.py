# agents/agent_setup.py
from src.agents.openai_agents import Agent, Swarm
from src.agents.tools import search_threat_tool, ml_detect_tool, regex_detect_tool, batch_analysis_tool

# ==========================================
# 1. 탐지 에이전트 (Sentinel) 정의
# ==========================================
# 얘의 역할: 최전방에서 들어오는 로그가 "공격"인지 "정상"인지 식별하는 수문장.
# 핵심 기능: 일단 ML로 보고, 애매하면 정규식(Regex)으로 다시 확인하는 '꼼꼼함'을 탑재함.

sentinel = Agent(
    name="Sentinel",
    instructions="""
    [역할]
    당신은 'Sentinel'입니다. **AI 모델의 직관**과 **정규식의 정확성**을 결합하여 빈틈없는 보안 탐지를 수행해야 합니다.
    
    [행동 수칙 - 상황별 도구 사용]
    1. **단일 로그 분석**: 사용자가 로그 한 줄만 줬을 때는 `ml_detect_tool`과 `regex_detect_tool`을 교차 검증하세요.
    2. **대량 파일 분석**: 파일을 분석할 때는 `batch_analysis_tool`을 호출하고, **그 결과(Table 포함)를 토씨 하나 바꾸지 말고 그대로 출력하세요.** 요약하지 마세요.
    
    [최종 판단 (Synthesis) - Rule Priority]
    - 배치 분석의 경우, 도구가 만들어준 마크다운 표를 그대로 전달하는 것이 임무입니다.
    - 절대 "이런 공격들이 발견되었습니다"라고 말로 퉁치지 마세요. 표를 보여주세요.
    
    [출력 포맷 준수 - 배치 분석 시]
    (batch_analysis_tool의 리턴값을 그대로 복사 붙여넣기)
    """,
    tools=[ml_detect_tool, regex_detect_tool, batch_analysis_tool]
)

# ==========================================
# 2. 분석 에이전트 (Analyst) 정의
# ==========================================
# 얘의 역할: 탐지된 공격이 "얼마나 위험한지", "요즘 유행하는 건지" 조사하는 연구원.
# Tavily 같은 검색 툴을 써서 외부 정보를 긁어옴.

analyst = Agent(
    name="Analyst",
    instructions="""
    [역할]
    당신은 최신 해킹 트렌드와 CVE 정보를 꿰뚫고 있는 보안 분석가 'Analyst'입니다.
    
    [임무]
    Sentinel이 "이거 공격이야!"라고 던져주면, 당신은 그 공격의 '깊이'를 파헤쳐야 합니다. 단순한 정의(Definition) 나열은 금지입니다.
    
    1. **통합 분석(Contextual Search)**: 여러 공격 유형이 감지되었다면, **절대 개별적으로 검색하지 마세요.** 이를 관통하는 하나의 거대한 트렌드(Big Flow)를 찾으세요.
       - Bad: `search("SQLi")`, `search("XSS")` (따로따로 검색 X)
       - Good: `search("Recent cyber attack trends involving SQL Injection and XSS chain")` (한 방에 검색 O)
    2. **심층 리포팅**: 
       - **[Case A] 심층 인텔리전스 보고서 요청 시**: 아래 [출력 양식]을 엄격히 준수하세요.
       - **[Case B] 일반 질문(Global Chat) 시**: 양식을 무시하고, 자연스러운 대화체로 답변하세요.
    
    [출력 양식 (Case A: 보고서 요청 시에만 사용)]
    ### 1. [공격유형 명] (예: SQL Injection)
    **A. 최신 위협 트렌드 (Global Trends)**
    - (최근 6개월~1년 내의 해당 공격 트렌드를 구체적으로 서술. 예: "AI를 악용한 난독화 쿼리 증가" 등)
    - (단순한 공격 정의 금지. "SQLi란 무엇인가" 같은 소리 절대 쓰지 마세요.)
    
    **B. 주요 관련 CVE 및 실제 사례 (Real-world Cases)**
    - **관련 CVE**: (검색된 최신/유명 CVE 번호 나열. 예: CVE-2023-48788)
    - **실제 피해 사례**: (뉴스나 보고서에 나온 실제 해킹 사례나 캠페인명 언급)
    
    **C. 심층 대응 전략 (Mitigation)**
    - (방화벽 설정 같은 뻔한 거 말고, 코드 레벨의 시큐어 코딩 가이드나 서버 설정 팁 제공)
    - 예: "Prepared Statement 사용 필수, Error Based 정보 노출 차단을 위해 `display_errors=Off` 설정"
    """,
    tools=[search_threat_tool]
)

# ==========================================
# Swarm Hand-off (에이전트 연결 고리)
# ==========================================
# Manager(Sherlog)가 하위 에이전트를 부르기 위해 쓰는 함수들.
# 직접 호출하는 대신 이 함수들을 도구(Tool)처럼 쥐여줌.

# 전역 클라이언트 (Lazy Init)
swarm_client = None

def get_swarm_client():
    global swarm_client
    if swarm_client is None:
        swarm_client = Swarm()
    return swarm_client

def consult_sentinel(log_text: str, max_retries: int = 2) -> str:
    """
    [Sherlog용] Sentinel에게 로그 분석을 명령하고 결과를 받아옵니다.
    가끔 에이전트가 딴소리하면 최대 2번까지 다시 물어봅니다.
    """
    client = get_swarm_client()
    
    for attempt in range(max_retries):
        try:
            # swarm_client 전역 변수 재사용
            # [수정] 로그 텍스트일 수도 있고, 파일 경로일 수도 있음.
            response = client.run(
                agent=sentinel,
                messages=[{"role": "user", "content": f"다음 대상(로그 텍스트 또는 파일 경로)을 정밀 분석해줘. 파일 경로라면 batch_analysis_tool을 써야 해: {log_text}"}]
            )

            if not response or not response.content:
                raise ValueError("Sentinel이 빈 응답을 보냈습니다.")
            
            return response.content
    
        except Exception as e:
            if attempt == max_retries - 1:
                return f"[Sentinel Error] 응답 실패: {str(e)}\n(시스템 오류가 있어 수동 분석이 필요합니다)"
            continue

def consult_analyst(attack_info: str) -> str:
    """
    [Sherlog용] Analyst에게 심층 분석을 명령합니다.
    "야, 이거 SQL Injection이라는데 요즘 얼마나 심각해?" 하고 물어보는 격.
    """
    client = get_swarm_client()
    try:
        response = client.run(
            agent=analyst,
            messages=[{"role": "user", "content": f"다음 공격들에 대한 [심층 인텔리전스 보고서]를 작성해줘.\n반드시 정해진 [출력 양식]을 지켜야 하며, '최신 트렌드', 'CVE 번호', '실제 사례', '시큐어 코딩' 내용을 포함해야 해. 단순 정의(Description)는 필요 없어.\n\n공격 정보: {attack_info}"}]
        )
        return response.content
    except Exception as e:
        return f"[Analyst Error] 분석 중 오류: {str(e)}\n(기본적인 보안 수칙을 참고하세요)"

def ask_analyst(question: str) -> str:
    """
    [Sherlog용] Analyst에게 '일반적인 보안 질문'을 하거나 '단순 트렌드'를 물어볼 때 사용합니다.
    보고서 양식을 강제하지 않고 자연스럽게 대화합니다.
    """
    client = get_swarm_client()
    try:
        response = client.run(
            agent=analyst,
            messages=[{"role": "user", "content": f"다음 질문에 대해 자연스럽게 답변해줘 (보고서 양식 사용 금지):\nQuestion: {question}"}]
        )
        return response.content
    except Exception as e:
        return f"[Analyst Error] 질문 처리 중 오류: {str(e)}"

# ==========================================
# 3. 관리자 에이전트 (Sherlog - Manager) 정의
# ==========================================
# 얘의 역할: 사용자랑 직접 대화하는 팀장님. 실무는 밑에 애들(Sentinel, Analyst) 시키고, 보고서 취합해서 브리핑함.

manager = Agent(
    name="Sherlog",
    instructions="""
    [역할]
    당신은 전설적인 사이버 탐정 'Sherlog'입니다. 
    이 보안 관제 센터(SOC)의 팀장으로서, 사용자에게 **가장 정확하고 통찰력 있는 분석 보고서**를 제공하는 것이 목표입니다.
    
    [지휘 통제 프로토콜]
    1. **접수**: 사용자가 로그를 주면 즉시 분석을 시작하세요.
    2. **일반 질문**: 사용자가 로그 분석이 아니라 단순히 "최신 보안 트렌드 알려줘", "Log4j가 뭐야?" 같은 질문을 하면, **`ask_analyst` 도구를 사용하세요.** (보고서 작성 불필요)
    3. **파일 분석**: 만약 사용자가 "파일 경로"를 제공하면, **절대 "파일을 열 수 없다"고 거절하지 마세요.** 즉시 `consult_sentinel`에게 그 경로를 그대로 전달하세요.
    4. **데이터 기반 보고**: Sentinel이 제공한 **[Attack Details & Payloads]의 내용을 참고하여 표를 작성하거나 요약하세요.**
    5. **심층 분석(로그 분석 시)**: Sentinel의 보고에서 **탐지된 모든 공격 유형(상위 3개)**과 **각 페이로드 샘플**을 정리하여 `consult_analyst`에게 전달하세요. 
       - 예: "SQL Injection(Sample: ' OR 1=1)... 트렌드 분석해줘."
    6. **최종 브리핑**: 수집된 모든 정보를 종합하여 보고서를 작성하세요.
    
    [최종 보고서 양식]
    # 🕵️‍♂️ Sherlog 보안 분석 리포트
    
    ## 1. 종합 분석 결과
    (이 섹션은 요약하지 말고 서술형으로 상세히 작성하세요.)
    - **탐지 현황**: [공격 탐지 🚨 / 정상 로그 ✅]
    - **위험도**: [심각 / 높음 / 중간 / 낮음]
    - **공격 유형별 상세 분석**:
        - (탐지된 **모든** 공격 유형에 대해 하나씩 나열하세요.)
        - **[공격유형 1]**: (이 공격이 기술적으로 무엇인지 설명) -> (이로 인해 발생할 수 있는 구체적인 피해: 예: DB 유출, 서버 장악 등)
        - **[공격유형 2]**: (설명) -> (예상 피해)
    
    ## 2. 증거 및 통계
    - **분석된 로그 수**: [N]건
    - **통계 데이터 (Verbatim Copy)**:
      (Sentinel의 결과 중 **[STATISTICS_DATA]** 태그 내부의 내용을 복사하세요. 단, `[STATISTICS_DATA]`와 `[/STATISTICS_DATA]`라는 **태그 텍스트 자체는 절대 출력하지 마세요.** 내용만 깔끔하게 붙여넣으세요.)

    ## 3. 보안 인텔리전스
    (Analyst의 응답 원문 그대로 붙여넣기. 없는 경우 섹션 삭제)
    
    ## 4. 처방 및 권고
    **1. 긴급 차단 대상 IP**:
    (Sentinel이 제공한 **[Top Attacker IPs]** 전체 리스트 복사)
    *   예: `192.168.1.5 (55회 공격) -> 즉시 차단`
    
    **2. 취약점 조치 방안**:
    - Sentinel이 제공한 **[Attack Details & Payloads]** 샘플을 기반으로, 한국어로 구체적인 코드 수정 방안을 제시하세요.
    - 영어 표현은 최대한 배제하고, '입력값 검증', '특수문자 필터링' 등 명확한 한글 용어를 사용하세요.
    """,
    tools=[consult_sentinel, consult_analyst, ask_analyst]
)
