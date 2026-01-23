# agents/agent_setup.py
from openai_agents import Agent
from agents.tools import detect_attack_tool, search_threat_tool

# 1. 로그 분석 에이전트
sentinel = Agent(
    name="Sentinel",
    instructions="로그를 분석하여 공격 여부를 판단하세요.",
    # tools=[detect_attack_tool]
)

# 2. 검색 에이전트
analyst = Agent(
    name="Analyst",
    instructions="공격 유형에 대한 최신 보안 정보를 검색하세요.",
    # tools=[search_threat_tool]
)

# 3. 매니저
manager = Agent(
    name="Sherlog",
    instructions="Sentinel과 Analyst를 관리하여 보안 리포트를 작성하세요.",
    # tools=[sentinel, analyst]
)
