"""
Agent 시스템 테스트 스크립트
- Sentinel, Analyst, Sherlog 응답 확인
- 보고서 형식 검증
- 에러 핸들링 테스트
"""
import os
import sys
from dotenv import load_dotenv

# 환경변수 로드
load_dotenv()

# 프로젝트 루트 경로 추가
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from src.agents.openai_agents import Swarm
from src.agents.agent_setup import manager

# 테스트 케이스 - 실제 웹 서버 로그 형식
test_cases = [
    {
        "name": "SQL Injection",
        "log": """192.168.1.100 - - [24/Jan/2025:10:30:45 +0900] "GET /api/users?id=1' OR '1'='1; SELECT * FROM users-- HTTP/1.1" 200 1234"""
    },
    {
        "name": "XSS Attack",
        "log": """10.0.0.50 - - [24/Jan/2025:11:15:22 +0900] "POST /comment HTTP/1.1" 200 567
User-Agent: Mozilla/5.0
Content: <script>alert(document.cookie)</script>"""
    },
    {
        "name": "Normal Traffic",
        "log": """192.168.1.25 - - [24/Jan/2025:09:12:33 +0900] "GET /index.html HTTP/1.1" 200 2048"""
    },
    {
        "name": "Path Traversal",
        "log": """203.0.113.45 - - [24/Jan/2025:14:22:11 +0900] "GET /../../etc/passwd HTTP/1.1" 403 0"""
    }
]

def run_test(test_case):
    """테스트 케이스 실행 및 검증"""
    print("\n" + "="*80)
    print(f"TEST: {test_case['name']}")
    print("="*80)
    print(f"\n입력 로그:\n{test_case['log']}\n")
    
    try:
        client = Swarm()
        response = client.run(
            agent=manager,
            messages=[{"role": "user", "content": f"다음 로그를 분석해줘:\n{test_case['log']}"}]
        )
        
        print("응답:")
        print("-"*80)
        print(response.content)
        print("-"*80)
        
        # 응답 검증
        content = response.content.lower()
        expected_sections = ["로그 분석 결과", "위협", "트렌드", "대응", "조치"]
        missing = [s for s in expected_sections if s not in content]
        
        if missing:
            print(f"\n  누락된 섹션: {', '.join(missing)}")
        else:
            print("\n 보고서 형식 검증 통과")
        
    except Exception as e:
        print(f"\n 에러 발생: {str(e)}")
        import traceback
        traceback.print_exc()

def check_environment():
    """환경 설정 확인"""
    print("="*80)
    print("환경 설정 확인")
    print("="*80)
    
    # OpenAI API 키 확인
    openai_key = os.getenv("OPENAI_API_KEY")
    if openai_key:
        print(f" OPENAI_API_KEY: {openai_key[:20]}...")
    else:
        print(" OPENAI_API_KEY가 설정되지 않았습니다.")
        print("   .env 파일에 OPENAI_API_KEY를 추가하세요.")
        return False
    
    # Tavily API 키 확인 
    tavily_key = os.getenv("TAVILY_API_KEY")
    if tavily_key:
        print(f" TAVILY_API_KEY: {tavily_key[:20]}...")
    else:
        print("  TAVILY_API_KEY 없음 (시뮬레이션 모드로 작동)")
    
    print()
    return True

if __name__ == "__main__":
    # 환경 확인
    if not check_environment():
        sys.exit(1)
    
    print(" Agent 시스템 테스트 시작")
    print(f"Manager Agent: {manager.name}")
    print(f"테스트 케이스: {len(test_cases)}개")
    print()
    
    # 테스트 실행
    success_count = 0
    for test_case in test_cases:
        try:
            run_test(test_case)
            success_count += 1
        except KeyboardInterrupt:
            print("\n\n중단됨")
            break
        except Exception as e:
            print(f"\n예상치 못한 에러: {str(e)}")
    
    # 결과 요약
    print("\n" + "="*80)
    print(f" 테스트 완료: {success_count}/{len(test_cases)}")
    print("="*80)