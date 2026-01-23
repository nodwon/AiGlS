# agents/tools.py
import os
import joblib
import re
from datetime import datetime
from src.agents.schemas import DetectionResult
try:
    from tavily import TavilyClient
except ImportError:
    TavilyClient = None

# 모델 파일 경로 설정 (지금은 임시로 정해놓음)
MODEL_PATH = os.path.join(os.path.dirname(__file__), "../../model/random_forest.pkl")

def detect_attack_tool(log_text: str) -> dict:
    """
    로그 텍스트를 분석하여 공격 여부를 탐지
    
    기능:
    1. 저장된 ML 모델(random_forest.pkl)을 로드하여 예측을 시도합니다.
    2. [임시] 모델이 없거나 로드 실패 시, 정규표현식(Regex) 기반의 룰셋으로 폴백(Fallback) 처리
    
    Args:
        log_text (str): 분석할 웹 서버 로그 텍스트
    Returns:
        dict: DetectionResult 스키마에 맞는 딕셔너리 (is_attack, confidence, type 등 포함)
    """
    
    # 1. ML 모델 기반 탐지 시도
    try:
        if os.path.exists(MODEL_PATH):
            model = joblib.load(MODEL_PATH)
            # vectorizer 등 전처리 과정이 필요할 수 있으나, 현재는 모델만 로드하는 구조로 작성
            # 실제 구현 시: vectorized_text = vectorizer.transform([log_text])
            # prediction = model.predict(vectorized_text)
            # probability = model.predict_proba(vectorized_text)
            # (임시) 모델 로드 성공 시뮬레이션 (전처리 로직 부재로 인한 더미)
            pass 
    except Exception as e:
        # 모델 로딩 에러 발생 시 로그 출력 (실제 운영 시에는 file log 권장)
        print(f"DEBUG: 모델 로드 실패 - {str(e)}")

    # [임시] 2. 룰 기반 탐지 대용품
    # 간단한 SQL Injection, xss 패턴 탐지
    if re.search(r"SELECT", log_text, re.IGNORECASE):
        return DETECTION_RESULT_TEMPLATE(
            is_attack=True,
            confidence=0.95,
            type="SQL Injection",
            severity="critical",
            description="SQL SELECT 구문이 감지되었습니다. 데이터 유출 위협이 있습니다."
        )
    
    if "<script>" in log_text.lower():
         return DETECTION_RESULT_TEMPLATE(
            is_attack=True,
            confidence=0.90,
            type="XSS",
            severity="high",
            description="스크립트 태그가 감지되었습니다. XSS 공격 위협이 있습니다."
        )

    # 공격이 감지되지 않은 경우
    return DETECTION_RESULT_TEMPLATE(
        is_attack=False,
        confidence=0.10,
        type="Normal",
        description="특이 사항이 발견되지 않았습니다."
    )

def search_threat_tool(keyword: str) -> str:
    """
    Tavily API를 사용하여 최신 위협 정보를 검색하는 도구입니다.
    
    Args:
        keyword (str): 검색할 위협 키워드 (예: "SQL Injection", "CVE-2024-XXXX")
        
    Returns:
        str: 검색 결과 요약 텍스트
    """
    api_key = os.getenv("TAVILY_API_KEY")
    
    # TavilyClient가 없을때
    if not api_key or not TavilyClient:
        return f"키워드: {keyword}\n(API 키가 없거나 라이브러리가 설치되지 않아 시뮬레이션 결과를 반환했습니다.)"

    try:
        # 실제 Tavily API 호출
        client = TavilyClient(api_key=api_key)
        # QnA -> 일반 search로 바꿈(api 키 무료 돈이 부족할시 채림님도 하나 만들어 주셔야할듯)
        response = client.search(
            query=f"web security threat '{keyword}' trends CVE mitigation", 
            search_depth="advanced",
            max_results=3
        )
        
        results = response.get("results", [])
        formatted_result = f"### '{keyword}' 관련 최신 보안 트렌드 검색 결과\n"
        
        for i, res in enumerate(results, 1):
            formatted_result += f"\n**{i}. {res.get('title')}**\n"
            formatted_result += f"- **URL**: {res.get('url')}\n"
            formatted_result += f"- **내용**: {res.get('content')[:300]}...\n"
            
        return formatted_result

    except Exception as e:
        return f"[Tavily Search Error] 검색 중 오류 발생: {str(e)}"

# 헬퍼 함수: 결과 딕셔너리 생성 편의
def DETECTION_RESULT_TEMPLATE(is_attack, confidence, type, severity="low", description=""):
    return DetectionResult(
        is_attack=is_attack,
        confidence=confidence,
        type=type,
        severity=severity,
        description=description,
        timestamp=datetime.now().isoformat()
    ).model_dump()
