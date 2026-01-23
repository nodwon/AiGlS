# agents/tools.py
import os
import joblib
import re
from src.agents.schemas import DetectionResult

# 모델 파일 경로 설정 (상대 경로로 설정하여 유연성 확보)
MODEL_PATH = os.path.join(os.path.dirname(__file__), "../../model/random_forest.pkl")

def detect_attack_tool(log_text: str) -> dict:
    """
    로그 텍스트를 분석하여 공격 여부를 탐지하는 도구입니다.
    
    기능:
    1. 저장된 ML 모델(random_forest.pkl)을 로드하여 예측을 시도합니다.
    2. 모델이 없거나 로드 실패 시, 정규표현식(Regex) 기반의 룰셋으로 폴백(Fallback) 처리합니다.
    
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
            # print("DEBUG: ML 모델 로드 성공")
            pass 
    except Exception as e:
        # 모델 로딩 에러 발생 시 로그 출력 (실제 운영 시에는 file log 권장)
        print(f"DEBUG: 모델 로드 실패 - {str(e)}")

    # 2. 룰 기반 탐지 (Fallback Logic)
    # 간단한 SQL Injection 패턴 탐지 (예: SELECT 문 포함 여부)
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
    Tavily API 등을 사용하여 최신 위협 정보를 검색하는 도구입니다. (현재는 시뮬레이션)
    
    Args:
        keyword (str): 검색할 위협 키워드 (예: "SQL Injection", "CVE-2024-XXXX")
        
    Returns:
        str: 검색 결과 요약 텍스트
    """
    api_key = os.getenv("TAVILY_API_KEY")
    
    # API 키가 있으면 실제 검색 (나중에 구현), 없으면 시뮬레이션 결과 반환
    if not api_key:
        # 시뮬레이션 응답
        return f"""
[검색 결과 시뮬레이션]
키워드: "{keyword}"
1. {keyword}는(은) 웹 애플리케이션 보안 취약점 중 하나입니다.
2. 최근 24시간 내 관련된 주요 침해 사고 사례는 보고되지 않았습니다.
3. 대응 방안: 입력값 검증 강화 및 최신 보안 패치 적용을 권장합니다.
(API 키가 설정되지 않아 더미 데이터를 반환했습니다.)
"""

    return f"[Tavily Search] '{keyword}'에 대한 검색 결과를 반환합니다. (API 연동 필요)"

# 헬퍼 함수: 결과 딕셔너리 생성 편의를 위함
def DETECTION_RESULT_TEMPLATE(is_attack, confidence, type, severity="low", description=""):
    return DetectionResult(
        is_attack=is_attack,
        confidence=confidence,
        type=type,
        severity=severity,
        description=description,
        timestamp="NOW" # 실제 구현 시 datetime.now() 사용
    ).model_dump()
