# agents/tools.py
# 나중에 여기에 ML 모델 로드 코드, 웹검색 코드들 넣으면 좋아좋아잉

def detect_attack_tool(log_text: str) -> dict:
    """
    가짜 로그 공격 탐지 함수
    """
    # 지금은 테스트용
    if "SELECT" in log_text.upper():
        return {"is_attack": True, "confidence": 0.99, "type": "SQL Injection"}
    return {"is_attack": False, "confidence": 0.1, "type": "Normal"}

def search_threat_tool(keyword: str) -> str:
    """
    임시 위협 정보 검색 함수
    """
    return f"[검색 결과] {keyword}는 매우 위험한 공격입니다. 님 서버는 망했습니다.."
