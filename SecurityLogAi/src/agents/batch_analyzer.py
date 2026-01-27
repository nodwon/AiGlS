import json
from collections import Counter

def run_batch_analysis(log_content: str) -> dict:
    """
    대량의 로그를 Python 코드로 직접 순회하며 분석합니다.
    LLM을 타지 않으므로 속도가 빠르고 누락이 없습니다.
    
    Args:
        log_content: 로그 파일 전체 텍스트
        
    Returns:
        dict: {
            "total_count": int,
            "attack_count": int,
            "normal_count": int,
            "attack_details": list[dict], # 공격으로 판정된 로그들의 상세 정보
            "stats": dict # 유형별 카운트
        }
    """
    # [수정] Circular Import 방지를 위해 함수 내부에서 import 수행
    from src.agents.tools import ml_detect_tool, regex_detect_tool

    lines = log_content.strip().splitlines()
    total = len(lines)
    
    attack_details = []
    stats = Counter()
    
    for line in lines:
        if not line.strip():
            continue
            
        # 1. ML 분석 실행
        ml_result_str = ml_detect_tool(line)
        # 2. 정규식 분석 실행
        regex_result_str = regex_detect_tool(line)
        
        # JSON 파싱 (도구가 문자열로 리턴하므로 다시 딕셔너리로 변환)
        try:
            # 큰따옴표 문제 등이 있을 수 있으므로 eval 대신 json.loads 노력...
            # 하지만 tools.py가 str(dict)를 리턴하므로 ast.literal_eval이 안전함
            import ast
            ml_data = ast.literal_eval(ml_result_str) if "{" in ml_result_str else {}
            regex_data = ast.literal_eval(regex_result_str) if "{" in regex_result_str else {}
        except:
            continue

        # 3. Sentinel 로직 구현 (Code-Level Double Check)
        is_regex_attack = regex_data.get("is_attack", False)
        regex_type = regex_data.get("type", "None")
        
        is_ml_attack = ml_data.get("is_attack", False)
        ml_type = str(ml_data.get("type", "Normal"))
        ml_conf = ml_data.get("confidence", 0.0)
        
        # [오탐 튜닝] ML 임계값 적용
        ml_threshold = 0.8
        
        # [사용자 요청] 오탐이 심한 특정 유형들은 ML 결과에서 제외 (정규식만 인정)
        excluded_ml_types = [
            "Dictionary", 
            "HTTP Response Splitting", 
            "Input Data Manipulation", 
            "Protocol Manipulation"
        ]
        
        # 대소문자 무시하고 포함 여부 확인
        is_excluded = any(ex_type.lower() in ml_type.lower() for ex_type in excluded_ml_types)
        
        if is_excluded:
             is_ml_valid = False
        else:
             is_ml_valid = is_ml_attack and (ml_conf >= ml_threshold)
        
        # 최종 판정: Regex가 잡거나, ML이 확신하면 공격
        final_verdict = is_regex_attack or is_ml_valid
        
        if final_verdict:
            # 최종 공격 유형 결정 (Regex 우선)
            final_display_type = regex_type if is_regex_attack else ml_type
            
            stats[final_display_type] += 1
            attack_details.append({
                "timestamp": ml_data.get("timestamp"),
                "ip": ml_data.get("source"),
                "final_type": final_display_type,
                "ml_type": ml_type,            # ML이 본 공격 유형
                "ml_confidence": ml_conf,      # ML 신뢰도
                "regex_detected": is_regex_attack, # 정규식 탐지 여부
                "regex_type": regex_type,      # 정규식 탐지 유형
                "target": ml_data.get("target"),
                "raw_log": line
            })
            
    return {
        "total_count": total,
        "attack_count": len(attack_details),
        "normal_count": total - len(attack_details),
        "attack_details": attack_details,
        "stats": dict(stats)
    }
