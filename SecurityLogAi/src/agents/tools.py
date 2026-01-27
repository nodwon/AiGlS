# agents/tools.py
import os
import joblib
import re
import json
from datetime import datetime
from src.agents.schemas import DetectionResult
from src.agents.model.ml_service import ModelHandler
from src.agents.parser import parse_log_line, extract_features
from src.agents.batch_analyzer import run_batch_analysis

# Tavily 검색 라이브러리 (없으면 시뮬레이션 모드)
try:
    from tavily import TavilyClient
except ImportError:
    TavilyClient = None

# ==========================================
# [중요] 전역 핸들러 초기화
# ==========================================
# 툴이 호출될 때마다 모델 로드하면 느려 터짐. 그래서 여기서 한 번 로드해두고 계속 씀.
# Singleton 패턴 비스무리한 거임.
model_handler = ModelHandler()

# 헬퍼 함수: 결과 딕셔너리 포맷팅
def DETECTION_RESULT_TEMPLATE(is_attack, confidence, type, severity="low", description="", target="", source="", timestamp=None):
    # 타임스탬프 없으면 현재 시간
    ts = timestamp if timestamp else datetime.now().isoformat()
    
    return DetectionResult(
        is_attack=is_attack,
        confidence=confidence,
        type=type,
        severity=severity,
        target=str(target),
        source=str(source), # 필드 추가
        description=description,
        timestamp=ts
    ).model_dump()

# ==========================================
# 도구 정의 (Agent가 갖다 쓰는 함수들)
# ==========================================

def ml_detect_tool(log_line: str) -> str:
    """
    [1단계 핵심 도구] ML 모델(XGBoost)을 써서 로그가 공격인지 아닌지 판단함.
    Sentinel 에이전트가 제일 먼저 이 툴을 사용함.
    
    Args:
        log_line: 분석할 로그 한 줄 문자열
    Returns:
        JSON 형태의 문자열 (공격 여부, 확신도, 공격 유형 등)
    """
    # 모델 로드 실패했으면 못 쓴다고 솔직하게 말함
    if not model_handler.model:
        return "Model Not Loaded (Skip)"

    # 1. 로그 한 줄을 씹고 뜯고 맛보고 즐기고 (파싱 + 피처 추출)
    # 기계가 이해할 수 있는 숫자들(Features)로 변환하는 과정
    parsed = parse_log_line(log_line)
    features = extract_features(parsed)
    
    if not features:
         return "Feature Extraction Failed"

    # 2. 모델한테 물어봄 ("이거 공격이야?")
    # model_handler.predict 내부에서 피처 정렬 같은 거 다 해줌
    try:
        attack_type, confidence = model_handler.predict(features)
        
        # 3. 결과 정리
        # [수정] 오탐 방지를 위해 임계값 0.8로 상향 조정
        is_attack = (str(attack_type).lower() != "normal") and (confidence >= 0.8)
        
        # 리포트에 쓸 부가 정보들 (어떤 URL을 건드렸는지, 누가 그랬는지)
        target_info = parsed.get("decoded_url") if parsed.get("decoded_url") else parsed.get("url")
        source_ip = parsed.get("ip")
        
        # 예쁘게 포장해서 리턴
        result_dict = DETECTION_RESULT_TEMPLATE(
            is_attack=True if is_attack else False,
            confidence=float(confidence),
            type=str(attack_type) if is_attack else "Normal", # 공격 아니면 Type은 Normal
            severity="high" if confidence > 0.8 else "medium", # 확신도 높으면 심각함
            target=target_info,
            source=source_ip,
            timestamp=parsed.get('timestamp'), # 로그 상의 시간 전달
            description=f"ML Model Prediction (UserAgent: {parsed.get('user_agent')})"
        )
        return str(result_dict)

    except Exception as e:
        return f"[ML Error] {str(e)}"

def regex_detect_tool(log_line: str) -> str:
    """
    [2단계 보조 도구] 정규식(Regex)으로 뻔한 공격 패턴을 잡아냄.
    ML 모델이 애매하다고 할 때(confidence 0.3 ~ 0.5) 사람 눈 대신 확인하는 용도.
    """
    # =========================================================
    # [3.0] 강화된 정규식 패턴 모음 (Hybrid Detection용)
    # ML 모델이 놓치는 공격을 잡기 위해 패턴을 대폭 보강함.
    # =========================================================
    ATTACK_PATTERNS = {
        "SQL Injection": [
            r"(?i)union\s+select", r"(?i)select\s+.*\s+from", r"(?i)insert\s+into",
            r"(?i)update\s+.*set", r"(?i)delete\s+from", r"(?i)drop\s+table",
            r"(?i)exec\(\s*", r"--", r"(?i)or\s+'?1'?='?1", r"\bOR\b\s+\d+=\d+",
            r"'\s+OR\s+'", r"\"\s+OR\s+\"", r"(?i)sleep\(", r"(?i)benchmark\(", 
            r"(?i)waitfor\s+delay"
        ],
        "XSS (Cross-Site Scripting)": [
            r"(?i)<script>", r"(?i)javascript:", r"(?i)on\w+\s*=", 
            r"(?i)alert\(", r"(?i)document\.cookie", r"(?i)onerror", r"(?i)onload",
            r"(?i)eval\(", r"(?i)<img\s+src", r"(?i)iframe\s+src"
        ],
        "Path Traversal & LFI": [
            r"\.\./", r"\.\.\\", r"/etc/passwd", r"c:\\windows\\system32",
            r"(?i)boot\.ini", r"(?i)win\.ini", r"(?i)/proc/self/environ"
        ],
        "Command Injection": [
            r";\s*\/bin\/sh", r";\s*cmd\.exe", r"\|\s*ls", r"\|\s*id",
            r"&&\s*cat", r"`.*`", r"\$\(.*\)", r"(?i)whoami", r"(?i)net\s+user"
        ],
        "Code Injection": [
             r"(?i)eval\(", r"(?i)base64_decode", r"(?i)system\(", r"(?i)passthru\(",
             r"(?i)popen\(", r"(?i)proc_open\(", r"(?i)pcntl_exec"
        ],
        "Input Data Manipulation": [
            r"%00", r"(?i)0x[0-9a-f]+", r"(?i)null", r"[<>]" # Null Byte, Hex, Suspicious chars
        ],
        "HTTP Verb Tampering": [
            r"(?i)PUT", r"(?i)DELETE", r"(?i)TRACE", r"(?i)CONNECT", r"(?i)OPTIONS" 
            # 일반적인 GET/POST 외의 메소드가 로그에 찍히면 의심 (상황에 따라 다름)
        ],
        "HTTP Request Smuggling": [
             r"(?i)Content-Length:.*Content-Length:", 
             r"(?i)Transfer-Encoding:.*chunked.*Content-Length:",
             r"(?i)Transfer-Encoding:.*chunked"
        ],
        "Scanning for Vulnerable Software": [
            r"(?i)sqlmap", r"(?i)nikto", r"(?i)nmap", r"(?i)metasploit",
            r"(?i)acunetix", r"(?i)havij", r"(?i)burp", r"(?i)dirbuster",
            r"(?i)nessus", r"(?i)netsparker"
        ],
        "Fake the Source of Data": [
             r"(?i)X-Forwarded-For:.*127\.0\.0\.1",
             r"(?i)Client-IP:.*127\.0\.0\.1",
             r"(?i)Referer:.*google\.com" # 단순 예시, Spoofing 패턴
        ]
    }
    
    # 분석 시작
    parsed = parse_log_line(log_line)
    
    # [수정] 룰 기반은 강력해야 하므로, 파싱된 필드만 보는 게 아니라
    # '로그 원본 전체' + '디코딩된 URL'을 모두 합쳐서 검사합니다.
    # 이렇게 하면 파서가 놓친 부분이나 헤더에 숨겨진 공격도 다 잡습니다.
    target_str = f"{parsed.get('raw', '')} {parsed.get('decoded_url', '')}"
    
    detected_attacks = []
    
    # 패턴 매칭 루프
    for attack_name, patterns in ATTACK_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, target_str):
                detected_attacks.append(attack_name)
                break # 해당 유형에서 하나 발견되면 다음 유형으로 넘어감 (중복 카운트 방지)

    # 결과 리턴
    if detected_attacks:
        return str(DETECTION_RESULT_TEMPLATE(
            is_attack=True,
            confidence=1.0, # 룰에 걸리면 빼박 100% 공격임
            type=", ".join(detected_attacks),
            severity="high",
            target=target_str[:100], # 너무 길면 자름
            source=parsed.get("ip"),
            timestamp=parsed.get('timestamp'), # 로그 상의 시간
            description=f"Rule Matched: {detected_attacks}"
        ))
    else:
        return str(DETECTION_RESULT_TEMPLATE(
            is_attack=False,
            confidence=0.0,
            type="Normal",
            timestamp=parsed.get('timestamp'),
            description="No known rule pattern matched"
        ))

def search_threat_tool(keyword: str) -> str:
    """
    [분석가용] Tavily API 써서 인터넷 검색함.
    "요즘 유행하는 SQLi 패턴" 같은 거 찾아서 보고서에 풍성하게 내용을 채워줌.
    """
    api_key = os.getenv("TAVILY_API_KEY")
    
    # API 키 없으면 시뮬레이션 (돈 아까우니까..)
    if not api_key or not TavilyClient:
        return f"키워드: {keyword}\n(API 키가 없거나 라이브러리가 설치되지 않아 시뮬레이션 결과를 반환했습니다.)"

    try:
        # 실제 검색 수행
        client = TavilyClient(api_key=api_key)
        # 꿀팁: QnA 모드보다 그냥 일반 검색해서 요약하는 게 더 정확함
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
        return f"[Tavily Search Error] 검색하다 터짐: {str(e)}"

def batch_analysis_tool(file_path: str) -> str:
    """
    [대용량 로그 전용 도구]
    Sentinel이 파일 경로를 받아서 전체 로그를 일괄 분석할 때 사용합니다.
    천 개, 만 개의 로그도 빠르게 처리하여 요약 통계를 반환합니다.
    """
    if not os.path.exists(file_path):
        return f"Error: 파일을 찾을 수 없습니다. 경로: {file_path}"
        
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            log_content = f.read()
            
        # 순수 파이썬 엔진으로 분석 실행 (tools.py가 아니라 batch_analyzer.py에 있음)
        result = run_batch_analysis(log_content)
        
        # [변경] LLM이 표를 그리면 자꾸 할루시네이션이 생겨서, 아예 CSV 파일로 저장해버림.
        # 사용자가 다운로드 받거나 직접 열어볼 수 있게 함.
        import csv
        
        # 저장 경로: Streamlit이 접근 가능한 temp_logs 폴더 (src/agents 하위로 이동)
        csv_path = os.path.abspath("SecurityLogAi/src/agents/temp_logs/analysis_report.csv")
        os.makedirs(os.path.dirname(csv_path), exist_ok=True)
        
        # [정렬 로직] 양쪽 다 탐지된(Double Checked) 건을 최우선으로
        sorted_details = sorted(
            result['attack_details'], 
            key=lambda x: (x['regex_detected'], x['ml_confidence']), 
            reverse=True
        )
        
        try:
            with open(csv_path, 'w', newline='', encoding='utf-8-sig') as csvfile:
                fieldnames = ['Timestamp', 'IP', 'Attack Type', 'ML Score', 'Regex Detected', 'Target Payload', 'Raw Log']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                
                writer.writeheader()
                for detail in sorted_details:
                    writer.writerow({
                        'Timestamp': detail['timestamp'],
                        'IP': detail['ip'],
                        'Attack Type': detail['final_type'],
                        'ML Score': f"{detail['ml_confidence']:.4f}",
                        'Regex Detected': "TRUE" if detail['regex_detected'] else "FALSE",
                        'Target Payload': detail['target'],
                        'Raw Log': detail['raw_log']
                    })
        except Exception as e:
            return f"[Error] CSV 저장 실패: {str(e)}"
            
        # [추가] 공격자 IP 빈도 분석 (Top Attacker)
        attacker_ips = [d['ip'] for d in result['attack_details']]
        from collections import Counter
        ip_counts = Counter(attacker_ips).most_common(10)
        
        top_ips_str = ""
        for ip, count in ip_counts:
            top_ips_str += f"- **{ip}** ({count} attacks) -> Immediate Block Recommended 🚫\n"
            
        # [Context 확장] LLM이 구체적인 조언(코드 수정 등)을 할 수 있도록,
        # 각 공격 유형별로 '실제 페이로드 샘플'을 3개씩 뽑아서 보여줌.
        payload_samples = {}
        for detail in result['attack_details']:
            atype = detail['final_type']
            if atype not in payload_samples:
                payload_samples[atype] = set()
            # 너무 긴 페이로드는 자름 (토큰 절약)
            if len(payload_samples[atype]) < 3:
                payload_samples[atype].add(detail['target'][:200])
                
        # [Python-side Statistics Injection]
        # LLM에게 통계 계산을 맡기지 않고, Python이 미리 다 만든 텍스트를 주입함.
        stats_block = """
### 1. Attack Statistics (By Type)
"""
        if result['stats']:
            for k, v in result['stats'].items():
                stats_block += f"- **{k}**: {v} detections\n"
        else:
            stats_block += "- **Normal**: No specific attacks detected.\n"
            
        stats_block += """
### 2. Top 10 Attacker IPs
"""
        if top_ips_str:
            stats_block += top_ips_str
        else:
            stats_block += "- No attackers found.\n"
            
        # LLM에게 전달할 최종 요약본
        summary = f"""
[Analysis Complete]
- **Saved Report**: `{csv_path}` (CSV File Generated)
- **Total Logs**: {result['total_count']}
- **Attacks Found**: {result['attack_count']}

[STATISTICS_DATA]
{stats_block}
[/STATISTICS_DATA]

[Attack Details & Payloads (For Action Plan)]
"""
        for k, v in result['stats'].items():
            summary += f"### {k}: {v} detected\n"
            if k in payload_samples:
                for sample in payload_samples[k]:
                    summary += f"  - Sample: `{sample}`\n"
            summary += "\n"
            
        summary += "\n(Details Saved to CSV. Use [STATISTICS_DATA] section for the final report.)"
            
        return summary

    except Exception as e:
        return f"[Batch Analysis Error] 분석 중 오류 발생: {str(e)}"
