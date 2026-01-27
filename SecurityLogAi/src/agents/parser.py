import re
import math
import urllib.parse
from datetime import datetime
from collections import defaultdict, deque

# ==========================================
# 로그 포맷 정규식 정의 (내 입맛대로 수정 가능)
# ==========================================

class LogPatterns:
    # 1. Combined / Common Log Format
    # 가장 흔한 아파치/Nginx 스타일. IP, 날짜, 요청내용, 상태코드, 사이즈, 리퍼러, 유저에이전트 순서임.
    COMBINED = re.compile(
        r'(?P<ip>[\d\.:]+)\s+\S+\s+\S+\s+\[(?P<timestamp>.*?)\]\s+"(?P<method>\S+)\s+(?P<url>.*?)\s+(?P<protocol>.*?)"\s+(?P<status>\d+)\s+(?P<bytes>\S+)(?:\s+"(?P<referer>.*?)"\s+"(?P<user_agent>.*?)")?'
    )
    
    # 2. AWS ALB 및 기타 포맷
    # 클라우드 환경 로드밸런서 로그 대응용. 앞에 타입이랑 타임스탬프가 먼저 나옴.
    # 복잡해 보이지만 결국 중요한 건 IP, 요청 URL, User-Agent임.
    AWS_ALB = re.compile(
        r'(?P<type>\S+)\s+(?P<timestamp>\S+)\s+(?P<elb>\S+)\s+(?P<ip>[\d\.:]+):\d+\s+\S+\s+\S+\s+\S+\s+\S+\s+(?P<status>\d+)\s+\S+\s+\S+\s+\S+\s+"(?P<method>\S+)\s+(?P<url>.*?)\s+(?P<protocol>.*?)"\s+"(?P<user_agent>.*?)"'
    )

# ==========================================
# 전역 상태 관리 (시계열 피쳐용)
# ==========================================
# IP별로 최근 언제 접속했는지 기록해두는 메모장.
# 이걸로 '짧은 시간에 너무 많이 요청했나?(DDoS)' 같은 거 판단함.
# 최대 10,000개 IP까지만 기억하고(메모리 절약), 각 IP당 접속 시간 기록.
_IP_ACCESS_HISTORY = defaultdict(lambda: deque(maxlen=10000))

def parse_log_line(line: str) -> dict:
    """
    로그 한 줄을 읽어서 깔끔한 딕셔너리로 만듦.
    정규식으로 시도해보고, 안 되면 억지로라도(Heuristic) 뜯어냄.
    """
    line = line.strip()
    result = {
        "raw": line, 
        "ip": None, "timestamp": None, "timestamp_dt": None,
        "method": None, "url": None, "protocol": None, 
        "status": 0, "bytes": 0, 
        "user_agent": "", "decoded_url": ""
    }

    # 1. 정규식 매칭 시도 (Combined -> AWS 순서)
    match = None
    for p in [LogPatterns.COMBINED, LogPatterns.AWS_ALB]:
        m = p.search(line)
        if m:
            match = m
            break
            
    if match:
        # 매칭 성공하면 그룹별로 착착 넣기
        data = match.groupdict()
        result.update(data)
        
        # [수정] 정규식의 [\d\.:]+가 IPv4:Port 형태(1.2.3.4:12345)를 통째로 잡는 문제 해결
        # IPv4인데 콜론(:)이 있으면 포트로 간주하고 떼버림.
        if result['ip'] and '.' in result['ip'] and ':' in result['ip']:
            result['ip'] = result['ip'].split(':')[0]
    else:
        # [Fallback] 포맷이 이상해도 최대한 정보는 건진다 (깨진 로그 대응)
        # IP 주소 패턴 찾기
        ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
        if ip_match: result['ip'] = ip_match.group(1)
        
        # 대괄호 [] 안에 있는 건 보통 날짜 시간임
        time_match = re.search(r'\[(.*?)\]', line)
        if time_match: result['timestamp'] = time_match.group(1)
        
        # "GET /... HTTP/1.1" 패턴 찾기
        req_match = re.search(r'"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(.*?)\s+(.*?)"', line)
        if req_match:
            result['method'] = req_match.group(1)
            result['url'] = req_match.group(2)
            result['protocol'] = req_match.group(3)

        # 상태 코드 (3자리 숫자) 찾기
        status_match = re.search(r'\s([1-5]\d{2})\s', line)
        if status_match: result['status'] = status_match.group(1)
        
        # User-Agent는 보통 "Mozilla..." 로 시작하니까 그거 잡기
        ua_match = re.search(r'"(Mozilla.*?)"', line)
        if ua_match: result['user_agent'] = ua_match.group(1)

    # 2. 형변환 및 데이터 클렌징
    try:
        if result['status']: result['status'] = int(result['status'])
        # 바이트 수는 숫자인지 확인하고 변환 (가끔 '-' 들어올 때 있음)
        if result['bytes'] and str(result['bytes']).isdigit(): result['bytes'] = int(result['bytes'])
        else: result['bytes'] = 0
    except:
        pass # 에러 나면 그냥 0으로 둠

    # 3. URL 디코딩 (%20 같은 거 공백으로 변환)
    # 이걸 해줘야 공격 패턴(sql injection 등)을 제대로 잡음
    if result.get("url"):
        try:
            result["decoded_url"] = urllib.parse.unquote(result["url"])
        except:
            result["decoded_url"] = result["url"]
    else:
        result["decoded_url"] = ""

    # 4. 날짜/시간 파싱 (문자열 -> datetime 객체)
    # 시계열 분석하려면 날짜 객체가 필수임
    if result.get("timestamp"):
        try:
            # 기본 포맷: 12/Dec/2024:12:12:12 +0900
            ts_str = result['timestamp']
            # 타임존(+0900) 복잡하니까 날려버리고 파싱
            ts_str_clean = re.sub(r'\s+[+-]\d{4}', '', ts_str)
            result['timestamp_dt'] = datetime.strptime(ts_str_clean, '%d/%b/%Y:%H:%M:%S')
        except:
            # 예외: AWS 형태나 다른 포맷일 경우
            try:
                result['timestamp_dt'] = datetime.strptime(result['timestamp'], '%Y-%m-%dT%H:%M:%S.%fZ')
            except:
                result['timestamp_dt'] = datetime.now() # 정 안되면 현재 시간 박음

    if not result['timestamp_dt']:
        result['timestamp_dt'] = datetime.now()

    return result

def calculate_entropy(text):
    """
    문자열의 무작위성(엔트로피) 계산.
    랜덤한 문자열(예: df8237s...)은 수치가 높게 나옴 -> 공격 의심.
    """
    if not text:
        return 0
    entropy = 0
    t_len = len(text)
    for x in set(text):
        p_x = text.count(x) / t_len
        entropy += - p_x * math.log2(p_x)
    return entropy

def extract_features(parsed_data: dict) -> dict:
    """
    [핵심] 파싱된 로그에서 ML 모델이 좋아할 만한 44개 숫자를 뽑아냄.
    EDA 분석 때 썼던 로직 그대로 가져옴.
    """
    features = {}
    
    # 1. 기본 필드 수치화
    features['response_http_status_code'] = parsed_data.get('status', 0)
    features['response_content_length'] = parsed_data.get('bytes', 0)
    
    # Method랑 Protocol은 원래 One-Hot 해야되는데, 
    # 일단 값 그대로 넘겨서 나중에 처리하거나(Vectorizer) 모델이 알아서 하게 둠.
    features['request_http_method'] = parsed_data.get('method', 'UNKNOWN')
    features['request_http_protocol'] = parsed_data.get('protocol', 'UNKNOWN')
    
    user_agent = parsed_data.get('user_agent', '') or ""
    url = parsed_data.get('url', '') or ""
    decoded_url = parsed_data.get('decoded_url', '') or ""
    
    # 길이 자체가 힌트가 됨 (너무 긴 URL은 오버플로우 공격일 수도)
    features['ua_len'] = len(user_agent)
    features['url_len'] = len(url)
    
    # 2. 공격 패턴 정규식 검사 (있으면 1, 없으면 0)
    # 디코딩된 URL과 소문자 변환된 User-Agent로 검사해야 정확함
    url_lower = decoded_url.lower()
    ua_lower = user_agent.lower()
    
    # SQL 인젝션: union select, 주석(--) 등
    features['has_sqli'] = 1 if re.search(r'union|select|insert|update|delete|drop|declare|exec|--|#|/\*', url_lower) else 0
    # 경로 탐색(Directory Traversal): ../ 같은 거
    features['has_traversal'] = 1 if re.search(r'\.\./|\.\.\\|/etc/passwd|c:\\windows', url_lower) else 0
    # 커맨드 인젝션 및 스크립트 삽입 시도
    features['has_injection'] = 1 if re.search(r';|&&|\||`|\$|\(|\)|<|>', url_lower) else 0
    # 스캐너 도구 사용 흔적 (nmap, sqlmap 등)
    features['has_scan'] = 1 if re.search(r'nmap|nikto|wikto|sf|sqlmap|bsqlbf|w3af|acunetix|havij|appscan', ua_lower) else 0
    
    # 봇(Bot) 의심 단어
    features['ua_is_bot'] = 1 if re.search(r'bot|crawler|spider|slurp|monitor|curl|wget|python', ua_lower) else 0
    # User-Agent가 비어있으면 그것도 이상함
    features['ua_is_missing'] = 1 if not user_agent or user_agent == "-" else 0
    
    # URL 엔트로피: 암호화된 난수나 쉘코드가 들어있으면 수치가 팍 올라감
    features['url_entropy'] = calculate_entropy(url)
    
    # 특수문자 비율: 정상이면 낮고, 공격이면 높음
    special_chars = re.findall(r'[^a-zA-Z0-9]', url)
    features['url_special_ratio'] = len(special_chars) / len(url) if url else 0
    
    # 인코딩된 문자(%xx) 비율: 이중 인코딩 공격 등 탐지
    encoded_chars = re.findall(r'%[0-9a-fA-F]{2}', url)
    features['url_encoded_ratio'] = len(encoded_chars) / len(url) if url else 0

    # 3. User-Agent 분석 (OS 및 기기 추정)
    # 이걸 One-Hot Encoding한 것처럼 0/1로 쪼개둠
    features['os_Windows'] = 1 if 'windows' in ua_lower else 0
    features['os_Mac'] = 1 if 'mac os' in ua_lower or 'macintosh' in ua_lower else 0
    features['os_Linux'] = 1 if 'linux' in ua_lower else 0
    features['os_iOS'] = 1 if 'iphone' in ua_lower or 'ipad' in ua_lower else 0
    features['os_Android'] = 1 if 'android' in ua_lower else 0
    features['os_Other'] = 1 if sum([features['os_Windows'], features['os_Mac'], features['os_Linux'], features['os_iOS'], features['os_Android']]) == 0 else 0
    
    # [중요] ML 서비스에서 Fallback으로 쓸 OS 문자열도 넣어줌 (피처 리스트 매칭용)
    if features['os_Windows']: features['ua_os'] = 'Windows'
    elif features['os_Android']: features['ua_os'] = 'Android'
    elif features['os_iOS']: features['ua_os'] = 'iOS'
    elif features['os_Mac']: features['ua_os'] = 'Mac'
    elif features['os_Linux']: features['ua_os'] = 'Linux'
    else: features['ua_os'] = 'Other'

    # PC냐 모바일이냐
    features['dev_PC'] = 1 if not re.search(r'mobile|android|iphone|ipad', ua_lower) else 0
    # 얘도 문자열 넣어둠
    features['ua_device'] = "Mobile" if re.search(r'mobile|android|iphone|ipad', ua_lower) else "PC"

    # 4. 시계열(Time-series) 특성 계산
    # 이게 중요함. "5분 동안 몇 번 왔냐?" 같은 거.
    ip = parsed_data.get('ip')
    current_ts = parsed_data.get('timestamp_dt')
    
    features['req_interval'] = 0.0
    features['prev_5min_cnt'] = 0
    
    if ip and current_ts:
        history = _IP_ACCESS_HISTORY[ip]
        
        # 직전 요청이랑 시간 차이 (Interval) 계산
        if history:
            last_ts = history[-1]
            interval = (current_ts - last_ts).total_seconds()
            features['req_interval'] = interval if interval >= 0 else 0
        
        # 현재 접속 시간 추가
        history.append(current_ts)
        
        # 5분(300초) 지난 기록은 버림 (슬라이딩 윈도우)
        while history and (current_ts - history[0]).total_seconds() > 300:
            history.popleft()
            
        # 최근 5분간 접속 횟수
        features['prev_5min_cnt'] = len(history)

    return features
