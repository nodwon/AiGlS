from pydantic import BaseModel, Field
from typing import Optional

# ==========================================
# 데이터 통신 규격 (Schema) 정의
# 에이전트랑 ML 모델이 서로 엉뚱한 데이터 주고받지 않게 약속하는 문서임.
# ==========================================

# 1. 로그 파서 결과 규격 
class ParsedLog(BaseModel):
    """
    LogParser가 원본 로그를 읽고 뱉어낼 규격.
    이게 '피처 추출기'의 입력값이 됨.
    """
    timestamp: str = Field(..., description="원본 타임스탬프 (예: 12/Dec/...)")
    src_ip: str = Field(..., description="출발지 IP")
    request_http_method: str = Field(..., description="GET, POST 등 메소드")
    request_http_request: str = Field(..., description="요청 URL/경로")
    request_http_protocol: str = Field(..., description="HTTP 프로토콜 버전")
    request_user_agent: str = Field(..., description="브라우저/기기 정보 (User-Agent)")
    response_http_status_code: int = Field(..., description="응답 상태 코드 (200, 404 등)")
    response_content_length: int = Field(0, description="응답 데이터 크기 (바이트)")


# 2. ML 모델 입력 피처 규격 (44개)
class MLInputFeatures(BaseModel):
    """
    EDA 팀이랑 맞춘 최종 44개 피처 리스트.
    이거 하나라도 틀리면 모델이 에러 뿜으니까 건드리지 말 것.
    """
    # [1-16] 네트워크 및 프로토콜 정보
    src_port: int = 0
    dst_port: int = 0
    request_http_method: str = "GET"
    request_http_protocol: str = "HTTP/1.1"
    request_origin: str = ""
    request_cookie: str = ""
    request_content_type: str = ""
    request_accept: str = ""
    request_accept_language: str = ""
    request_accept_encoding: str = ""
    request_do_not_track: str = ""
    request_connection: str = ""
    request_body: str = ""
    response_http_protocol: str = "HTTP/1.1"
    response_http_status_code: int = 200
    response_content_length: int = 0

    # [17-28] 텍스트 길이, 상태 코드 및 기초 패턴
    url_len: int
    ua_len: int
    is_4xx: int
    is_5xx: int
    is_auth_fail: int
    has_sqli: int
    has_traversal: int
    has_cmdi: int
    has_admin: int
    url_entropy: float
    url_special_ratio: float
    url_encoded_ratio: float

    # [29-40] 시계열 통계 및 윈도우(5분) 집계 (DDoS 탐지용)
    req_interval_s: float
    req_cnt_w: int
    cnt_4xx_w: int
    cnt_5xx_w: int
    cnt_auth_fail_w: int
    rate_4xx_w: float
    rate_5xx_w: float
    rate_auth_fail_w: float
    url_entropy_mean_w: float
    url_entropy_max_w: float
    url_special_mean_w: float
    url_special_max_w: float

    # [41-44] User-Agent 지능형 분류
    ua_is_bot: int
    ua_is_missing: int
    ua_os: str     # 'Windows', 'Linux', 'Mac' 등
    ua_device: str # 'PC', 'Mobile'


# 3. 최종 분석 결과 규격 (Output)
class DetectionResult(BaseModel):
    """
    모든 분석(ML + Regex)이 끝나고 에이전트가 리포트에 쓸 최종 성적표.
    """
    is_attack: bool = Field(..., description="공격 여부 (True/False)")
    confidence: float = Field(..., description="AI의 확신도 (0.0 ~ 1.0)")
    type: str = Field(..., description="공격 유형 (예: SQL Injection, Normal)")
    severity: str | None = Field(None, description="심각도 (Low ~ Critical)")
    
    target: str | None = Field(None, description="공격 당한 URL")
    source: str | None = Field(None, description="공격자 IP")
    timestamp: str | None = Field(None, description="분석 시간")
    
    description: str | None = Field(None, description="상세 설명 로그")
    recommendation: str | None = Field(None, description="보안 담당자에게 추천하는 조치")
