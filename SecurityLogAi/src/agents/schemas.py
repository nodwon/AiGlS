from pydantic import BaseModel, Field
from typing import Optional


#1. 에이전트 -> ML 모델 전달 규격 (INPUT)


#1. ML 분석 결과 규격 (ML->Agent)
## 예시임 추후 ml팀과 상의해 변경예정
class DetectionResult(BaseModel):
    is_attack: bool = Field(..., description="공격 여부")
    confidence: float = Field(..., description="신뢰도 (0~1)")
    type: str = Field(..., description="탐지된 공격 유형")
    severity: str | None = Field(None, description="심각도 (low, medium, high, critical)")
    target: str | None = Field(None, description="공격 대상")
    source: str | None = Field(None, description="공격 소스")
    timestamp: str | None = Field(None, description="발생 시간")
    description: str | None = Field(None, description="상세 설명")
    recommendation: str | None = Field(None, description="권장 조치")



from pydantic import BaseModel, Field
from typing import Optional, Dict

# 1. 로그 파서 결과 규격 
class ParsedLog(BaseModel):
    """

    LogParser가 원본 로그를 읽고 뱉어낼 규격임.
    '피처 추출 패키지'에 입력값으로 던져줄 표준 규격
    
    """
    timestamp: str = Field(..., description="원본 타임스탬프 ")
    src_ip: str = Field(..., description="출발지 IP")
    request_http_method: str = Field(..., description="GET, POST 등")
    request_http_request: str = Field(..., description="요청 URL/경로")
    request_http_protocol: str = Field(..., description="HTTP/1.1 등")
    request_user_agent: str = Field(..., description="User-Agent 헤더")
    response_http_status_code: int = Field(..., description="상태 코드")
    response_content_length: int = Field(0, description="응답 길이")

# 2. 에이전트 -> ML 모델 전달 규격 (INPUT)
class MLInputFeatures(BaseModel):
    """
   
    피드백3.ipynb에서 확정한 최종 44개 피처 리스트입니다.
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

    # [29-40] 시계열 통계 및 윈도우(5분) 집계
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

# 3. ML 분석 결과 규격 (ML -> Agent)
class DetectionResult(BaseModel):
    """ XGBoost 모델이 최종 판정한 보안 리포트 규격"""
    is_attack: bool = Field(..., description="공격 여부")
    confidence: float = Field(..., description="신뢰도 (0~1)")
    type: str = Field(..., description="탐지된 공격 유형 (예: SQL Injection)")
    severity: str | None = Field(None, description="심각도 (low, medium, high, critical)")
    target: str | None = Field(None, description="공격 대상 시스템")
    source: str | None = Field(None, description="공격자 IP")
    timestamp: str | None = Field(None, description="분석 시각")
    description: str | None = Field(None, description="상세 분석 내용")
    recommendation: str | None = Field(None, description="권장 보안 조치")