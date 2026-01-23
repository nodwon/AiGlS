from pydantic import BaseModel, Field

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
