import re
from typing import Optional
from .schemas import ParsedLog

class LogParser:
    """
    사용자가 입력한 raw 웹 로그를 구조화된 데이터로 변환하는 클래스입니다.
    피드백3.ipynb 규격을 따라서 만들었습니다.
    """
    def __init__(self):
        # 표준 Apache/Nginx Combined 로그 형식을 기반으로 한 정규식입니다.
        # IP - - [Time] "Method URL Proto" Status Length "Referer" "User-Agent"
        self.log_pattern = re.compile(
            r'(?P<ip>\S+) - - \[(?P<time>.*?)\] '
            r'"(?P<method>\S+) (?P<url>\S+) (?P<proto>\S+)" '
            r'(?P<status>\d+) (?P<length>\d+|-) '
            r'"(?P<referer>.*?)" "(?P<user_agent>.*?)"'
        )

    def parse_line(self, raw_log: str) -> Optional[ParsedLog]:
        """
        한 줄의 로그 문자열을 읽어 ParsedLog 객체를 반환합니다.
        파싱에 실패할 경우 None을 반환합니다.
        """
        line = raw_log.strip()
        if not line:
            return None

        match = self.log_pattern.search(line)
        if not match:
            # 정규식에 맞지 않는 로그일 경우 예외 처리나 로그를 남길 수 있습니다.
            return None

        data = match.groupdict()

        # 데이터 팀이 정의한 컬럼명(COLS)과 일치시켜 매핑합니다.
        return ParsedLog(
            timestamp=data['time'],
            src_ip=data['ip'],
            request_http_method=data['method'],
            request_http_request=data['url'],
            request_http_protocol=data['proto'],
            request_user_agent=data['user_agent'],
            response_http_status_code=int(data['status']),
            response_content_length=int(data['length']) if data['length'] != '-' else 0
        )