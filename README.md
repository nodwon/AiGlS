##  셜log
### 2.Introduction

AI를 활용한 로그 탐지 및  대응 방안

사용 흐름

1. 사용자가 로그 파일 업로드
2. AI 에이전트가 로그 요약
3. 이상 징후 판단 (ex. Brute Force,, Port Scanning, DDoS 등등등…)
4. 자연어로 위험 원인 설명
5. 대응 가이드 제공

ex)

Q. 이 로그에서 문제되는 부분 알려줘!

A. SSH 로그인 실패가 5분간 200회 발생 → Brute Force 의심

IP: 192.168.x.x

권장 조치:

- Fail2Ban 적용
- 해당 IP 차단

### 3.git 

C : CREATE 새로운 파일 입력할때
R : csv 파일이나 데이터 파일 읽어오는 파일 표시
U : update 파일 제작 
D : 삭제 디렉토리나 파일 표시
