# 테스트 스크립트 작성
test_logs = [
    "SELECT * FROM users WHERE id=1",  # SQL Injection
    "<script>alert('xss')</script>",   # XSS
    "GET /index.html 200",             # Normal
]