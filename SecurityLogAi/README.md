# 🕵️‍♂️ 셜log (Sherlog): AI Agent-Based Security Log Analysis

> **"로그 속의 범인을 찾아내는 지능형 보안 파트너, 셜log"** > 서버 및 웹 로그를 분석하여 침해 징후를 탐지하고, 보안 비전문가도 즉시 대응할 수 있는 가이드를 제공합니다.

---

## 📖 1. Introduction
최근 서버 환경의 보안 위협(Brute Force, DDoS 등)은 방대한 로그를 남기지만, 이를 직접 분석하기에는 많은 시간과 전문 지식이 필요합니다. **셜log**는 OpenAI 에이전트 API를 활용해 복잡한 로그 데이터 사이의 '맥락'을 읽고, 실무적인 대응 방안을 자연어로 제안합니다.

### 🎯 주요 목표
- **자동화**: 방대한 로그 데이터의 실시간 보안 이상 징후 탐지
- **대중화**: 보안 비전문가도 이해할 수 있는 자연어 리포트 생성
- **실무화**: 탐지된 위협에 대한 즉각적인 대응(Action Plan) 가이드 제공

---

## ⚙️ 2. System Workflow
셜log는 다음과 같은 프로세스로 보안 위협에 대응합니다.



1. **Upload**: 사용자가 서버/네트워크 원본 로그 파일 업로드
2. **Summary**: AI 에이전트가 로그의 전체적인 패턴과 핵심 정보 요약
3. **Detection**: 이상 징후 판단 (Brute Force, Port Scanning, DDoS, SQL Injection 등)
4. **Analysis**: 공격의 원인 및 위험도를 자연어로 설명
5. **Guidance**: 차단 명령어 제공 및 보안 설정 변경 가이드 제시

---

## 💬 3. Analysis Example
**Q. 이 로그에서 문제되는 부분 알려줘!**

**A. 셜log 분석 결과:**
- **🚨 탐지 위협**: SSH Brute Force (무차별 대입 공격) 의심
- **🔍 근거**: 최근 5분간 특정 IP(`192.168.x.x`)에서 200회 이상의 로그인 실패 발생
- **🛡️ 권장 조치**:
  - `Fail2Ban` 적용을 통한 자동 차단 활성화
  - 방화벽(`iptables`)을 이용해 해당 IP 즉시 차단

---

## 🛠 4. Git Convention (Commit Message)
프로젝트 유지보수와 협업을 위해 아래의 **CRUD 기반 컨벤션**을 준수합니다.

| Prefix | Meaning | Description |
| :--- | :--- | :--- |
| **`C : CREATE`** | **생성** | 새로운 기능 추가, 파일 신규 생성 시 |
| **`R : READ`** | **읽기/데이터** | 데이터셋 로드, 문서화, 기존 코드 분석 시 |
| **`U : UPDATE`** | **수정** | 기존 코드 기능 개선, 버그 수정, 프롬프트 최적화 |
| **`D : DELETE`** | **삭제** | 불필요한 코드, 중복 디렉토리 및 파일 삭제 시 |

---

## 📂 Project Structure
```text
Sherlog/
├── app/              # 웹 인터페이스 (Streamlit 기반 UI)
├── src/              # 핵심 로직
│   ├── agents/       # OpenAI 에이전트 설계 및 프롬프트
│   ├── parsers/      # 로그 데이터 전처리 및 정규식 엔진
│   └── utils/        # 공통 유틸리티
├── data/             # 분석용 보안 데이터셋 (CIC-IDS, HDFS 등)
├── .env              # API Key 및 환경변수
└── README.md         # 프로젝트 가이드라인
