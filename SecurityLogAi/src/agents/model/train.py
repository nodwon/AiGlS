import sys
import os
from dotenv import load_dotenv

load_dotenv()

current_dir = os.path.dirname(os.path.abspath(__file__))

if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

try:
    from ml_service import MLService
    print("✅ MLService 모듈 로드 성공!")
except ImportError:
    # 경로가 바뀌었을 경우를 대비한 백업 임포트
    from src.agents.ml_service import MLService
    print("✅ src.agents 경로로 로드 성공!")

if __name__ == "__main__":
    ml = MLService()
    
    # 1. 먼저 모델 파일이 이미 있는지 확인합니다.
    # ml.model_path는 ml_service.py에서 설정한 절대 경로입니다.
    if os.path.exists(ml.model_path):
        print(f"📂 [알림] 기존 모델 파일이 이미 존재합니다: {ml.model_path}")
        print("💡 새로 학습하면 기존 파일이 덮어쓰여집니다.")
    else:
        print("🆕 [알림] 생성된 모델 파일이 없습니다. 새로운 학습이 필요합니다.")

    # 2. 데이터 경로 설정 및 학습 시작
    rel_csv_path = os.getenv("TRAIN_DATA_PATH", "./data/data_capec_multilabel.csv")
    csv_path = os.path.abspath(os.path.join(ml.project_root, rel_csv_path))
    
    if os.path.exists(csv_path):
        print(f"📊 데이터 발견: {csv_path}")
        confirm = input("🚀 학습을 시작할까요? (y/n): ")
        if confirm.lower() == 'y':
            ml.train_and_save(csv_path)
            
            # 3. 학습 종료 후 파일 생성 확인
            if os.path.exists(ml.model_path):
                print(f"✨ [완료] 모델 파일이 성공적으로 생성되었습니다!")
                print(f"📍 위치: {ml.model_path}")
        else:
            print("👋 학습을 취소했습니다.")
    else:
        print(f"❌ 에러: {csv_path}에 데이터 파일이 없습니다.")