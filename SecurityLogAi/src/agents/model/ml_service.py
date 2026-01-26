import pandas as pd
import numpy as np
import joblib
import os
from dotenv import load_dotenv
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from imblearn.over_sampling import SMOTE

load_dotenv()

class MLService:
    def __init__(self):
        # 1. 현재 파일 위치를 기준으로 프로젝트 루트(SecurityLogAi) 찾기
        # ml_service.py 위치: src/agents/model/ml_service.py (4단계 위가 루트)
        current_file = os.path.abspath(__file__)
        self.project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(current_file))))

        # 2. .env에서 상대 경로 가져오기
        rel_model_path = os.getenv("MODEL_PATH", "./models/security_rf_model.pkl")
        rel_le_x_path = os.getenv("ENCODER_X_PATH", "./models/feature_encoder.pkl")
        rel_le_y_path = os.getenv("ENCODER_Y_PATH", "./models/label_encoder.pkl")

        # 3. 절대 경로로 변환
        self.model_path = os.path.abspath(os.path.join(self.project_root, rel_model_path))
        self.le_x_path = os.path.abspath(os.path.join(self.project_root, rel_le_x_path))
        self.le_y_path = os.path.abspath(os.path.join(self.project_root, rel_le_y_path))
        
        # 저장 폴더가 없으면 생성
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)

        self.model = None
        self.le_x = LabelEncoder()
        self.le_y = LabelEncoder()

    def preprocess_data(self, df):
        label_start_idx = df.columns.get_loc("response_content_length") + 1
        target_cols = df.columns[label_start_idx:].tolist()
        df['target'] = df[target_cols].idxmax(axis=1)

        X = df.drop(columns=target_cols + ['target', 'timestamp', 'src_ip', 'dst_ip'], errors='ignore')
        y = df['target']

        for col in X.select_dtypes(include=['object']).columns:
            X[col] = X[col].fillna("None")
        for col in X.select_dtypes(exclude=['object']).columns:
            X[col] = X[col].fillna(0)
        X = X.replace([np.inf, -np.inf], 0)
        return X, y

    def train_and_save(self, csv_path):
        print(f"📂 데이터 로드 중: {csv_path}")
        df = pd.read_csv(csv_path, low_memory=False)
        X, y = self.preprocess_data(df)

        print("🔢 데이터 수치화 진행 중...")
        for col in X.columns:
            if X[col].dtype == 'object':
                X[col] = self.le_x.fit_transform(X[col].astype(str))
        y_encoded = self.le_y.fit_transform(y)

        print("🚀 데이터 증강(SMOTE) 시작... (약 2~3분 소요)")
        smote = SMOTE(random_state=42, k_neighbors=1)
        X_res, y_res = smote.fit_resample(X, y_encoded)

        X_train, X_test, y_train, y_test = train_test_split(X_res, y_res, test_size=0.2, random_state=42, stratify=y_res)
        self.model = RandomForestClassifier(n_estimators=100, max_depth=20, n_jobs=-1, random_state=42)
        
        print("🌲 모델 학습 중...")
        self.model.fit(X_train, y_train)

        # 최종 저장
        joblib.dump(self.model, self.model_path)
        joblib.dump(self.le_x, self.le_x_path)
        joblib.dump(self.le_y, self.le_y_path)
        print(f"✅ [성공] 모델이 다음 위치에 저장되었습니다: {self.model_path}")