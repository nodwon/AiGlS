import joblib
import os
import pandas as pd
import numpy as np

class ModelHandler:
    """
    머신러닝 모델(XGBoost)을 로드하고 예측을 수행하는 핸들러.
    팀원이 준 파일 3개(xgb_attack.pkl, label.pkl, feature.pkl)가 꼭 있어야 함.
    """
    def __init__(self, model_dir=None):
        # 파일들이 있는 기본 경로 설정 (이 소스파일이랑 같은 폴더)
        base_dir = model_dir if model_dir else os.path.dirname(__file__)
        
        # 파일 경로 지정
        self.model_path = os.path.join(base_dir, "xgb_attack.pkl")
        self.label_path = os.path.join(base_dir, "label.pkl")
        self.feature_path = os.path.join(base_dir, "feature.pkl")
        
        # 변수들 초기화 (아직 로드 안됨)
        self.model = None
        self.label_encoder = None
        self.feature_columns = None
        
        # 실제 로딩 수행
        self.load_artifacts()

    def load_artifacts(self):
        """
        모델, 라벨, 피처 리스트 파일들을 실제로 읽어온다.
        없으면 에러 로그 찍고 넘어감 (예측 시에 체크함).
        """
        try:
            # 1. 모델 파일 (xgb_attack.pkl)
            if os.path.exists(self.model_path):
                self.model = joblib.load(self.model_path)
                print(f"[ModelHandler] 모델(두뇌) 장착 완료: {self.model_path}")
            else:
                print(f"[ModelHandler] Error: 모델 파일이 안 보임.. ({self.model_path})")

            # 2. 라벨 인코더 (label.pkl) - 예측 결과(0, 1)를 "SQL Injection" 같은 글자로 바꿔줌
            if os.path.exists(self.label_path):
                self.label_encoder = joblib.load(self.label_path)
                print(f"[ModelHandler] 라벨 통역기 로드 완료")
            
            # 3. 피처 리스트 (feature.pkl) - 학습할 때 썼던 컬럼 순서 (매우 중요)
            if os.path.exists(self.feature_path):
                self.feature_columns = joblib.load(self.feature_path)
                print(f"[ModelHandler] 피처 지도(컬럼 리스트) 로드 완료 (총 {len(self.feature_columns)}개)")
                
        except Exception as e:
            print(f"[ModelHandler] 파일 로딩하다가 뻗음: {e}")

    def predict(self, features: dict):
        """
        [핵심] 로그 하나(딕셔너리)를 받아서 공격인지 판단함.
        학습된 컬럼 순서에 맞춰서 딕셔너리를 일렬로 줄세워야 함.
        """
        if not self.model or not self.feature_columns:
            return "Model Not Ready", 0.0

        try:
            # 1. 일단 딕셔너리를 DataFrame으로 만듦 (편하니까)
            df = pd.DataFrame([features])
            
            # 2. One-Hot Encoding 처리 (수동 매핑)
            # EDA에서는 pd.get_dummies를 썼지만, 여기서는 피처 하나 들어오니까 직접 맞춰줘야 함.
            
            # 현재 들어온 로그의 OS랑 기기 정보 가져오기 (없으면 Other/PC)
            os_val = features.get('ua_os', 'Other')
            dev_val = features.get('ua_device', 'PC')
            
            # 3. 학습된 컬럼 리스트(self.feature_columns)를 기준으로 최종 입력 데이터 만들기
            # 빈 DataFrame 하나 만들고 순서대로 채워넣음
            input_data = pd.DataFrame(index=[0])
            
            for col in self.feature_columns:
                # [Case A] 파싱된 피처가 원래 있는 경우 (예: 'response_content_length') -> 그대로 넣음
                if col in df.columns:
                    input_data[col] = df[col]
                
                # [Case B] 모델에는 있는데 파서는 안 준거? (One-Hot Encoding 된 컬럼들)
                # 예: 모델은 'os_Windows'를 원하는데, 파서는 'ua_os'='Windows'만 줬을 때 -> 알아서 1로 채움.
                # (사실 파서가 os_Windows도 주긴 하는데, 혹시 몰라서 이중 안전장치해둠)
                elif col.startswith('os_') or col.startswith('dev_'):
                    # col이 'os_Windows'면 target_val은 'Windows'
                    target_val = col.split('_', 1)[1] 
                    
                    if col.startswith('os_'):
                        input_data[col] = 1 if os_val == target_val else 0
                    elif col.startswith('dev_'):
                        input_data[col] = 1 if dev_val == target_val else 0
                else:
                    # [Case C] 듣도 보도 못한 컬럼이면 그냥 0 채워넣음 (에러 방지)
                    input_data[col] = 0
            
            # 컬럼 순서 확실하게 다시 정렬 (XGBoost는 순서 틀리면 엉뚱한 예측 함)
            input_data = input_data[self.feature_columns]
            
            # 4. 예측 수행 (확률까지 뽑음)
            probs = self.model.predict_proba(input_data)
            max_prob_idx = probs[0].argmax() # 확률 제일 높은 인덱스 찾기
            confidence = float(probs[0][max_prob_idx]) # 확신도 (0.0 ~ 1.0)
            
            # 5. 숫자(인덱스)를 다시 사람이 읽을 수 있는 라벨로 변환
            if self.label_encoder:
                # inverse_transform은 리스트를 리턴하니까 [0]번째 꺼냄
                predicted_label = self.label_encoder.inverse_transform([max_prob_idx])[0]
            else:
                # 없으면 그냥 숫자 그대로 리턴
                predicted_label = str(max_prob_idx)
                
            return predicted_label, confidence

        except Exception as e:
            print(f"[ModelHandler] 예측하다 넘어짐: {e}")
            return "Error", 0.0
