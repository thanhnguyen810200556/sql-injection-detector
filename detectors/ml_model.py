import numpy as np
import pandas as pd
import joblib
import os
import time
import logging
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix
from utils.data_processor import DataProcessor
from config import Config

class MLDetector:
    """
    Detector sử dụng machine learning để phát hiện SQL injection
    """
    
    def __init__(self, model_path=None):
        self.data_processor = DataProcessor()
        
        # Đường dẫn mặc định cho model
        if model_path is None:
            if not os.path.exists(Config.ML_MODEL_PATH):
                os.makedirs(Config.ML_MODEL_PATH)
            model_path = os.path.join(Config.ML_MODEL_PATH, Config.MODEL_FILENAME)
            
        self.model_path = model_path
        self.model = None
        self.scaler = None
        self.feature_names = None
        
        # Tải model nếu đã tồn tại
        if os.path.exists(model_path):
            self.load_model()
    
    def train(self, train_file=None):
        """
        Huấn luyện mô hình machine learning
    
        Args:
            train_file (str, optional): Đường dẫn đến file dữ liệu huấn luyện
        
        Returns:
            float: Độ chính xác trên tập huấn luyện
        
        Raises:
            FileNotFoundError: Nếu không tìm thấy file dữ liệu
            ValueError: Nếu dữ liệu chỉ có một lớp
        """
        if train_file is None:
            train_file = Config.TRAIN_DATA_PATH
        
        # Kiểm tra file huấn luyện
        if not os.path.exists(train_file):
            raise FileNotFoundError(f"Không tìm thấy file train: {train_file}")
        
        # Đọc dữ liệu train
        logging.debug(f"Đọc dữ liệu từ {train_file}")
        train_df = pd.read_csv(train_file)
    
        # Kiểm tra phân bố nhãn
        label_counts = train_df['label'].value_counts()
        logging.debug("Label distribution: %s", label_counts.to_dict())
        if len(label_counts) < 2:
            logging.error("Dữ liệu huấn luyện chỉ có một lớp: %s", label_counts)
            raise ValueError("Dữ liệu huấn luyện chỉ có một lớp. Vui lòng cung cấp dữ liệu với cả hai nhãn.")

        # Chuẩn bị features và labels
        X_train_df, y_train = self.data_processor.prepare_features_from_df(
            train_df, query_column='query', label_column='label'
        )
        logging.debug("Features shape: %s", X_train_df.shape)
    
        # Lưu tên các features
        self.feature_names = X_train_df.columns.tolist()
    
        # Khởi tạo scaler và mô hình trong pipeline
        self.pipeline = Pipeline([
            ('scaler', StandardScaler()),
            ('classifier', RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42,
                n_jobs=-1,
                class_weight='balanced'
            ))
        ])
    
        # Huấn luyện pipeline
        print("Bắt đầu huấn luyện mô hình...")
        self.pipeline.fit(X_train_df, y_train)
        print("Huấn luyện mô hình hoàn tất.")
    
        # Trích xuất mô hình và scaler từ pipeline
        self.model = self.pipeline.named_steps['classifier']
        self.scaler = self.pipeline.named_steps['scaler']
    
        # Kiểm tra số lớp
        if len(self.model.classes_) < 2:
            logging.error("Mô hình chỉ học được một lớp: %s", self.model.classes_)
            raise ValueError("Mô hình chỉ học được một lớp. Kiểm tra dữ liệu huấn luyện.")
    
        # Lưu model
        self.save_model()
    
        # Đánh giá model trên tập train
        train_accuracy = self.pipeline.score(X_train_df, y_train)
        print(f"Độ chính xác trên tập train: {train_accuracy:.4f}")
    
        return train_accuracy
    
    def evaluate(self, test_file=None):
        """
        Đánh giá mô hình trên tập test
    
        Args:
            test_file (str, optional): Đường dẫn đến file dữ liệu kiểm tra
        
        Returns:
            dict: Dictionary chứa các metrics đánh giá
        
        Raises:
            ValueError: Nếu mô hình chưa được huấn luyện
            FileNotFoundError: Nếu không tìm thấy file dữ liệu
        """
        if self.model is None or self.scaler is None:
            raise ValueError("Mô hình chưa được huấn luyện hoặc tải")
        
        if test_file is None:
            test_file = Config.TEST_DATA_PATH
        
        if not os.path.exists(test_file):
            raise FileNotFoundError(f"Không tìm thấy file test: {test_file}")
            
        # Đọc dữ liệu test
        test_df = pd.read_csv(test_file)
    
        # Chuẩn bị features và labels
        X_test_df, y_test = self.data_processor.prepare_features_from_df(
            test_df, query_column='query', label_column='label'
        )
    
        # Kiểm tra và thêm các features thiếu
        for feature in self.feature_names:
            if feature not in X_test_df.columns:
                X_test_df[feature] = 0
    
        # Chỉ giữ các features đã dùng trong train
        X_test_df = X_test_df[self.feature_names]
    
        # Sử dụng scaler và dự đoán
        X_test = self.scaler.transform(X_test_df)
        y_pred = self.model.predict(X_test)
    
        # Tính toán các metrics
        accuracy = self.model.score(X_test, y_test)
        precision = precision_score(y_test, y_pred, zero_division=0)
        recall = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)
        conf_matrix = confusion_matrix(y_test, y_pred)
    
        # In kết quả
        print(f"Độ chính xác trên tập test: {accuracy:.4f}")
        print(f"Precision: {precision:.4f}")
        print(f"Recall: {recall:.4f}")
        print(f"F1 Score: {f1:.4f}")
        print(f"Confusion Matrix:\n{conf_matrix}")
    
        return {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1': f1,
            'confusion_matrix': conf_matrix.tolist()
        }
    
    def save_model(self):
        """
        Lưu model và scaler
        """
        if self.model is None:
            raise ValueError("Không có model để lưu")
            
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'feature_names': self.feature_names
        }
        
        # Tạo thư mục nếu chưa tồn tại
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        
        # Lưu model
        joblib.dump(model_data, self.model_path)
        print(f"Đã lưu model tại: {self.model_path}")
    
    def load_model(self):
        """
        Tải model và scaler
        """
        if not os.path.exists(self.model_path):
            raise FileNotFoundError(f"Không tìm thấy model tại: {self.model_path}")
            
        try:
            model_data = joblib.load(self.model_path)
            self.model = model_data['model']
            self.scaler = model_data['scaler']
            self.feature_names = model_data['feature_names']
            print(f"Đã tải model từ: {self.model_path}")
            return True
        except Exception as e:
            print(f"Lỗi khi tải model: {e}")
            return False
    
    def detect(self, query):
        """
        Phát hiện SQL injection bằng machine learning
    
        Args:
            query (str): Chuỗi truy vấn cần kiểm tra
        
        Returns:
            dict: Kết quả phát hiện bao gồm:
                - score: Xác suất query là SQL injection (0.0 đến 1.0)
                - is_sqli: Boolean cho biết có phải SQL injection hay không
                - execution_time: Thời gian thực thi (ms)
        """
        if self.model is None:
            raise ValueError("Model chưa được huấn luyện hoặc tải")
        
        start_time = time.time()
    
        # Trích xuất features
        features = self.data_processor.extract_features(query)
        features_df = pd.DataFrame([features])
    
        # Kiểm tra các features thiếu
        missing_features = set(self.feature_names) - set(features_df.columns)
        for feature in missing_features:
            features_df[feature] = 0
        
        # Đảm bảo thứ tự các features giống với lúc train
        features_df = features_df[self.feature_names]
    
        # Chuẩn hóa features
        X = self.scaler.transform(features_df)
    
        # Xử lý trường hợp mô hình chỉ có một lớp
        if len(self.model.classes_) < 2:
            logging.warning("Mô hình chỉ có một lớp: %s", self.model.classes_)
            # Nếu lớp duy nhất là 0 (không phải SQLi), score = 0
            # Nếu lớp duy nhất là 1 (là SQLi), score = 1
            is_only_class_sqli = 1 in self.model.classes_
            return {
                'score': 1.0 if is_only_class_sqli else 0.0,
                'is_sqli': is_only_class_sqli,
                'execution_time': (time.time() - start_time) * 1000
            }
    
        # Dự đoán xác suất (với mô hình có cả 2 lớp)
        try:
            score = self.model.predict_proba(X)[0, 1]  # Xác suất là SQL injection
            is_sqli = score >= 0.5
        except Exception as e:
            logging.error("Lỗi khi dự đoán: %s", str(e))
            # Fallback an toàn - không phải SQLi
            score = 0.0
            is_sqli = False
    
        execution_time = (time.time() - start_time) * 1000  # ms
    
        return {
            'score': score,
            'is_sqli': is_sqli,
            'execution_time': execution_time
        }
    
    def get_feature_importance(self, top_n=10):
        """
        Lấy tầm quan trọng của các tính năng trong mô hình
    
        Args:
            top_n (int): Số lượng tính năng quan trọng nhất để hiển thị
        
        Returns:
            dict: Dictionary chứa top_n tính năng quan trọng nhất và điểm số
        
        Raises:
            ValueError: Nếu mô hình chưa được huấn luyện
        """
        if self.model is None:
            raise ValueError("Mô hình chưa được huấn luyện hoặc tải")
        
        # Lấy điểm tầm quan trọng của các tính năng
        importances = self.model.feature_importances_
    
        # Tạo DataFrame chứa tính năng và tầm quan trọng
        feature_importance = pd.DataFrame({
            'feature': self.feature_names,
            'importance': importances
        })
    
        # Sắp xếp giảm dần theo tầm quan trọng
        feature_importance = feature_importance.sort_values('importance', ascending=False)
    
        # Lấy top_n tính năng quan trọng nhất
        top_features = feature_importance.head(top_n)
    
        return {
        'top_features': top_features.to_dict('records'),
        'all_features': feature_importance.to_dict('records')
        }