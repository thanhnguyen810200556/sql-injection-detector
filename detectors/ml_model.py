import numpy as np
import pandas as pd
import joblib
import os
import time
import logging
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_selection import SelectFromModel
from sklearn.model_selection import RandomizedSearchCV
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import precision_recall_curve, precision_score, recall_score, f1_score, confusion_matrix, roc_curve
from utils.data_processor import DataProcessor
from config import Config
from imblearn.pipeline import Pipeline as ImbPipeline
from imblearn.over_sampling import SMOTE

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
        self.threshold = Config.ML_THRESHOLD

        # Tải model nếu đã tồn tại
        if os.path.exists(model_path):
            self.load_model()
    
    def train(self, train_file=None):
        """
        Huấn luyện mô hình machine learning với SMOTE, feature selection và tinh chỉnh tham số
        """
        if train_file is None:
            train_file = Config.TRAIN_DATA_PATH
        
        # Kiểm tra file huấn luyện
        if not os.path.exists(train_file):
            logging.error(f"Không tìm thấy file train: {train_file}")
            raise FileNotFoundError(f"Không tìm thấy file train: {train_file}")
        
        # Đọc dữ liệu train
        logging.info(f"Đọc dữ liệu từ {train_file}")
        train_df = pd.read_csv(train_file)
    
        # Kiểm tra phân bố nhãn
        label_counts = train_df['label'].value_counts()
        logging.info("Phân bố nhãn: %s", label_counts.to_dict())
        if len(label_counts) < 2:
            logging.error("Dữ liệu huấn luyện chỉ có một lớp: %s", label_counts)
            raise ValueError("Dữ liệu huấn luyện chỉ có một lớp. Vui lòng cung cấp dữ liệu với cả hai nhãn.")

        # Chuẩn bị features và labels
        logging.info("Chuẩn bị đặc trưng từ dataframe")
        X_train_df, y_train = self.data_processor.prepare_features_from_df(
            train_df, query_column='query', label_column='label'
        )
        logging.info("Kích thước đặc trưng: %s", X_train_df.shape)
    
        # Lưu tên các features
        self.feature_names = X_train_df.columns.tolist()
        logging.info(f"Số lượng đặc trưng đầu vào: {len(self.feature_names)}")
        print(f"Số lượng đặc trưng đầu vào: {len(self.feature_names)}")

        # Tạo pipeline với SMOTE, feature selection và RandomForest
        logging.info("Khởi tạo pipeline")
        self.pipeline = ImbPipeline([
            ('scaler', StandardScaler()),
            ('smote', SMOTE(random_state=42)),  
            ('classifier', RandomForestClassifier(
                                    n_estimators=100,
                                    max_depth = 10, 
                                    )) 
            ])

        # Định nghĩa tham số tìm kiếm
        param_grid = {
            'classifier__n_estimators': [200, 300, 400],
            'classifier__max_depth': [8, 10, 12],
            'classifier__min_samples_split': [5, 10],
            'classifier__min_samples_leaf': [2, 4],
            'classifier__max_features': ['sqrt', 'log2'],
            'classifier__class_weight': ['balanced', {0:1, 1:1.5}, {0:1, 1:2}]
        }

        # Tinh chỉnh tham số với RandomizedSearchCV
        logging.info("Bắt đầu tinh chỉnh tham số...")
        print("Bắt đầu tinh chỉnh tham số...")
        search = RandomizedSearchCV(
            self.pipeline,
            param_distributions=param_grid,
            n_iter=10,  # Số lần thử
            cv=5,
            scoring='recall',
            n_jobs=-1,
            random_state=42,
            verbose=1
        )

        search.fit(X_train_df, y_train)
        self.pipeline = search.best_estimator_
        logging.info(f"Tham số tốt nhất: {search.best_params_}")
        logging.info(f"Recall tốt nhất (CV): {search.best_score_:.4f}")
        print(f"Tham số tốt nhất: {search.best_params_}")
        print(f"Recall tốt nhất (CV): {search.best_score_:.4f}")

        # Trích xuất mô hình và scaler từ pipeline
        self.model = self.pipeline.named_steps['classifier']
        self.scaler = self.pipeline.named_steps['scaler']
    
        # Kiểm tra số lớp
        if len(self.model.classes_) < 2:
            logging.error("Mô hình chỉ học được một lớp: %s", self.model.classes_)
            raise ValueError("Mô hình chỉ học được một lớp. Kiểm tra dữ liệu huấn luyện.")
    
        # Đánh dấu model đã được tải/huấn luyện
        self.is_loaded = True
        
        # Lưu model
        self.save_model()
    
        # Đánh giá model trên tập train
        y_pred = self.pipeline.predict(X_train_df)
        train_recall = recall_score(y_train, y_pred)
        logging.info(f"Recall trên tập train: {train_recall:.4f}")
        print(f"Recall trên tập train: {train_recall:.4f}")
    
        return train_recall
    
    def evaluate(self, test_file=None):
        """
        Đánh giá mô hình trên tập test
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

    def detect(self, query, test_file=None, find_optimal_threshold=False):
        """
        Phát hiện SQL injection bằng machine learning
        """
        if self.model is None:
            raise ValueError("Model chưa được huấn luyện hoặc tải")
    
        start_time = time.time()
        
        # Tìm threshold tốt nhất nếu được yêu cầu
        if find_optimal_threshold:
            if test_file is None:
                test_file = Config.TEST_DATA_PATH
            
            optimal_threshold = self._find_optimal_threshold(test_file)
            if optimal_threshold is not None:
                self.threshold = optimal_threshold
                print(f"Threshold tốt nhất được tìm thấy: {optimal_threshold:.4f}")
                logging.info(f"Optimal threshold found and updated: {optimal_threshold:.4f}")
    
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
            is_only_class_sqli = 1 in self.model.classes_
            result = {
                'score': 1.0 if is_only_class_sqli else 0.0,
                'is_sqli': is_only_class_sqli,
                'execution_time': (time.time() - start_time) * 1000
            }
            if find_optimal_threshold:
                result['optimal_threshold'] = self.threshold
            return result
    
        # Dự đoán xác suất (với mô hình có cả 2 lớp)
        try:
            score = self.model.predict_proba(X)[0, 1]  
            is_sqli = score >= self.threshold
        except Exception as e:
            logging.error("Lỗi khi dự đoán: %s", str(e))
            score = 0.0
            is_sqli = False
    
        execution_time = (time.time() - start_time) * 1000  # ms
    
        result = {
            'ml_score': score,
            'is_sqli': is_sqli,
            'execution_time': execution_time
        }
        
        if find_optimal_threshold:
            result['optimal_threshold'] = self.threshold
        
        return result

    def _find_optimal_threshold(self, test_file):
        """
        Tìm threshold tốt nhất 
        """
        try:
            test_data = pd.read_csv(test_file)
        
            if 'query' not in test_data.columns or 'label' not in test_data.columns:
                logging.error("Test file phải có cột 'query' và 'label'")
                return None
            
            # Trích xuất features cho tất cả test queries
            test_features = []
            test_labels = []
            
            for _, row in test_data.iterrows():
                try:
                    features = self.data_processor.extract_features(row['query'])
                    test_features.append(features)
                    test_labels.append(row['label'])
                except Exception as e:
                    logging.warning(f"Lỗi khi xử lý query: {row['query'][:50]}... - {str(e)}")
                    continue
            
            if len(test_features) == 0:
                logging.error("Không thể trích xuất features từ test data")
                return None
            
            # Chuyển đổi thành DataFrame
            test_features_df = pd.DataFrame(test_features)
            
            # Kiểm tra các features thiếu
            missing_features = set(self.feature_names) - set(test_features_df.columns)
            for feature in missing_features:
                test_features_df[feature] = 0
            
            # Đảm bảo thứ tự features
            test_features_df = test_features_df[self.feature_names]
            
            # Chuẩn hóa features
            X_test = self.scaler.transform(test_features_df)
            y_test = np.array(test_labels)
            
            # Dự đoán xác suất
            if len(self.model.classes_) < 2:
                logging.warning("Model chỉ có một lớp, không thể tìm optimal threshold")
                return None
            
            y_proba = self.model.predict_proba(X_test)[:, 1]
            
            # Tìm threshold tốt nhất 
            precision, recall, thresholds_pr = precision_recall_curve(y_test, y_proba)
            f1_scores = 2 * (precision * recall) / (precision + recall + 1e-8)  
            
           
            best_f1_idx = np.argmax(f1_scores)
            
            
            if best_f1_idx >= len(thresholds_pr):
                optimal_threshold_f1 = thresholds_pr[-1]
            else:
                optimal_threshold_f1 = thresholds_pr[best_f1_idx]
            
           
            fpr, tpr, thresholds_roc = roc_curve(y_test, y_proba)
            j_scores = tpr - fpr  
            best_j_idx = np.argmax(j_scores)
            optimal_threshold_roc = thresholds_roc[best_j_idx]
            
            # Log thông tin về các threshold tìm được
            logging.info(f"Optimal threshold (F1-based): {optimal_threshold_f1:.4f} (F1: {f1_scores[best_f1_idx]:.4f})")
            logging.info(f"Optimal threshold (ROC-based): {optimal_threshold_roc:.4f} (J: {j_scores[best_j_idx]:.4f})")
            
           
            return float(optimal_threshold_f1)
            
        except Exception as e:
            logging.error(f"Lỗi khi tìm optimal threshold: {str(e)}")
            return None
        
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
    
