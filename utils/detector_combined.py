import time
import logging
import numpy as np
import pandas as pd
from sklearn.metrics import f1_score, recall_score
from detectors.ml_model import MLDetector
from app.models import DetectionResult
from config import Config
from utils.logger import Logger

class CombinedDetector:
    """
    Lớp kết hợp Rule-based và Machine Learning để phát hiện SQL injection
    """
    
    def __init__(self, logger=None):
        """
        Khởi tạo CombinedDetector với các thành phần cần thiết
        """
        from detectors.rule_based import RuleBasedDetector
        self.rule_detector = RuleBasedDetector()
        self.ml_detector = MLDetector()
        
        # Load ML model nếu có
        try:
            self.ml_detector.load_model()
            self.ml_available = True
        except Exception as e:
            logging.warning(f"Không thể tải model ML: {e}")
            self.ml_available = False
            
        # Trọng số cho từng phương pháp
        self.rule_weight = Config.RULE_WEIGHT
        self.ml_weight = Config.ML_WEIGHT
        self.combined_threshold = Config.COMBINED_THRESHOLD
        
        # Logger
        self.logger = logger or Logger()
        
    def detect(self, query, test_file=None, find_optimal_combination=False):
        """
        Phân tích truy vấn để phát hiện SQL injection và tìm trọng số kết hợp tối ưu nếu được yêu cầu
        """
        start_time = time.time()

        # Nếu được yêu cầu tìm trọng số kết hợp tối ưu
        if find_optimal_combination:
            if test_file is None:
                test_file = Config.TEST_DATA_PATH
            optimal = self._find_optimal_combination(test_file)
            if optimal is not None:
                self.rule_weight, self.ml_weight, self.combined_threshold = optimal
                print(f"Tìm được trọng số tối ưu: rule_weight = {self.rule_weight:.2f}, "
                    f"ml_weight = {self.ml_weight:.2f}, threshold = {self.combined_threshold:.4f}")
                self.logger.log_info(f"Updated weights and threshold: rule={self.rule_weight}, "
                                    f"ml={self.ml_weight}, threshold={self.combined_threshold}")

        # Phát hiện bằng rule-based
        rule_result = self.rule_detector.detect(query)
        rule_score = rule_result['rule_score']
        detected_patterns = rule_result['patterns']

        # Phát hiện bằng machine learning nếu có thể
        if self.ml_available:
            try:
                ml_result = self.ml_detector.detect(query)
                ml_score = ml_result['ml_score']
                ml_error = None
            except Exception as e:
                self.logger.log_error(f"Lỗi khi phát hiện bằng ML: {e}")
                ml_score = 0.0
                ml_error = str(e)
        else:
            ml_score = 0.0
            ml_error = "Model ML không khả dụng"

        # Tính toán độ tin cậy kết hợp
        if self.ml_available:
            confidence = self.rule_weight * rule_score + self.ml_weight * ml_score
        else:
            confidence = rule_score

        is_sqli = confidence >= self.combined_threshold
        execution_time = (time.time() - start_time) * 1000

        result = DetectionResult(
            query=query,
            is_sqli=is_sqli,
            confidence=confidence,
            rule_score=rule_score,
            ml_score=ml_score,
            detected_patterns=detected_patterns,
            execution_time=execution_time,
            ml_error=ml_error
        )

        return result
    
    def _find_optimal_combination(self, test_file):
        """
        Tìm rule_weight, ml_weight, và threshold tốt nhất 

        """
        try:
            data = pd.read_csv(test_file)
            if 'query' not in data.columns or 'label' not in data.columns:
                self.logger.log_error("File test cần có cột 'query' và 'label'")
                return None

            scores = []
            for _, row in data.iterrows():
                try:
                    rule_result = self.rule_detector.detect(row['query'])
                    ml_result = self.ml_detector.detect(row['query']) if self.ml_available else {'ml_score': 0.0}

                    scores.append({
                        'rule_score': rule_result['rule_score'],
                        'ml_score': ml_result['ml_score'],
                        'label': row['label']
                    })
                except Exception as e:
                    self.logger.log_warning(f"Lỗi khi xử lý query: {e}")
                    continue

            if len(scores) == 0:
                self.logger.log_error("Không có dữ liệu hợp lệ để tối ưu")
                return None

            df = pd.DataFrame(scores)

            best_f1 = 0.0
            best_combination = None

            # Duyệt các trọng số và ngưỡng
            for rw in np.arange(0.0, 1.1, 0.1):
                mw = 1.0 - rw
                for threshold in np.arange(0.1, 1.0, 0.05):
                    df['combined_score'] = rw * df['rule_score'] + mw * df['ml_score']
                    df['pred'] = (df['combined_score'] >= threshold).astype(int)
                    f1 = f1_score(df['label'], df['pred'], zero_division=0)
                    if f1 > best_f1:
                        best_f1 = f1
                        best_combination = (rw, mw, threshold)

            if best_combination:
                self.logger.log_info(f"Best combination found - rule: {best_combination[0]}, "
                                    f"ml: {best_combination[1]}, threshold: {best_combination[2]:.4f}, "
                                    f"F1: {best_f1:.4f}")
            return best_combination

        except Exception as e:
            self.logger.log_error(f"Lỗi khi tìm trọng số tối ưu: {e}")
            return None

    
    def train_ml_model(self, train_file=None, **kwargs):
        """
        Huấn luyện mô hình machine learning
        """
        try:
            accuracy = self.ml_detector.train(train_file, **kwargs)
            self.ml_available = True
            self.logger.log_info(f"Đã huấn luyện mô hình ML với độ chính xác: {accuracy:.4f}")
            return accuracy
        except Exception as e:
            self.logger.log_error(f"Lỗi khi huấn luyện mô hình ML: {e}")
            self.ml_available = False
            raise
    
    def evaluate_ml_model(self, test_file=None):
        """
        Đánh giá mô hình machine learning
        
        """
        if not self.ml_available:
            raise ValueError("Mô hình ML không khả dụng để đánh giá")
            
        try:
            return self.ml_detector.evaluate(test_file)
        except Exception as e:
            self.logger.log_error(f"Lỗi khi đánh giá mô hình ML: {e}")
            raise
    
    def get_feature_importance(self, top_n=10):
        """
        Lấy các đặc trưng quan trọng của mô hình ML
        """
        if not self.ml_available:
            raise ValueError("Mô hình ML không khả dụng")
            
        try:
            return self.ml_detector.get_feature_importance(top_n)
        except Exception as e:
            self.logger.log_error(f"Lỗi khi lấy feature importance: {e}")
            raise
    
    def get_config(self):
        """
        Lấy thông tin cấu hình hiện tại của detector
        """
        return {
            'ml_available': self.ml_available,
            'rule_weight': self.rule_weight,
            'ml_weight': self.ml_weight,
            'combined_threshold': self.combined_threshold,
            'rule_based_threshold': self.rule_detector.threshold,
            'model_path': self.ml_detector.model_path if self.ml_available else None
        }
