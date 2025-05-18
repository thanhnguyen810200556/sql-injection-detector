import time
import logging
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
        
        Args:
            logger (Logger, optional): Logger để ghi log detection
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
        
        # Ngưỡng phát hiện
        self.combined_threshold = Config.COMBINED_THRESHOLD
        
        # Logger
        self.logger = logger or Logger()
        
    def detect(self, query):
        """
        Phân tích truy vấn để phát hiện SQL injection
        
        Args:
            query (str): Chuỗi truy vấn cần kiểm tra
        
        Returns:
            DetectionResult: Kết quả phân tích
        """
        start_time = time.time()
        
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
            # Kết hợp cả hai điểm số với trọng số
            confidence = self.rule_weight * rule_score + self.ml_weight * ml_score
        else:
            # Chỉ sử dụng rule-based nếu ML không khả dụng
            confidence = rule_score
        
        # Xác định có phải SQL injection hay không
        is_sqli = confidence >= self.combined_threshold
        
        # Thời gian thực thi tính bằng ms
        execution_time = (time.time() - start_time) * 1000
        
        # Tạo kết quả phát hiện
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
    
    def train_ml_model(self, train_file=None, **kwargs):
        """
        Huấn luyện mô hình machine learning
        
        Args:
            train_file (str, optional): Đường dẫn đến file huấn luyện
            
        Returns:
            float: Độ chính xác trên tập huấn luyện
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
        
        Args:
            test_file (str, optional): Đường dẫn đến file kiểm tra
            
        Returns:
            dict: Kết quả đánh giá
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
        
        Args:
            top_n (int): Số lượng đặc trưng quan trọng nhất
            
        Returns:
            dict: Thông tin về các đặc trưng quan trọng
        """
        if not self.ml_available:
            raise ValueError("Mô hình ML không khả dụng")
            
        try:
            return self.ml_detector.get_feature_importance(top_n)
        except Exception as e:
            self.logger.log_error(f"Lỗi khi lấy feature importance: {e}")
            raise
    
    def tune_thresholds(self, rule_threshold=None, ml_threshold=None, combined_threshold=None):
        """
        Điều chỉnh các ngưỡng phát hiện
        
        Args:
            rule_threshold (float, optional): Ngưỡng phát hiện cho rule-based
            ml_threshold (float, optional): Ngưỡng phát hiện cho ML
            combined_threshold (float, optional): Ngưỡng phát hiện kết hợp
        """
        if rule_threshold is not None:
            self.rule_detector.threshold = float(rule_threshold)
            self.logger.log_info(f"Đã điều chỉnh ngưỡng rule-based: {rule_threshold}")
            
        if ml_threshold is not None and hasattr(self.ml_detector, 'threshold'):
            self.ml_detector.threshold = float(ml_threshold)
            self.logger.log_info(f"Đã điều chỉnh ngưỡng ML: {ml_threshold}")
            
        if combined_threshold is not None:
            self.combined_threshold = float(combined_threshold)
            self.logger.log_info(f"Đã điều chỉnh ngưỡng kết hợp: {combined_threshold}")
    
    def adjust_weights(self, rule_weight=None, ml_weight=None):
        """
        Điều chỉnh trọng số cho rule-based và ML
        
        Args:
            rule_weight (float, optional): Trọng số cho rule-based
            ml_weight (float, optional): Trọng số cho ML
        """
        if rule_weight is not None and ml_weight is not None:
            # Kiểm tra tổng trọng số bằng 1
            if abs(rule_weight + ml_weight - 1.0) > 0.001:
                raise ValueError("Tổng trọng số phải bằng 1.0")
                
            self.rule_weight = float(rule_weight)
            self.ml_weight = float(ml_weight)
            self.logger.log_info(f"Đã điều chỉnh trọng số: Rule={self.rule_weight}, ML={self.ml_weight}")
        elif rule_weight is not None:
            self.rule_weight = float(rule_weight)
            self.ml_weight = 1.0 - self.rule_weight
            self.logger.log_info(f"Đã điều chỉnh trọng số: Rule={self.rule_weight}, ML={self.ml_weight}")
        elif ml_weight is not None:
            self.ml_weight = float(ml_weight)
            self.rule_weight = 1.0 - self.ml_weight
            self.logger.log_info(f"Đã điều chỉnh trọng số: Rule={self.rule_weight}, ML={self.ml_weight}")

    def get_config(self):
        """
        Lấy thông tin cấu hình hiện tại của detector
        
        Returns:
            dict: Thông tin cấu hình hiện tại
        """
        return {
            'ml_available': self.ml_available,
            'rule_weight': self.rule_weight,
            'ml_weight': self.ml_weight,
            'combined_threshold': self.combined_threshold,
            'rule_based_threshold': self.rule_detector.threshold,
            'model_path': self.ml_detector.model_path if self.ml_available else None
        }
