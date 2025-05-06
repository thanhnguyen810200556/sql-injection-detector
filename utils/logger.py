import logging
import os
from datetime import datetime
import pandas as pd
from config import Config

class Logger:
    """
    Class quản lý log cho hệ thống
    """
    
    def __init__(self, log_file=None):
        # Tạo thư mục logs nếu chưa tồn tại
        if not os.path.exists(Config.LOG_DIR):
            os.makedirs(Config.LOG_DIR)
            
        # Đặt tên file log
        if log_file is None:
            log_file = os.path.join(Config.LOG_DIR, Config.LOG_FILENAME)
            
        # Thiết lập logger
        self.logger = logging.getLogger('sql_injection_detector')
        self.logger.setLevel(logging.INFO)
        
        # Tạo file handler
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.INFO)
        
        # Tạo console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        
        # Định dạng log
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        # Thêm handlers vào logger
        if not self.logger.handlers:
            self.logger.addHandler(file_handler)
            self.logger.addHandler(console_handler)
            
        # Đường dẫn file log cho detection
        self.detection_log_file = os.path.join(Config.LOG_DIR, 'detection_log.csv')
        
        # Khởi tạo file log detection nếu chưa tồn tại
        if not os.path.exists(self.detection_log_file):
            pd.DataFrame(columns=[
                'timestamp', 'query', 'is_sqli', 'confidence', 
                'rule_score', 'ml_score', 'ip_address'
            ]).to_csv(self.detection_log_file, index=False)
    
    def log_info(self, message):
        """Log thông tin thông thường"""
        self.logger.info(message)
    
    def log_warning(self, message):
        """Log cảnh báo"""
        self.logger.warning(message)
    
    def log_error(self, message):
        """Log lỗi"""
        self.logger.error(message)
    
    def log_detection(self, detection_result, ip_address=None):
        """
        Log kết quả phát hiện vào file CSV
        """
        log_data = {
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'query': detection_result.query,
            'is_sqli': detection_result.is_sqli,
            'confidence': detection_result.confidence,
            'rule_score': detection_result.rule_score,
            'ml_score': detection_result.ml_score,
            'ip_address': ip_address
        }
        
        # Đọc file hiện tại
        try:
            df = pd.read_csv(self.detection_log_file)
        except:
            df = pd.DataFrame(columns=[
                'timestamp', 'query', 'is_sqli', 'confidence', 
                'rule_score', 'ml_score', 'ip_address'
            ])
        
        # Thêm log mới
        df = pd.concat([df, pd.DataFrame([log_data])], ignore_index=True)
        
        # Lưu file
        df.to_csv(self.detection_log_file, index=False)
        
        # Log thông báo
        message = f"Detection: [{'SQLI' if detection_result.is_sqli else 'Normal'}] - Confidence: {detection_result.confidence:.4f} - Query: {detection_result.query[:50]}"
        if detection_result.is_sqli:
            self.logger.warning(message)
        else:
            self.logger.info(message)
            
    def get_recent_logs(self, limit=50):
        """
        Lấy các logs gần đây nhất
        """
        try:
            df = pd.read_csv(self.detection_log_file)
            # Chuyển đổi các giá trị boolean thành int hoặc string
            if 'is_sqli' in df.columns:
                df['is_sqli'] = df['is_sqli'].astype(int)  # Chuyển True/False thành 1/0
        
            # Sắp xếp theo thời gian giảm dần
            df = df.sort_values(by='timestamp', ascending=False)
            # Lấy số lượng logs theo limit
            return df.head(limit).to_dict('records')
        except Exception as e:
            self.logger.error(f"Không thể đọc logs: {e}")
            return []