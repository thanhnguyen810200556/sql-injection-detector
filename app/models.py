#Lưu trữ và xử lý thông tin
from datetime import datetime

class DetectionResult:
    """
    Lớp lưu trữ kết quả phân tích phát hiện SQL injection
    
    Attributes:
        query (str): Truy vấn được kiểm tra
        is_sqli (bool): Truy vấn có phải là SQL injection không
        confidence (float): Độ tin cậy tổng hợp (0.0-1.0)
        rule_score (float): Điểm từ phương pháp rule-based (0.0-1.0)
        ml_score (float): Điểm từ phương pháp machine learning (0.0-1.0)
        detected_patterns (list): Danh sách các mẫu đáng ngờ được phát hiện
        timestamp (datetime): Thời gian phân tích
        execution_time (int): Thời gian thực thi phân tích (ms)
        ml_error (str): Thông tin lỗi từ mô hình machine learning nếu có
    """
    
    def __init__(self, query, is_sqli=False, confidence=0.0, rule_score=0.0, 
             ml_score=0.0, detected_patterns=None, execution_time=0, ml_error=None, rule_details=None):
        self.query = query if query else ""  
        self.is_sqli = bool(is_sqli)  
        self.confidence = max(0.0, min(1.0, float(confidence)))  
        self.rule_score = max(0.0, min(1.0, float(rule_score)))  
        self.ml_score = max(0.0, min(1.0, float(ml_score)))  
        self.detected_patterns = detected_patterns or []
        self.timestamp = datetime.now()
        self.execution_time = max(0, execution_time)  
        self.ml_error = ml_error
        self.rule_details = rule_details or {}

    def to_dict(self):
        """Chuyển đổi kết quả sang dictionary để dễ dàng truyền dưới dạng JSON"""
        return {
            "query": self.query,
            "is_sqli": self.is_sqli,
            "confidence": round(self.confidence, 4),
            "rule_score": round(self.rule_score, 4),
            "ml_score": round(self.ml_score, 4),
            "detected_patterns": self.detected_patterns,
            "timestamp": self.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "execution_time": self.execution_time
        }
    
    def get_severity_level(self):
        """Trả về mức độ nghiêm trọng dựa trên confidence"""
        if self.confidence >= 0.8:
            return "High"
        elif self.confidence >= 0.5:
            return "Medium"
        else:
            return "Low"

class QueryLog:
    """
    Lớp lưu trữ lịch sử các truy vấn và kết quả phát hiện SQL injection
    
    Attributes:
        query (str): Truy vấn được kiểm tra
        is_sqli (bool): Truy vấn có phải là SQL injection không
        confidence (float): Độ tin cậy của kết quả (0.0-1.0)
        timestamp (datetime): Thời gian ghi log
        ip_address (str): Địa chỉ IP thực hiện truy vấn
        user_agent (str): Thông tin user agent của client
        request_path (str): Đường dẫn yêu cầu
    """
    
    def __init__(self, query, is_sqli, confidence, ip_address=None, 
                 user_agent=None, request_path=None):
        self.query = query if query else ""
        self.is_sqli = bool(is_sqli)
        self.confidence = max(0.0, min(1.0, float(confidence)))
        self.timestamp = datetime.now()
        self.ip_address = ip_address
        self.user_agent = user_agent
        self.request_path = request_path

    def to_dict(self):
        return {
            'query': self.query,
            'is_sqli': self.is_sqli,
            'confidence': round(self.confidence, 4),
            'timestamp': self.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            'ip_address': self.ip_address
        }