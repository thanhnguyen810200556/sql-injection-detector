#import và khởi tạo
import re
import time
from utils.data_processor import DataProcessor #Xử lý dữ liệu trước khi bị phát hiện
from config import Config

class RuleBasedDetector:
    def __init__(self):
        self.data_processor = DataProcessor()
        self.sql_keywords = Config.SQL_KEYWORDS
        self.special_chars = Config.SPECIAL_CHARS
        self.threshold = Config.RULE_BASED_THRESHOLD
    
    #Các phương thức phát hiện
    def _check_union_attack(self, query):
        """Kiểm tra Union-based attack"""
        patterns = [
            r'union\s+(?:all\s+)?select',
            r'union\s+select\s+null',
            r'union\s+select\s+[^\s]+\s+from'
        ]
        return self._match_patterns(query, patterns, "Union-based attack")
    
    def _check_error_based(self, query):
        """Kiểm tra Error-based attack"""
        patterns = [
            r'xpath',
            r'extractvalue\s*\(',
            r'updatexml\s*\(',
            r'exp\s*\(',
            r'floor\s*\(.*\)\s*rand\s*\(',
            r'geometrycollection|multipoint|polygon|multipolygon|linestring|multilinestring',
            r'convert\s*\(.+using\s+\w+\)'
        ]
        return self._match_patterns(query, patterns, "Error-based attack")
    
    def _check_boolean_based(self, query):
        """Kiểm tra Boolean-based attack (ĐÃ CẢI THIỆN)"""
        patterns = [
            r'(?:and|or)\s+\d+=\d+',
            r'(?:and|or)\s+\'\s*=\s*\'',
            r'(?:and|or)\s+\"\s*=\s*\"',
            r'(?:and|or)\s+\w+\s*=\s*\w+',
            r'(?:and|or)\s+[\w\'\"]+\s*(?:like|=|!=|<>|>|<)\s*[\w\'\"]+',
            r'(?:and|or)\s+substring\s*\(',
            r'(?:and|or)\s+if\s*\('
        ]
        return self._match_patterns(query, patterns, "Boolean-based attack")
    
    def _check_tautology(self, query):
        """KIỂM TRA TẤN CÔNG TAUTOLOGY MỚI (QUAN TRỌNG)"""
        patterns = [
            r'or\s+\'1\'=\'1\'',
            r'or\s+\"1\"=\"1\"',
            r'or\s+1=1',
            r'or\s+\d+=\d+',
            r'or\s+[\w\'\"]+\s*=\s*[\w\'\"]+',
            r'\'\s*or\s*.+',
            r'\"\s*or\s*.+'
        ]
        return self._match_patterns(query, patterns, "Tautology attack")
    
    def _check_time_based(self, query):
        """Kiểm tra Time-based attack"""
        patterns = [
            r'sleep\s*\(\s*\d+\s*\)',
            r'benchmark\s*\(\s*\d+\s*,\s*\w+\s*\)',
            r'pg_sleep\s*\(\s*\d+\s*\)',
            r'waitfor\s+delay\s+\'\d{2}:\d{2}:\d{2}\''
        ]
        return self._match_patterns(query, patterns, "Time-based attack")
    
    def _check_stacked_queries(self, query):
        """Kiểm tra Stacked Queries attack"""
        patterns = [
            r';\s*(?:select|update|delete|insert|create|drop|alter|truncate)',
            r';\s*\w+\s*=',
            r';\s*exec\s+',
            r';\s*declare\s+'
        ]
        return self._match_patterns(query, patterns, "Stacked Queries attack")
    
    def _check_comment_attack(self, query):
        """Kiểm tra Comment attack"""
        patterns = [
            r'--\s+.*',
            r'\/\*.*\*\/',
            r'#.*$'
        ]
        return self._match_patterns(query, patterns, "Comment attack")
    
    def _check_sqlmap_fingerprints(self, query):
        """Kiểm tra các mẫu đặc trưng của sqlmap"""
        patterns = [
            r'sqlmap',
            r'AND\s+\d+=\d+\s*--',
            r'ORDER\s+BY\s+\d+--',
            r'UNION\s+ALL\s+SELECT\s+NULL'
        ]
        return self._match_patterns(query, patterns, "SQLMap fingerprint")
    
    #Hàm helper kiểm tra truy vấn có khớp với bất kỳ mẫu trong danh sách không
    def _match_patterns(self, query, patterns, pattern_name):
        """Hàm helper để kiểm tra nhiều patterns"""
        for pattern in patterns:
            if re.search(pattern, query, re.IGNORECASE): #cờ re.IGNORECASE để không phân biệt chữ hoa/thường.
                return True, pattern_name
        return False, None
        
    def detect(self, query):
        """
        Phát hiện SQL injection dựa vào các rule (ĐÃ CẢI THIỆN)
        
        Trả về:
        - score: Điểm đánh giá mức độ nguy hiểm (0.0 đến 1.0)
        - patterns: Các mẫu tấn công được phát hiện
        - is_sqli: Boolean cho biết có phải SQL injection hay không
        """
        start_time = time.time()
        processed_query = self.data_processor.preprocess_query(query)
        
        checks = [
            self._check_union_attack,
            self._check_error_based,
            self._check_boolean_based,
            self._check_tautology,  # THÊM DÒNG NÀY
            self._check_time_based,
            self._check_stacked_queries,
            self._check_comment_attack,
            self._check_sqlmap_fingerprints
        ]
        
        detected_patterns = []
        
        for check_function in checks:
            is_detected, pattern_name = check_function(processed_query)
            if is_detected and pattern_name:
                detected_patterns.append(pattern_name)
        
        # Đếm từ khóa và ký tự đặc biệt
        keyword_count, found_keywords = self.data_processor._count_sql_keywords(processed_query)
        char_count, found_chars = self.data_processor._count_special_chars(processed_query)
        
        if found_keywords:
            detected_patterns.append(f"SQL keywords: {', '.join(found_keywords)}")
        if found_chars:
            detected_patterns.append(f"Special chars: {', '.join(found_chars)}")
        
        # TÍNH ĐIỂM CẢI TIẾN
        base_score = min(len(detected_patterns) * 0.2, 0.8)  # Tăng trọng số patterns
        keyword_score = min(keyword_count * 0.07, 0.3)  # Tăng trọng số từ khóa
        char_score = min(char_count * 0.03, 0.3)  # Tăng trọng số ký tự đặc biệt
        
        # THƯỞNG ĐIỂM NẾU PHÁT HIỆN TAUTOLOGY/BOOLEAN-BASED
        if any("Tautology" in p or "Boolean-based" in p for p in detected_patterns):
            base_score = min(base_score + 0.3, 1.0)
        
        score = min(base_score + keyword_score + char_score, 1.0)
        is_sqli = score >= self.threshold
        
        return {
            'score': score,
            'patterns': detected_patterns,
            'is_sqli': is_sqli,
            'execution_time': (time.time() - start_time) * 1000
        }