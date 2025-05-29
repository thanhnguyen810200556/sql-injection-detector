import logging
import re
import time
import numpy as np
import pandas as pd
from sklearn.metrics import f1_score, precision_recall_curve, roc_curve
from utils.data_processor import DataProcessor 
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
            if re.search(pattern, query, re.IGNORECASE): 
                return True, pattern_name
        return False, None
        
    def detect(self, query, test_file=None, find_optimal_threshold=False):
        """
        Phát hiện SQL injection dựa vào các rule (ĐÃ CẢI THIỆN)
        """
        start_time = time.time()
        
        # Tìm threshold tốt nhất 
        if find_optimal_threshold:
            if test_file is None:
                test_file = Config.TEST_DATA_PATH
            
            optimal_threshold = self._find_optimal_threshold(test_file)
            if optimal_threshold is not None:
                self.threshold = optimal_threshold
                print(f"Threshold tốt nhất được tìm thấy: {optimal_threshold:.4f}")
                logging.info(f"Optimal threshold found and updated: {optimal_threshold:.4f}")
        
        processed_query = self.data_processor.preprocess_query(query)
    
        checks = [
            self._check_union_attack,
            self._check_error_based,
            self._check_boolean_based,
            self._check_tautology,  
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
    
        result = {
            'rule_score': score,
            'patterns': detected_patterns,
            'is_sqli': is_sqli,
            'execution_time': (time.time() - start_time) * 1000
        }
        
        if find_optimal_threshold:
            result['optimal_threshold'] = self.threshold
        
        return result

    def _find_optimal_threshold(self, test_file):
        """
        Tìm threshold tốt nhất dựa trên test data cho rule-based detection
        """
        try:
            # Đọc test data
            test_data = pd.read_csv(test_file)
            
            # Kiểm tra cột cần thiết
            if 'query' not in test_data.columns or 'label' not in test_data.columns:
                logging.error("Test file phải có cột 'query' và 'label'")
                return None
            
            # Tính toán rule scores cho tất cả test queries
            test_scores = []
            test_labels = []
            
            for _, row in test_data.iterrows():
                try:
                    # Tính điểm rule-based cho từng query (không dùng threshold hiện tại)
                    query = row['query']
                    processed_query = self.data_processor.preprocess_query(query)
                    
                    checks = [
                        self._check_union_attack,
                        self._check_error_based,
                        self._check_boolean_based,
                        self._check_tautology,
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
                    
                    # TÍNH ĐIỂM CẢI TIẾN (giống như trong hàm detect)
                    base_score = min(len(detected_patterns) * 0.2, 0.8)
                    keyword_score = min(keyword_count * 0.07, 0.3)
                    char_score = min(char_count * 0.03, 0.3)
                    
                    # THƯỞNG ĐIỂM NẾU PHÁT HIỆN TAUTOLOGY/BOOLEAN-BASED
                    if any("Tautology" in p or "Boolean-based" in p for p in detected_patterns):
                        base_score = min(base_score + 0.3, 1.0)
                    
                    score = min(base_score + keyword_score + char_score, 1.0)
                    
                    test_scores.append(score)
                    test_labels.append(row['label'])
                    
                except Exception as e:
                    logging.warning(f"Lỗi khi xử lý query: {row['query'][:50]}... - {str(e)}")
                    continue
            
            if len(test_scores) == 0:
                logging.error("Không thể tính toán scores từ test data")
                return None
            
            # Chuyển đổi thành numpy arrays
            y_scores = np.array(test_scores)
            y_test = np.array(test_labels)
            
            # Tìm threshold tốt nhất 
            thresholds = np.unique(y_scores)
            thresholds = np.sort(thresholds)
            
            best_f1 = 0
            best_threshold_f1 = 0.5
            
            for threshold in thresholds:
                y_pred = (y_scores >= threshold).astype(int)
                f1 = f1_score(y_test, y_pred, zero_division=0)
                
                if f1 > best_f1:
                    best_f1 = f1
                    best_threshold_f1 = threshold
            
            # Tìm threshold tốt nhất 
            fpr, tpr, thresholds_roc = roc_curve(y_test, y_scores)
            j_scores = tpr - fpr  # Youden's J statistic
            best_j_idx = np.argmax(j_scores)
            optimal_threshold_roc = thresholds_roc[best_j_idx]
            
            # Tìm threshold tốt nhất 
            precision, recall, thresholds_pr = precision_recall_curve(y_test, y_scores)
            f1_scores_pr = 2 * (precision * recall) / (precision + recall + 1e-8)
            best_f1_pr_idx = np.argmax(f1_scores_pr)
            
            if best_f1_pr_idx >= len(thresholds_pr):
                optimal_threshold_pr = thresholds_pr[-1]
            else:
                optimal_threshold_pr = thresholds_pr[best_f1_pr_idx]
            
            # Log thông tin về các threshold tìm được
            logging.info(f"Optimal threshold (F1-based): {best_threshold_f1:.4f} (F1: {best_f1:.4f})")
            logging.info(f"Optimal threshold (ROC-based): {optimal_threshold_roc:.4f} (J: {j_scores[best_j_idx]:.4f})")
            logging.info(f"Optimal threshold (PR-based): {optimal_threshold_pr:.4f} (F1: {f1_scores_pr[best_f1_pr_idx]:.4f})")
            
            # Chọn threshold 
            return float(best_threshold_f1)
            
        except Exception as e:
            logging.error(f"Lỗi khi tìm optimal threshold: {str(e)}")
            return None
