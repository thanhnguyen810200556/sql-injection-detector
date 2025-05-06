import pandas as pd
import numpy as np
import re
from scipy.stats import entropy
from collections import Counter
from config import Config
import logging
from functools import lru_cache

class DataProcessor:
    """
    Class xử lý dữ liệu cho mô hình machine learning và rule-based phát hiện SQL Injection
    """
    
    def __init__(self):
        self.sql_keywords = Config.SQL_KEYWORDS
        self.special_chars = Config.SPECIAL_CHARS
        self.feature_extractors = Config.FEATURE_EXTRACTORS
        # Khởi tạo bộ nhớ đệm cho các phương thức tính toán tốn kém
        self._feature_cache = {}
    
    @lru_cache(maxsize=1000)
    def preprocess_query(self, query):
        """
        Tiền xử lý truy vấn trước khi trích xuất đặc trưng
        Được cache để tối ưu hiệu suất với truy vấn trùng lặp
        """
        if not query:
            return ""
        
        # Chuyển về chữ thường
        query = query.lower()
        
        # Loại bỏ các ký tự trắng thừa
        query = ' '.join(query.split())
        
        # Thay thế URL encoding
        url_encodings = {
            '%20': ' ', '%27': "'", '%22': '"', '%2B': '+', 
            '%3D': '=', '%3B': ';', '%28': '(', '%29': ')',
            '%2F': '/', '%5C': '\\', '%40': '@', '%23': '#',
            '%26': '&', '%3C': '<', '%3E': '>'
        }
        
        for code, char in url_encodings.items():
            query = query.replace(code, char)
            
        return query
    
    def _count_sql_keywords(self, query):
        """Đếm số từ khóa SQL xuất hiện trong truy vấn"""
        query_lower = query.lower()
        count = 0
        found_keywords = []
        
        for keyword in self.sql_keywords:
            pattern = r'\b{}\b'.format(re.escape(keyword))
            matches = re.findall(pattern, query_lower)
            if matches:
                count += len(matches)
                found_keywords.append(keyword)
                
        return count, found_keywords
    
    def _count_special_chars(self, query):
        """Đếm số ký tự đặc biệt trong truy vấn"""
        count = 0
        found_chars = []
        
        for char in self.special_chars:
            if char in query:
                count += query.count(char)
                found_chars.append(char)
                
        return count, found_chars
    
    def _calculate_entropy(self, query):
        """Tính entropy của chuỗi truy vấn"""
        if not query:
            return 0
            
        counter = Counter(query)
        probabilities = [count / len(query) for count in counter.values()]
        return entropy(probabilities, base=2)
    
    def _analyze_text_patterns(self, processed_query):
        """Phân tích các mẫu văn bản nguy hiểm"""
        features = {}
        
        # Các mẫu nguy hiểm thường gặp trong SQL Injection
        comment_sequence = ['--', '/*', '*/']
        
        # Pattern-specific features
        features['has_union'] = 1 if re.search(r'\bunion\s+select\b', processed_query, re.IGNORECASE) else 0
        features['has_comment'] = 1 if any(seq in processed_query for seq in comment_sequence) else 0
        features['has_or_true'] = 1 if re.search(r'\bor\s+[\'"]?\s*\d+\s*[\'"]?\s*=\s*[\'"]?\s*\d+\s*[\'"]?', processed_query, re.IGNORECASE) else 0
        features['has_sleep'] = 1 if re.search(r'\bsleep\s*\(\s*\d+\s*\)', processed_query, re.IGNORECASE) else 0
        features['has_benchmark'] = 1 if re.search(r'\bbenchmark\s*\(', processed_query, re.IGNORECASE) else 0
        features['has_concat'] = 1 if re.search(r'concat\s*\(', processed_query, re.IGNORECASE) else 0
        features['has_exec'] = 1 if re.search(r'\bexec\s*\(', processed_query, re.IGNORECASE) else 0
        
        # Comment ratio
        comment_count = sum(processed_query.count(seq) for seq in comment_sequence)
        features['comment_ratio'] = comment_count / max(len(processed_query), 1)
        
        return features
    
    def _analyze_url_patterns(self, processed_query, original_query):
        """Phân tích các mẫu URL nguy hiểm"""
        features = {}
        
        # Uppercase ratio
        if original_query:
            features['uppercase_ratio'] = sum(1 for c in original_query if c.isupper()) / len(original_query)
        else:
            features['uppercase_ratio'] = 0
        
        # URL-specific features
        features['has_encoded_chars'] = 1 if re.search(r'%[0-9A-F]{2}', processed_query) else 0
        features['param_count'] = len(processed_query.split('&')) if '&' in processed_query else 1
        features['has_suspicious_param'] = 1 if re.search(r'[\'";]', processed_query.split('=')[-1] if '=' in processed_query else '') else 0
        
        return features
    
    def extract_n_grams(self, query, n=2):
        """
        Trích xuất n-gram từ truy vấn
        """
        tokens = query.split()
        n_grams = []
        
        for i in range(len(tokens) - n + 1):
            n_grams.append(' '.join(tokens[i:i+n]))
            
        return n_grams
    
    def extract_features(self, query):
        """
        Trích xuất các đặc trưng từ truy vấn để dùng cho mô hình ML
        """
        # Kiểm tra cache
        if query in self._feature_cache:
            return self._feature_cache[query]
        
        processed_query = self.preprocess_query(query)
        features = {}
        
        # Đặc trưng độ dài
        if self.feature_extractors.get('length_features', True):
            features['query_length'] = len(processed_query)
            features['word_count'] = len(processed_query.split())
            
        # Đặc trưng từ khóa SQL
        if self.feature_extractors.get('token_freq', True):
            sql_keywords_count, _ = self._count_sql_keywords(processed_query)
            features['sql_keyword_count'] = sql_keywords_count
            features['sql_keyword_ratio'] = sql_keywords_count / max(len(processed_query.split()), 1)
            
        # Đặc trưng ký tự đặc biệt
        if self.feature_extractors.get('char_freq', True):
            special_char_count, _ = self._count_special_chars(processed_query)
            features['special_char_count'] = special_char_count
            features['special_char_ratio'] = special_char_count / max(len(processed_query), 1)
            
        # Entropy
        if self.feature_extractors.get('entropy', True):
            features['entropy'] = self._calculate_entropy(processed_query)
            
        # Phân tích mẫu văn bản
        pattern_features = self._analyze_text_patterns(processed_query)
        features.update(pattern_features)
        
        # Phân tích mẫu URL
        url_features = self._analyze_url_patterns(processed_query, query)
        features.update(url_features)
        
        # N-gram features (optional)
        if self.feature_extractors.get('ngrams', False):
            bigrams = self.extract_n_grams(processed_query, 2)
            features['sql_bigram_count'] = sum(1 for bg in bigrams 
                                              if any(kw in bg for kw in self.sql_keywords))
        
        # Lưu vào cache
        self._feature_cache[query] = features
        return features
    
    def normalize_features(self, features_df):
        """
        Chuẩn hóa các đặc trưng số
        """
        numeric_cols = features_df.select_dtypes(include=['float64', 'int64']).columns
        
        # Simple min-max scaling
        for col in numeric_cols:
            if features_df[col].max() > features_df[col].min():
                features_df[col] = (features_df[col] - features_df[col].min()) / (features_df[col].max() - features_df[col].min())
            
        return features_df
    
    def load_dataset(self, file_path):
        """
        Đọc dataset từ file CSV
        """
        try:
            df = pd.read_csv(file_path)
            return df
        except Exception as e:
            logging.error(f"Error loading dataset: {e}")
            return None
    
    def load_train_test_data(self, train_path, test_path):
        """
        Đọc dữ liệu từ file train và test
        """
        train_df = self.load_dataset(train_path)
        test_df = self.load_dataset(test_path)
        
        return train_df, test_df
    
    def prepare_features_from_df(self, df, query_column='query', label_column='label'):
        """
        Chuẩn bị features và labels từ DataFrame
        """
        features = []
        labels = []
        
        # Kiểm tra cột tồn tại
        if query_column not in df or label_column not in df:
            logging.error("Cột %s hoặc %s không tồn tại trong DataFrame", query_column, label_column)
            raise ValueError(f"Cột {query_column} hoặc {label_column} không tồn tại")

        # Kiểm tra nhãn hợp lệ
        unique_labels = df[label_column].unique()
        logging.debug("Unique labels: %s", unique_labels)
        if not all(label in [0, 1] for label in unique_labels):
            logging.error("Nhãn không hợp lệ: %s. Chỉ chấp nhận 0 và 1", unique_labels)
            raise ValueError("Nhãn không hợp lệ. Chỉ chấp nhận 0 và 1")

        for _, row in df.iterrows():
            query = row[query_column]
            label = row[label_column]
            
            if isinstance(query, str):
                feature_dict = self.extract_features(query)
                features.append(feature_dict)
                labels.append(label)
            else:
                logging.warning("Bỏ qua query không phải chuỗi: %s", query)
    
        X_df = pd.DataFrame(features)
        y = np.array(labels)
        
        # Chuẩn hóa đặc trưng
        X_df = self.normalize_features(X_df)
    
        logging.debug("Features shape: %s", X_df.shape)
        logging.debug("Sample features: %s", X_df.head().to_dict())
        logging.debug("Label distribution: %s", pd.Series(y).value_counts().to_dict())
    
        return X_df, y
    
    
    