# các thông số cấu hình:
import os
from datetime import datetime

# Cấu hình cơ bản
class Config:
    # Bảo mật
    
    
    # Đường dẫn dữ liệu
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    DATA_DIR = os.path.join(BASE_DIR, 'data')    
    RAW_DATA_PATH = os.path.join(DATA_DIR, 'csic_database.csv')
    PREPROCESSED_DATA_PATH = os.path.join(DATA_DIR, 'preprocessed_csiv.csv')
    TRAIN_DATA_PATH = os.path.join(DATA_DIR, 'train', 'Train_clean.csv')
    TEST_DATA_PATH = os.path.join(DATA_DIR, 'test', 'Test_clean.csv')
    
    # Cấu hình ML model
    ML_MODEL_PATH = os.path.join(BASE_DIR, 'detectors', 'models')
    MODEL_FILENAME = 'sqli_detector_model.pkl'
    
    # Cấu hình logger
    LOG_DIR = os.path.join(BASE_DIR, 'logs')
    LOG_FILENAME = f'app_{datetime.now().strftime("%Y%m%d")}.log'
    
    # Thông số ML
    FEATURE_EXTRACTORS = {
        'char_freq': True,  # Tần số ký tự đặc biệt
        'token_freq': True,  # Tần số token SQL
        'length_features': True,  # Đặc trưng độ dài
        'entropy': True,  # Entropy của chuỗi
    }
    
    # Danh sách từ khóa SQL và ký tự đặc biệt để phát hiện SQLi
    SQL_KEYWORDS = [
        'select', 'insert', 'update', 'delete', 'drop', 'union', 'create', 'alter', 
        'where', 'from', 'table', 'database', 'having', 'column', 'exec', 'execute',
        'declare', 'cast', 'convert', 'truncate', 'information_schema', 'sysobjects',
        'syslogins', 'master', 'xp_cmdshell', 'sp_', 'waitfor', 'delay', 'varchar',
        'char', 'script', 'set', 'into', 'values', 'procedure'
    ]
    
    SPECIAL_CHARS = [
        "'", '"', ';', '--', '/*', '*/', '@@', '@', '#', '=', '+', '||', '|', '&', '&&',
        '>', '<', '!', '%', '$', '()', '(', ')', '{', '}', '[', ']', ',', '\\', '`'
    ]
    
      # Ngưỡng phát hiện SQLi
    RULE_BASED_THRESHOLD = 0.75  # Ngưỡng riêng cho rule-based
    ML_THRESHOLD = 0.5          # Ngưỡng riêng cho ML
    COMBINED_THRESHOLD = 0.7    # Ngưỡng khi kết hợp cả hai
    THRESHOLD = 0.5

    # Cấu hình kết hợp model
    RULE_WEIGHT = 0.4  # Trọng số cho rule-based 0.7
    ML_WEIGHT = 0.6    # Trọng số cho machine learning 0.3
