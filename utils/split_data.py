import pandas as pd
from sklearn.model_selection import train_test_split
import os

def split_dataset(input_file, train_file, test_file, test_size=0.2):
    """Chia dữ liệu thành tập train/test và lưu vào file CSV."""
    # Kiểm tra file tồn tại
    if not os.path.exists(input_file):
        raise FileNotFoundError(f"File đầu vào {input_file} không tồn tại!")

    # Đọc dữ liệu
    df = pd.read_csv(input_file)
    if df.empty:
        raise ValueError("File CSV không có dữ liệu!")

    # Chia dữ liệu (stratified)
    train_df, test_df = train_test_split(
        df, 
        test_size=test_size, 
        random_state=42, 
        stratify=df['label']
    )

    # Đảm bảo thư mục tồn tại
    os.makedirs(os.path.dirname(train_file), exist_ok=True)
    os.makedirs(os.path.dirname(test_file), exist_ok=True)

    # Lưu file
    train_df.to_csv(train_file, index=False)
    test_df.to_csv(test_file, index=False)

    # Thống kê
    print(f"Tập huấn luyện ({len(train_df)} mẫu): {train_file}")
    print(f"Tập kiểm tra ({len(test_df)} mẫu): {test_file}")
    
    print("\nPhân phối label trong tập huấn luyện:")
    print(train_df['label'].value_counts(normalize=True).to_string())
    print("\nPhân phối label trong tập kiểm tra:")
    print(test_df['label'].value_counts(normalize=True).to_string())

if __name__ == "__main__":
    # Đường dẫn tương đối an toàn
    base_dir = os.path.dirname(os.path.dirname(__file__))
    data_dir = os.path.join(base_dir, "data")    
    input_file = os.path.join(data_dir, "preprocessed_csic.csv")
    train_file = os.path.join(data_dir, "training", "train.csv")
    test_file = os.path.join(data_dir, "test", "test.csv")
    
    split_dataset(input_file, train_file, test_file)