#Xử lý dữ liệu thô
import pandas as pd

def preprocess_csic_data(input_file, output_file):
    # Đọc file CSV
    df = pd.read_csv(input_file)

    # Lọc chỉ giữ các request có classification là 0 (Normal) hoặc 1 (SQLI)
    df_filtered = df[df['classification'].isin([0, 1])].copy()
    
    # Tạo cột "query" - sử dụng URL cho GET request hoặc content cho POST request
    df_filtered['query'] = df_filtered.apply(
        lambda row: row['URL'] if row['Method'] == 'GET' else row.get('content', ''), 
        axis=1
    )

    # Đổi tên cột classification thành label (0=Normal, 1=SQLI)
    df_filtered['label'] = df_filtered['classification']

    # Loại bỏ các hàng có query rỗng hoặc None
    df_filtered = df_filtered[df_filtered['query'].notna() & (df_filtered['query'] != '')]

    # Chỉ giữ 2 cột cần thiết
    df_final = df_filtered[['query', 'label']]

    # Lưu file CSV
    df_final.to_csv(output_file, index=False)
    
    # Thống kê
    print(f"Dữ liệu đã được tiền xử lý và lưu tại: {output_file}")
    print(f"Số lượng truy vấn Normal (0): {len(df_final[df_final['label'] == 0])}")
    print(f"Số lượng truy vấn SQLI (1): {len(df_final[df_final['label'] == 1])}")
    print(f"Tổng số mẫu: {len(df_final)}")

if __name__ == "__main__":
    input_file = "D:/University Courses/HK4/HDH-IT007/Đồ án cuối kì/sql-injection-detector/data/csic_database.csv"
    output_file = "D:/University Courses/HK4/HDH-IT007/Đồ án cuối kì/sql-injection-detector/data/preprocessed_csic.csv"
    preprocess_csic_data(input_file, output_file)