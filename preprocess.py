# # import pandas as pd

# # # Đọc file
# # file_path = "data/validation/Validation.csv"
# # df = pd.read_csv(file_path)

# # # Trước xử lý
# # total_before = len(df)

# # # Xóa các dòng label không hợp lệ (NaN, không phải 0 hoặc 1)
# # df_clean = df[df['label'].isin([0, 1])].copy()
# # df_clean = df_clean.dropna(subset=['label'])

# # # Sau xử lý
# # total_after = len(df_clean)
# # removed = total_before - total_after

# # # Tính tỷ lệ 0:1
# # label_counts = df_clean['label'].value_counts()
# # label_0 = label_counts.get(0, 0)
# # label_1 = label_counts.get(1, 0)
# # ratio = f"{label_0}:{label_1}"

# # # In kết quả
# # print(f"Đã xoá {removed} dòng không hợp lệ.")
# # print(f"Còn lại {total_after} dòng.")
# # print(f"Tỷ lệ nhãn 0:1 là {ratio}")

# # # Lưu lại file sạch
# # df_clean.to_csv("data/validation/Validation_clean.csv", index=False)
# import pandas as pd
# from sklearn.model_selection import train_test_split
# import os

# # Đảm bảo các thư mục tồn tại
# os.makedirs("data/train", exist_ok=True)
# os.makedirs("data/test", exist_ok=True)

# # Đọc dữ liệu
# df = pd.read_csv("data/clean_sql_dataset.csv")

# # Tách dữ liệu thành train2 và test2 (80% train, 20% test - bạn có thể thay đổi tỉ lệ nếu cần)
# train2, test2 = train_test_split(df, test_size=0.2, random_state=42)

# # Lưu vào các file CSV
# train2.to_csv("data/train/train2.csv", index=False)
# test2.to_csv("data/test/test2.csv", index=False)

# print("Đã tách và lưu train2 và test2 thành công.")
import pandas as pd

# Đọc file CSV
df = pd.read_csv('data/test/Test_clean.csv')

# Giả sử cột nhãn tên là 'label'. Nếu khác, sửa lại tên cột cho đúng
label_counts = df['label'].value_counts()

# In ra số lượng mỗi nhãn
print("Số lượng nhãn:")
print(label_counts)

# Tính tỷ lệ phần trăm
label_percentages = df['label'].value_counts(normalize=True) * 100

print("\nTỷ lệ phần trăm:")
print(label_percentages.round(2))  # Làm tròn 2 chữ số
