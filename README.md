# sql-injection-detector
# 🔍 Web Attack Detection System

Ứng dụng web triển khai mô hình phân tích truy vấn HTTP để phát hiện các tấn công web, đặc biệt là tấn công **SQL Injection**. Hệ thống kết hợp giữa phương pháp **Rule-based (regex)** và **Machine Learning** để đưa ra dự đoán chính xác.

## 🚀 Tính năng chính

- Tiền xử lý và trích xuất đặc trưng từ truy vấn web (query string).
- Phát hiện truy vấn tấn công dựa trên:
  - Mô hình Rule-based (Regex)
  - Mô hình học máy ( Random Forest )
  - Mô hình kết hợp Rule-based và Machine Learning
- API RESTful sử dụng Flask.
- Giao diện web đơn giản để kiểm tra trực tiếp.

---

## 🧠 Mô hình sử dụng

- **Rule-based**: Dựa vào tập hợp các mẫu regex để phát hiện từ khóa tấn công.
- **ML-based**: Huấn luyện trên đặc trưng như độ dài truy vấn, số ký tự đặc biệt, số từ khóa SQL, entropy, v.v.
- **Combined**: Kết hợp hai mô hình trên bằng voting hoặc điều kiện bổ sung.

---
## 📊 Kết quả mô hình
| Metric    | Rule-based | ML-based | Combined |
| --------- | ---------- | -------- | -------- |
| Accuracy  | 0.8320     | 0.9727   | 0.9170   |
| Precision | 0.8099     | 0.9627   | 0.9344   |
| Recall    | 0.8738     | 0.9861   | 0.8994   |
| F1-score  | 0.8406     | 0.9742   | 0.9166   |
| ROC-AUC   | 0.9258     | 0.8961   | 0.9579   |

