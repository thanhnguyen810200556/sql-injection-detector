# 🔍 Web Attack Detection System

A web application that analyzes HTTP queries to detect **web attacks**, with a primary focus on **SQL Injection**.  
The system combines both **Rule-based (regex)** and **Machine Learning (Random Forest)** approaches to achieve accurate predictions.  

---

## 🚀 Key Features
- Preprocessing and feature extraction from HTTP query strings.  
- Detection based on three models:  
  - **Rule-based model (Regex)**  
  - **Machine Learning model (Random Forest)**  
  - **Hybrid model combining Rule-based + ML**  
- RESTful API built with **Flask**.  
- Simple **web interface** for real-time testing.  

---

## 🧠 Detection Models
- **Rule-based**: Uses a set of regex patterns to identify suspicious SQL keywords and payloads.  
- **ML-based**: Trained on features such as query length, number of special characters, SQL keyword count, entropy, and n-gram patterns.  
- **Combined**: Hybrid detection strategy leveraging both rule-based and ML outputs via voting or complementary conditions.  

---

## 📊 Model Performance

| Metric      | Rule-based | ML-based | Combined |
|-------------|-----------:|---------:|---------:|
| Accuracy    | 0.8320     | 0.9727   | 0.9170   |
| Precision   | 0.8099     | 0.9627   | 0.9344   |
| Recall      | 0.8738     | 0.9861   | 0.8994   |
| F1-score    | 0.8406     | 0.9742   | 0.9166   |
| ROC-AUC     | 0.9258     | 0.8961   | 0.9579   |

Confusion Matrix:

<img width="800" height="600" alt="image" src="https://github.com/user-attachments/assets/09e76941-5782-4761-8b74-39ec5b53187b" />

---

## ⚙️ Installation & Setup

```bash
# Clone repository
git clone https://github.com/thanhnguyen810200556/sql-injection-detector.git
cd sql-injection-detector

# (Optional) Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt

# Run the Flask app
python app.py
```

---

## 🎥 Demo Video  
👉 [Watch here](https://drive.google.com/file/d/1J9QmimoD3FSK7v0PveiiO9ZBOeVksrwi/view?usp=sharing)

---

## 👨‍💻 Development Team  
- **Nguyễn Xuân Thanh** –  Design & implementation of machine learning models, evaluation & visualization, feature engineering
- **Nguyễn Trần Khánh Vân** – Preprocessing, rule-based system design, web implementation, testing, demo video recording.


