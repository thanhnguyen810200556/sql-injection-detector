import argparse
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import os
import joblib
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.metrics import confusion_matrix, roc_curve, auc, precision_recall_curve
from sklearn.ensemble import RandomForestClassifier
from detectors.ml_model import MLDetector
from detectors.rule_based import RuleBasedDetector
from utils.detector_combined import CombinedDetector
from config import Config

def parse_args():
    parser = argparse.ArgumentParser(description='Huấn luyện và đánh giá mô hình phát hiện SQL injection')
    parser.add_argument('--train', action='store_true', help='Huấn luyện mô hình mới')
    parser.add_argument('--evaluate', action='store_true', help='Đánh giá mô hình')
    parser.add_argument('--compare', action='store_true', help='So sánh các mô hình (rule-based, ML, combined)')
    parser.add_argument('--tune', action='store_true', help='Tinh chỉnh tham số mô hình')
    parser.add_argument('--train_file', type=str, default=Config.TRAIN_DATA_PATH, help='Đường dẫn file train')
    parser.add_argument('--test_file', type=str, default=Config.TEST_DATA_PATH, help='Đường dẫn file test')
    parser.add_argument('--output_dir', type=str, default='results', help='Thư mục lưu kết quả')
    return parser.parse_args()

def train_model(train_file, output_dir):
    """Huấn luyện mô hình ML mới"""
    print(f"Bắt đầu huấn luyện mô hình với dữ liệu từ {train_file}...")
    
    # Khởi tạo detector
    ml_detector = MLDetector()
    
    # Huấn luyện mô hình
    accuracy = ml_detector.train(train_file)
    
    # Lưu kết quả
    os.makedirs(output_dir, exist_ok=True)
    
    print(f"Huấn luyện hoàn tất! Độ chính xác trên tập huấn luyện: {accuracy:.4f}")
    
    # Lưu thông tin mô hình
    with open(os.path.join(output_dir, 'model_info.txt'), 'w', encoding='utf-8') as f:
        f.write(f"Train file: {train_file}\n")
        f.write(f"Train accuracy: {accuracy:.4f}\n")
        f.write(f"Model path: {ml_detector.model_path}\n")
    
    return ml_detector

def evaluate_model(ml_detector, test_file, output_dir):
    """Đánh giá mô hình ML trên tập test"""
    print(f"Đánh giá mô hình trên {test_file}...")
    
    # Đánh giá mô hình
    eval_results = ml_detector.evaluate(test_file)
    
    # Lưu kết quả
    os.makedirs(output_dir, exist_ok=True)
    
    # In kết quả
    print(f"Độ chính xác: {eval_results['accuracy']:.4f}")
    print(f"Precision: {eval_results['precision']:.4f}")
    print(f"Recall: {eval_results['recall']:.4f}")
    print(f"F1 Score: {eval_results['f1']:.4f}")
    
    # Lưu kết quả vào file
    with open(os.path.join(output_dir, 'evaluation_results.txt'), 'w', encoding='utf-8') as f:
        f.write(f"Test file: {test_file}\n")
        f.write(f"Accuracy: {eval_results['accuracy']:.4f}\n")
        f.write(f"Precision: {eval_results['precision']:.4f}\n")
        f.write(f"Recall: {eval_results['recall']:.4f}\n")
        f.write(f"F1 Score: {eval_results['f1']:.4f}\n")
        f.write(f"Confusion Matrix:\n{np.array(eval_results['confusion_matrix'])}\n")
    
    # Vẽ ma trận nhầm lẫn
    plt.figure(figsize=(8, 6))
    cm = np.array(eval_results['confusion_matrix'])
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
    plt.title('Confusion Matrix')
    plt.ylabel('Actual Label')
    plt.xlabel('Predicted Label')
    plt.savefig(os.path.join(output_dir, 'confusion_matrix.png'))
    
    # Vẽ feature importance nếu có
    try:
        feature_importance = ml_detector.get_feature_importance(top_n=20)
        
        # Vẽ biểu đồ feature importance
        plt.figure(figsize=(12, 8))
        
        # Trích xuất dữ liệu
        features = [item['feature'] for item in feature_importance['top_features']]
        importances = [item['importance'] for item in feature_importance['top_features']]
        
        # Sắp xếp theo tầm quan trọng tăng dần để vẽ từ dưới lên
        sorted_idx = np.argsort(importances)
        features = [features[i] for i in sorted_idx]
        importances = [importances[i] for i in sorted_idx]
        
        plt.barh(features, importances)
        plt.title('Top Feature Importance')
        plt.xlabel('Importance')
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, 'feature_importance.png'))
    except Exception as e:
        print(f"Không thể vẽ biểu đồ feature importance: {e}")
    
    return eval_results

from tqdm import tqdm

def compare_models(test_file, output_dir):
    """So sánh hiệu suất của các mô hình khác nhau"""
    print("So sánh các mô hình phát hiện SQL injection...")
    
    # Tạo thư mục kết quả
    os.makedirs(output_dir, exist_ok=True)
    
    # Đọc dữ liệu test
    test_df = pd.read_csv(test_file, encoding='utf-8')

    test_df = test_df.sample(min(1000, len(test_df)))

    queries = test_df['query'].tolist()
    true_labels = test_df['label'].tolist()
    
    # Khởi tạo các detector
    rule_detector = RuleBasedDetector()
    ml_detector = MLDetector()
    combined_detector = CombinedDetector()
    
    # Lưu các kết quả dự đoán
    rule_results = []
    ml_results = []
    combined_results = []
    
    # Dự đoán trên từng truy vấn
    for query in tqdm(queries, desc="Phân tích các truy vấn"):
        # Rule-based
        rule_result = rule_detector.detect(query)
        rule_results.append(rule_result)
        
        # ML-based
        ml_result = ml_detector.detect(query)
        ml_results.append(ml_result)
        
        # Combined
        combined_result = combined_detector.detect(query)
        #combined_results.append(combined_result)
        combined_results.append(combined_result.to_dict())
   
    # Tính các metrics
    def calculate_metrics(results, true_labels):
        # Xử lý cả 2 trường hợp: dict và DetectionResult
        preds = []
        scores = []
        for r in results:
            if isinstance(r, dict):
                preds.append(1 if r['is_sqli'] else 0)
                if 'confidence' in r:
                    scores.append(float(r['confidence']))
                elif 'ml_score' in r:
                    scores.append(float(r['ml_score']))
                elif 'rule_score' in r:
                    scores.append(float(r['rule_score']))
            else:  # Nếu là DetectionResult object
                preds.append(1 if r.is_sqli else 0)
                if 'confidence' in r:
                    scores.append(float(r.confidence))
                elif 'ml_score' in r:
                    scores.append(float(r['ml_score']))
                elif 'rule_score' in r:
                    scores.append(float(r['rule_score']))

        # Confusion matrix
        tn, fp, fn, tp = confusion_matrix(true_labels, preds).ravel()
        
        # Các metrics
        accuracy = (tp + tn) / (tp + tn + fp + fn)
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        
        roc_auc = 0
        pr_auc = 0
        fpr, tpr = [], []
        precision_curve, recall_curve = [], []
    
        if len(scores) > 0:
            fpr, tpr, _ = roc_curve(true_labels, scores)
            roc_auc = auc(fpr, tpr)
        
            precision_curve, recall_curve, _ = precision_recall_curve(true_labels, scores)
            pr_auc = auc(recall_curve, precision_curve)
    
        
        return {
            'accuracy': accuracy,
            'precision': precision, 
            'recall': recall,
            'f1': f1,
            'roc_auc': roc_auc,
            'pr_auc': pr_auc,
            'fpr': fpr,
            'tpr': tpr,
            'precision_curve': precision_curve,
            'recall_curve': recall_curve
        }
    
    # Tính metrics cho từng mô hình
    rule_metrics = calculate_metrics(rule_results, true_labels)
    ml_metrics = calculate_metrics(ml_results, true_labels)
    combined_metrics = calculate_metrics(combined_results, true_labels)
    
    # In so sánh
    print("Kết quả so sánh các mô hình:")
    print(f"{'Metric':<15} {'Rule-based':<15} {'ML-based':<15} {'Combined':<15}")
    print("-" * 60)
    for metric in ['accuracy', 'precision', 'recall', 'f1', 'roc_auc', 'pr_auc']:
        print(f"{metric:<15} {rule_metrics[metric]:<15.4f} {ml_metrics[metric]:<15.4f} {combined_metrics[metric]:<15.4f}")
    
    # Lưu kết quả vào file
    with open(os.path.join(output_dir, 'model_comparison.txt'), 'w', encoding='utf-8') as f:
        f.write("Kết quả so sánh các mô hình:\n")
        f.write(f"{'Metric':<15} {'Rule-based':<15} {'ML-based':<15} {'Combined':<15}\n")
        f.write("-" * 60 + "\n")
        for metric in ['accuracy', 'precision', 'recall', 'f1', 'roc_auc', 'pr_auc']:
            f.write(f"{metric:<15} {rule_metrics[metric]:<15.4f} {ml_metrics[metric]:<15.4f} {combined_metrics[metric]:<15.4f}\n")
    
    # Vẽ ROC curve
    plt.figure(figsize=(10, 8))
    plt.plot(rule_metrics['fpr'], rule_metrics['tpr'], label=f'Rule-based (AUC = {rule_metrics["roc_auc"]:.4f})')
    plt.plot(ml_metrics['fpr'], ml_metrics['tpr'], label=f'ML-based (AUC = {ml_metrics["roc_auc"]:.4f})')
    plt.plot(combined_metrics['fpr'], combined_metrics['tpr'], label=f'Combined (AUC = {combined_metrics["roc_auc"]:.4f})')
    plt.plot([0, 1], [0, 1], 'k--')
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title('ROC Curve')
    plt.legend()
    plt.grid(True)
    plt.savefig(os.path.join(output_dir, 'roc_curve.png'))
    
    # Vẽ PR curve
    plt.figure(figsize=(10, 8))
    plt.plot(rule_metrics['recall_curve'], rule_metrics['precision_curve'], label=f'Rule-based (AUC = {rule_metrics["pr_auc"]:.4f})')
    plt.plot(ml_metrics['recall_curve'], ml_metrics['precision_curve'], label=f'ML-based (AUC = {ml_metrics["pr_auc"]:.4f})')
    plt.plot(combined_metrics['recall_curve'], combined_metrics['precision_curve'], label=f'Combined (AUC = {combined_metrics["pr_auc"]:.4f})')
    plt.xlabel('Recall')
    plt.ylabel('Precision')
    plt.title('Precision-Recall Curve')
    plt.legend()
    plt.grid(True)
    plt.savefig(os.path.join(output_dir, 'pr_curve.png'))
    
    return {
        'rule': rule_metrics,
        'ml': ml_metrics,
        'combined': combined_metrics
    }

def tune_model_parameters(train_file, test_file, output_dir):
    """Tinh chỉnh tham số cho mô hình ML"""
    print("Tinh chỉnh tham số cho mô hình...")
    
    # Đọc dữ liệu train
    train_df = pd.read_csv(train_file)
    
    # Chuẩn bị dữ liệu
    from utils.data_processor import DataProcessor
    data_processor = DataProcessor()
    X_train_df, y_train = data_processor.prepare_features_from_df(
        train_df, query_column='query', label_column='label'
    )
    
    # Chia dữ liệu thành train và validation
    X_train, X_val, y_train, y_val = train_test_split(
        X_train_df, y_train, test_size=0.2, random_state=42
    )
    
    # Định nghĩa các tham số cần tìm
    param_grid = {
        'n_estimators': [50, 100, 200],
        'max_depth': [5, 10, 15, None],
        'min_samples_split': [2, 5, 10],
        'min_samples_leaf': [1, 2, 4],
        'class_weight': ['balanced', None]
    }
    
    # Grid search
    grid_search = GridSearchCV(
        RandomForestClassifier(random_state=42),
        param_grid=param_grid,
        cv=5,
        scoring='f1',
        n_jobs=-1,
        verbose=1
    )
    
    # Fit grid search
    grid_search.fit(X_train, y_train)
    
    # Lấy tham số tốt nhất
    best_params = grid_search.best_params_
    best_score = grid_search.best_score_
    
    print(f"Tham số tốt nhất: {best_params}")
    print(f"F1 score tốt nhất: {best_score:.4f}")
    
    # Lưu kết quả
    os.makedirs(output_dir, exist_ok=True)
    with open(os.path.join(output_dir, 'tuning_results.txt'), 'w', encoding='utf-8') as f:
        f.write(f"Best parameters: {best_params}\n")
        f.write(f"Best F1 score: {best_score:.4f}\n\n")
        f.write("Grid search results:\n")
        for i, params in enumerate(grid_search.cv_results_['params']):
            f.write(f"Parameters: {params}\n")
            f.write(f"Mean F1 score: {grid_search.cv_results_['mean_test_score'][i]:.4f}\n")
            f.write("-" * 50 + "\n")
    
    # Huấn luyện mô hình với tham số tốt nhất
    best_model = RandomForestClassifier(**best_params, random_state=42)
    best_model.fit(X_train_df, y_train)
    
    # Lưu mô hình tốt nhất
    best_model_path = os.path.join(output_dir, 'best_model.pkl')
    joblib.dump(best_model, best_model_path)
    
    return best_params, best_score

def main():
    args = parse_args()
    
    # Tạo thư mục đầu ra nếu chưa tồn tại
    os.makedirs(args.output_dir, exist_ok=True)
    
    if args.train:
        ml_detector = train_model(args.train_file, args.output_dir)
        
        if args.evaluate:
            evaluate_model(ml_detector, args.test_file, args.output_dir)
    
    elif args.evaluate:
        ml_detector = MLDetector()
        evaluate_model(ml_detector, args.test_file, args.output_dir)
    
    if args.compare:
        compare_models(args.test_file, args.output_dir)
    
    if args.tune:
        tune_model_parameters(args.train_file, args.test_file, args.output_dir)

if __name__ == "__main__":
    main()
