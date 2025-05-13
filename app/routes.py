# app/routes.py
from flask import Blueprint, request, jsonify
from utils.detector_combined import CombinedDetector
from app.models import DetectionResult, QueryLog
from utils.logger import Logger
import time
from flask import render_template

main_bp = Blueprint('main', __name__)
detector = CombinedDetector(logger=Logger())

@main_bp.route('/')
def index():
    return render_template('index.html')
    
@main_bp.route('/api/detect', methods=['POST'])
def detect_sqli():
    """Endpoint phát hiện SQL injection"""
    start_time = time.time()
    
    # Lấy dữ liệu từ request
    data = request.get_json()
    if not data or 'query' not in data:
        return jsonify({'error': 'Missing query parameter'}), 400
    
    query = data['query']
    ip_address = request.remote_addr
    
    # Phát hiện SQLi
    result = detector.detect(query)
    
    # Log kết quả
    Logger().log_detection(result, ip_address)
    
    # Trả về kết quả
    return jsonify({
        'success': True,
        'result': result.to_dict(),
        'execution_time_ms': result.execution_time
    })

@main_bp.route('/api/logs', methods=['GET'])
def get_logs():
    """Endpoint lấy lịch sử phát hiện"""
    limit = request.args.get('limit', default=50, type=int)
    logs = Logger().get_recent_logs(limit)
    return jsonify({'success': True, 'logs': logs})

@main_bp.route('/api/config', methods=['GET'])
def get_config():
    """Endpoint lấy cấu hình hiện tại"""
    config = detector.get_config()
    return jsonify({'success': True, 'config': config})

@main_bp.route('/api/adjust_thresholds', methods=['POST'])
def adjust_thresholds():
    """Endpoint điều chỉnh ngưỡng phát hiện"""
    data = request.get_json()
    try:
        detector.tune_thresholds(
            rule_threshold=data.get('rule_threshold'),
            ml_threshold=data.get('ml_threshold'),
            combined_threshold=data.get('combined_threshold')
        )
        return jsonify({'success': True, 'message': 'Thresholds updated'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@main_bp.route('/api/adjust_weights', methods=['POST'])
def adjust_weights():
    """Endpoint điều chỉnh trọng số"""
    data = request.get_json()
    try:
        detector.adjust_weights(
            rule_weight=data.get('rule_weight'),
            ml_weight=data.get('ml_weight')
        )
        return jsonify({'success': True, 'message': 'Weights updated'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@main_bp.route('/health', methods=['GET'])
def health_check():
    """Endpoint kiểm tra trạng thái service"""
    return jsonify({
        'status': 'healthy',
        'timestamp': time.strftime("%Y-%m-%d %H:%M:%S")
    })
