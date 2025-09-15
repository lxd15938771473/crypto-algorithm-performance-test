#!/usr/bin/env python3
"""
简化版Web服务器 - 用于故障排查
"""

from flask import Flask, send_from_directory, jsonify, request
from flask_cors import CORS
import time
import threading

app = Flask(__name__)
CORS(app)

# 简单的全局状态
test_running = False
test_results = {}

@app.route('/')
def index():
    return send_from_directory('web', 'index.html')

@app.route('/web/<path:filename>')
def web_static(filename):
    return send_from_directory('web', filename)

@app.route('/api/system-info', methods=['GET'])
def system_info():
    return jsonify({
        'cpu': 'Test CPU (4核/8线程)',
        'memory': '16.0 GB',
        'python': 'Python 3.9.0',
        'platform': 'Test System'
    })

@app.route('/api/benchmark', methods=['POST'])
def start_test():
    global test_running, test_results
    
    if test_running:
        return jsonify({'error': '测试正在运行中'}), 400
    
    data = request.json
    algorithms = data.get('algorithms', [])
    
    if not algorithms:
        return jsonify({'error': '请选择至少一个算法'}), 400
    
    # 模拟测试
    test_running = True
    thread = threading.Thread(target=run_mock_test, args=(algorithms,))
    thread.start()
    
    return jsonify({'status': 'started', 'message': '测试已开始'})

def run_mock_test(algorithms):
    global test_running, test_results
    
    test_results = {}
    
    for i, algorithm in enumerate(algorithms):
        if not test_running:
            break
            
        time.sleep(2)  # 模拟测试时间
        
        # 生成模拟结果
        test_results[algorithm] = {
            'performance': 150.0 + i * 20,
            'unit': 'MB/s',
            'latency': 6.67,
            'category': '测试算法'
        }
    
    test_running = False

@app.route('/api/benchmark/status', methods=['GET'])
def get_status():
    return jsonify({
        'is_running': test_running,
        'progress': 50 if test_running else 100,
        'current_test': 'test_algorithm' if test_running else '',
        'logs': ['测试日志示例']
    })

@app.route('/api/benchmark/results', methods=['GET'])
def get_results():
    return jsonify({
        'results': test_results,
        'is_running': test_running,
        'logs': ['测试完成']
    })

@app.route('/api/benchmark/stop', methods=['POST'])
def stop_test():
    global test_running
    test_running = False
    return jsonify({'status': 'stopped'})

if __name__ == '__main__':
    print("=" * 50)
    print("简化版Web服务器启动中...")
    print("访问: http://127.0.0.1:5000")
    print("这是一个用于故障排查的简化版本")
    print("=" * 50)
    
    app.run(host='127.0.0.1', port=5000, debug=True)
