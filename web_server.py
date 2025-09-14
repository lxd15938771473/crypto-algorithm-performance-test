#!/usr/bin/env python3
"""
Web服务器 - 为前端提供API接口
提供RESTful API来执行密码算法性能测试
"""

import os
import sys
import json
import threading
import time
from pathlib import Path
from typing import Dict, Any
from flask import Flask, request, jsonify, send_from_directory, send_file
from flask_cors import CORS

# 添加src目录到Python路径
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from src.utils import SystemInfo, create_default_config, BenchmarkLogger
from src.benchmarks import BenchmarkRunner
from src.algorithms import (
    create_symmetric_cipher, 
    create_hash_function, 
    create_asymmetric_cipher
)

app = Flask(__name__)
CORS(app)  # 启用跨域支持

# 全局变量
current_benchmark = None
benchmark_thread = None
benchmark_results = {}
system_info = SystemInfo()

class WebBenchmarkRunner:
    """Web版基准测试运行器"""
    
    def __init__(self):
        self.is_running = False
        self.progress = 0
        self.current_test = ""
        self.results = {}
        self.logs = []
        
    def log(self, message: str):
        """添加日志"""
        timestamp = time.strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {message}"
        self.logs.append(log_entry)
        print(log_entry)  # 同时输出到控制台
        
    def run_quick_benchmark(self, settings: Dict[str, Any]):
        """运行快速基准测试"""
        self.is_running = True
        self.progress = 0
        self.results = {}
        self.logs = []
        
        try:
            algorithms = settings.get('algorithms', [])
            iterations = settings.get('iterations', 100)
            data_size = settings.get('dataSize', 65536)
            
            self.log(f"开始测试，算法: {', '.join(algorithms)}")
            self.log(f"设置: {iterations}次迭代, 数据大小: {data_size}字节")
            
            total_algorithms = len(algorithms)
            current_index = 0
            
            for algorithm in algorithms:
                if not self.is_running:
                    break
                    
                self.current_test = algorithm
                self.progress = (current_index / total_algorithms) * 100
                
                try:
                    result = self.test_single_algorithm(algorithm, iterations, data_size)
                    self.results[algorithm] = result
                    self.log(f"{algorithm.upper()} 测试完成: {result.get('performance', 0):.2f} {result.get('unit', '')}")
                    
                except Exception as e:
                    self.log(f"{algorithm.upper()} 测试失败: {str(e)}")
                    self.results[algorithm] = {'error': str(e)}
                
                current_index += 1
                self.progress = (current_index / total_algorithms) * 100
                time.sleep(0.5)  # 小延迟以显示进度
            
            self.log("所有测试完成!")
            
        except Exception as e:
            self.log(f"测试过程中发生错误: {str(e)}")
        finally:
            self.is_running = False
            self.current_test = ""
    
    def test_single_algorithm(self, algorithm: str, iterations: int, data_size: int) -> Dict[str, Any]:
        """测试单个算法"""
        test_data = b'A' * data_size
        
        # 确定算法类型
        symmetric_algorithms = ['aes', 'des', 'des3', 'chacha20']
        asymmetric_algorithms = ['rsa', 'ecc', 'ecdsa']
        hash_algorithms = ['sha256', 'sha512', 'md5', 'blake2b']
        
        if algorithm in symmetric_algorithms:
            return self.test_symmetric_algorithm(algorithm, test_data, iterations)
        elif algorithm in asymmetric_algorithms:
            return self.test_asymmetric_algorithm(algorithm, test_data, iterations)
        elif algorithm in hash_algorithms:
            return self.test_hash_algorithm(algorithm, test_data, iterations)
        else:
            raise ValueError(f"未知算法: {algorithm}")
    
    def test_symmetric_algorithm(self, algorithm: str, data: bytes, iterations: int) -> Dict[str, Any]:
        """测试对称加密算法"""
        try:
            cipher = create_symmetric_cipher(algorithm, 256 if algorithm == 'aes' else None, 'CBC')
            
            # 测试加密性能
            result = cipher.benchmark_encrypt(data, iterations)
            
            return {
                'category': '对称加密',
                'performance': result['throughput_mbps'],
                'unit': 'MB/s',
                'latency': result['latency_ms'],
                'operations_per_second': result['operations_per_second'],
                'iterations': iterations,
                'data_size': len(data)
            }
        except Exception as e:
            raise Exception(f"对称加密测试失败: {str(e)}")
    
    def test_asymmetric_algorithm(self, algorithm: str, data: bytes, iterations: int) -> Dict[str, Any]:
        """测试非对称加密算法"""
        try:
            if algorithm == 'rsa':
                cipher = create_asymmetric_cipher('rsa', key_size=2048)
            else:  # ecc, ecdsa
                cipher = create_asymmetric_cipher('ecc', curve='secp256r1')
            
            # 测试签名性能（非对称算法主要用于签名）
            result = cipher.benchmark_sign(data, min(iterations, 50))  # 减少迭代次数因为非对称算法较慢
            
            return {
                'category': '非对称加密',
                'performance': result['operations_per_second'],
                'unit': 'ops/sec',
                'latency': result['latency_ms'],
                'operations_per_second': result['operations_per_second'],
                'iterations': result['successful_operations'],
                'data_size': len(data)
            }
        except Exception as e:
            raise Exception(f"非对称加密测试失败: {str(e)}")
    
    def test_hash_algorithm(self, algorithm: str, data: bytes, iterations: int) -> Dict[str, Any]:
        """测试哈希算法"""
        try:
            hash_func = create_hash_function(algorithm)
            
            # 测试哈希性能
            result = hash_func.benchmark(data, iterations)
            
            return {
                'category': '哈希算法',
                'performance': result['throughput_mbps'],
                'unit': 'MB/s',
                'latency': result['latency_ms'],
                'operations_per_second': result['operations_per_second'],
                'iterations': iterations,
                'data_size': len(data)
            }
        except Exception as e:
            raise Exception(f"哈希算法测试失败: {str(e)}")
    
    def stop(self):
        """停止测试"""
        self.is_running = False
        self.log("测试被用户停止")

# 全局基准测试运行器实例
web_runner = WebBenchmarkRunner()

@app.route('/')
def index():
    """首页 - 返回Web界面"""
    return send_from_directory('web', 'index.html')

@app.route('/web/<path:filename>')
def web_static(filename):
    """提供Web静态文件"""
    return send_from_directory('web', filename)

@app.route('/api/system-info', methods=['GET'])
def get_system_info():
    """获取系统信息API"""
    try:
        info = {
            'cpu': system_info.get_cpu_info(),
            'memory': system_info.get_memory_info(),
            'python': system_info.get_python_version(),
            'platform': system_info.get_platform_info(),
            'current_cpu_usage': system_info.get_current_cpu_usage(),
            'current_memory_usage': system_info.get_current_memory_usage()
        }
        return jsonify(info)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/benchmark', methods=['POST'])
def start_benchmark():
    """开始基准测试API"""
    global benchmark_thread
    
    try:
        if web_runner.is_running:
            return jsonify({'error': '测试正在运行中'}), 400
        
        settings = request.json
        if not settings or not settings.get('algorithms'):
            return jsonify({'error': '请选择至少一个算法'}), 400
        
        # 在新线程中运行测试
        benchmark_thread = threading.Thread(
            target=web_runner.run_quick_benchmark, 
            args=(settings,)
        )
        benchmark_thread.start()
        
        return jsonify({
            'status': 'started',
            'message': '基准测试已开始'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/benchmark/status', methods=['GET'])
def get_benchmark_status():
    """获取基准测试状态API"""
    return jsonify({
        'is_running': web_runner.is_running,
        'progress': web_runner.progress,
        'current_test': web_runner.current_test,
        'logs': web_runner.logs[-10:] if len(web_runner.logs) > 10 else web_runner.logs  # 只返回最近10条日志
    })

@app.route('/api/benchmark/results', methods=['GET'])
def get_benchmark_results():
    """获取基准测试结果API"""
    return jsonify({
        'results': web_runner.results,
        'is_running': web_runner.is_running,
        'logs': web_runner.logs
    })

@app.route('/api/benchmark/stop', methods=['POST'])
def stop_benchmark():
    """停止基准测试API"""
    try:
        web_runner.stop()
        return jsonify({
            'status': 'stopped',
            'message': '基准测试已停止'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/benchmark/clear', methods=['POST'])
def clear_results():
    """清除结果API"""
    try:
        if web_runner.is_running:
            return jsonify({'error': '测试正在运行中，无法清除结果'}), 400
        
        web_runner.results = {}
        web_runner.logs = []
        web_runner.progress = 0
        
        return jsonify({
            'status': 'cleared',
            'message': '结果已清除'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/export', methods=['POST'])
def export_results():
    """导出结果API"""
    try:
        if not web_runner.results:
            return jsonify({'error': '没有可导出的结果'}), 400
        
        # 创建导出数据
        export_data = {
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'system_info': {
                'cpu': system_info.get_cpu_info(),
                'memory': system_info.get_memory_info(),
                'python': system_info.get_python_version(),
                'platform': system_info.get_platform_info()
            },
            'results': web_runner.results,
            'logs': web_runner.logs,
            'summary': {
                'total_tests': len(web_runner.results),
                'successful_tests': len([r for r in web_runner.results.values() if 'error' not in r]),
                'failed_tests': len([r for r in web_runner.results.values() if 'error' in r])
            }
        }
        
        # 保存到临时文件
        output_dir = Path('web_results')
        output_dir.mkdir(exist_ok=True)
        
        filename = f'crypto_benchmark_{int(time.time())}.json'
        filepath = output_dir / filename
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)
        
        return send_file(filepath, as_attachment=True, download_name=filename)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/algorithms', methods=['GET'])
def get_supported_algorithms():
    """获取支持的算法列表API"""
    algorithms = {
        'symmetric': [
            {'id': 'aes', 'name': 'AES', 'description': 'Advanced Encryption Standard'},
            {'id': 'des', 'name': 'DES', 'description': 'Data Encryption Standard'},
            {'id': 'des3', 'name': '3DES', 'description': 'Triple DES'},
            {'id': 'chacha20', 'name': 'ChaCha20', 'description': 'ChaCha20 Stream Cipher'}
        ],
        'asymmetric': [
            {'id': 'rsa', 'name': 'RSA', 'description': 'RSA Public Key Cryptography'},
            {'id': 'ecc', 'name': 'ECC', 'description': 'Elliptic Curve Cryptography'},
            {'id': 'ecdsa', 'name': 'ECDSA', 'description': 'Elliptic Curve Digital Signature Algorithm'}
        ],
        'hash': [
            {'id': 'sha256', 'name': 'SHA-256', 'description': 'Secure Hash Algorithm 256-bit'},
            {'id': 'sha512', 'name': 'SHA-512', 'description': 'Secure Hash Algorithm 512-bit'},
            {'id': 'md5', 'name': 'MD5', 'description': 'Message Digest Algorithm 5'},
            {'id': 'blake2b', 'name': 'BLAKE2b', 'description': 'BLAKE2b Hash Function'}
        ]
    }
    
    return jsonify(algorithms)

@app.route('/api/test-single', methods=['POST'])
def test_single_algorithm():
    """测试单个算法API（用于快速测试）"""
    try:
        data = request.json
        algorithm = data.get('algorithm')
        iterations = data.get('iterations', 100)
        data_size = data.get('dataSize', 65536)
        
        if not algorithm:
            return jsonify({'error': '请指定算法'}), 400
        
        if web_runner.is_running:
            return jsonify({'error': '另一个测试正在运行中'}), 400
        
        # 运行单个算法测试
        result = web_runner.test_single_algorithm(algorithm, iterations, data_size)
        
        return jsonify({
            'algorithm': algorithm,
            'result': result
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.errorhandler(404)
def not_found(error):
    """404错误处理"""
    return jsonify({'error': 'API端点未找到'}), 404

@app.errorhandler(500)
def internal_error(error):
    """500错误处理"""
    return jsonify({'error': '服务器内部错误'}), 500

def create_sample_config():
    """创建示例配置文件"""
    config_dir = Path('web_config')
    config_dir.mkdir(exist_ok=True)
    
    sample_config = {
        'host': '127.0.0.1',
        'port': 5000,
        'debug': False,
        'max_iterations': 10000,
        'max_data_size': 10485760,  # 10MB
        'allowed_algorithms': [
            'aes', 'des', 'des3', 'chacha20',
            'rsa', 'ecc', 'ecdsa',
            'sha256', 'sha512', 'md5', 'blake2b'
        ]
    }
    
    config_file = config_dir / 'server_config.json'
    if not config_file.exists():
        with open(config_file, 'w', encoding='utf-8') as f:
            json.dump(sample_config, f, indent=2, ensure_ascii=False)
        print(f"创建示例配置文件: {config_file}")

def main():
    """主函数"""
    print("=" * 60)
    print("密码算法性能测试工具 - Web服务器")
    print("=" * 60)
    
    # 创建必要的目录
    Path('web_results').mkdir(exist_ok=True)
    create_sample_config()
    
    # 显示系统信息
    print("\n系统信息:")
    print(f"CPU: {system_info.get_cpu_info()}")
    print(f"内存: {system_info.get_memory_info()}")
    print(f"Python: {system_info.get_python_version()}")
    print(f"平台: {system_info.get_platform_info()}")
    
    # 启动Web服务器
    host = '127.0.0.1'
    port = 5000
    
    print(f"\n🚀 启动Web服务器...")
    print(f"📱 Web界面: http://{host}:{port}")
    print(f"🔌 API接口: http://{host}:{port}/api")
    print(f"\n💡 使用提示:")
    print(f"  - 在浏览器中打开 http://{host}:{port} 使用Web界面")
    print(f"  - 或者直接调用API接口进行自动化测试")
    print(f"  - 按 Ctrl+C 停止服务器")
    print("=" * 60)
    
    try:
        app.run(host=host, port=port, debug=False, threaded=True)
    except KeyboardInterrupt:
        print("\n\n⚠️  服务器被用户停止")
    except Exception as e:
        print(f"\n❌ 服务器启动失败: {e}")

if __name__ == '__main__':
    main()
