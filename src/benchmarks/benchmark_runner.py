"""
基准测试运行器
统一管理和执行各种密码算法的性能测试
"""

import json
import csv
import time
import threading
from pathlib import Path
from typing import Dict, Any, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import psutil

from ..utils.logger import BenchmarkLogger
from ..utils.config import BenchmarkConfig
from ..algorithms import (
    create_symmetric_cipher, 
    create_asymmetric_cipher,
    create_hash_function,
    HashBenchmarkSuite,
    AsymmetricBenchmarkSuite
)


class SystemMonitor:
    """系统性能监控器"""
    
    def __init__(self, sample_interval: float = 0.1):
        self.sample_interval = sample_interval
        self.monitoring = False
        self.cpu_samples = []
        self.memory_samples = []
        self.monitor_thread = None
    
    def start_monitoring(self):
        """开始监控"""
        if self.monitoring:
            return
        
        self.monitoring = True
        self.cpu_samples = []
        self.memory_samples = []
        self.monitor_thread = threading.Thread(target=self._monitor_loop)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
    
    def stop_monitoring(self):
        """停止监控"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=1.0)
    
    def _monitor_loop(self):
        """监控循环"""
        while self.monitoring:
            try:
                cpu_percent = psutil.cpu_percent(interval=None)
                memory_info = psutil.virtual_memory()
                
                self.cpu_samples.append(cpu_percent)
                self.memory_samples.append({
                    'percent': memory_info.percent,
                    'available_gb': memory_info.available / (1024**3),
                    'used_gb': memory_info.used / (1024**3)
                })
                
                time.sleep(self.sample_interval)
            except Exception:
                pass
    
    def get_summary(self) -> Dict[str, Any]:
        """获取监控摘要"""
        if not self.cpu_samples or not self.memory_samples:
            return {}
        
        cpu_avg = sum(self.cpu_samples) / len(self.cpu_samples)
        cpu_max = max(self.cpu_samples)
        
        memory_percents = [m['percent'] for m in self.memory_samples]
        memory_avg = sum(memory_percents) / len(memory_percents)
        memory_max = max(memory_percents)
        
        return {
            'cpu_usage': {
                'average': cpu_avg,
                'maximum': cpu_max,
                'samples': len(self.cpu_samples)
            },
            'memory_usage': {
                'average_percent': memory_avg,
                'maximum_percent': memory_max,
                'samples': len(self.memory_samples)
            }
        }


class BenchmarkRunner:
    """基准测试运行器"""
    
    def __init__(self, config: BenchmarkConfig, output_dir: Path, output_format: str = 'json'):
        self.config = config
        self.output_dir = Path(output_dir)
        self.output_format = output_format
        
        # 创建输出目录
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # 设置日志记录器
        self.logger = BenchmarkLogger(self.output_dir, verbose=True)
        
        # 初始化监控器
        if self.config.monitoring.enabled:
            self.monitor = SystemMonitor(self.config.monitoring.sample_interval)
        else:
            self.monitor = None
        
        # 测试结果存储
        self.results = {}
    
    def run_all_benchmarks(self) -> Dict[str, Any]:
        """运行所有基准测试"""
        self.logger.info("开始运行所有基准测试")
        start_time = time.time()
        
        # 开始系统监控
        if self.monitor:
            self.monitor.start_monitoring()
        
        try:
            # 运行对称加密测试
            if any(alg.enabled for alg in self.config.symmetric_algorithms.values()):
                self.logger.info("运行对称加密算法测试")
                self.results['symmetric'] = self._run_symmetric_benchmarks()
            
            # 运行非对称加密测试
            if any(alg.enabled for alg in self.config.asymmetric_algorithms.values()):
                self.logger.info("运行非对称加密算法测试")
                self.results['asymmetric'] = self._run_asymmetric_benchmarks()
            
            # 运行哈希算法测试
            if any(alg.enabled for alg in self.config.hash_algorithms.values()):
                self.logger.info("运行哈希算法测试")
                self.results['hash'] = self._run_hash_benchmarks()
            
            # 如果启用多线程测试
            if self.config.threading.enabled:
                self.logger.info("运行多线程性能测试")
                self.results['threading'] = self._run_threading_benchmarks()
        
        finally:
            # 停止监控
            if self.monitor:
                self.monitor.stop_monitoring()
                self.results['system_monitoring'] = self.monitor.get_summary()
        
        end_time = time.time()
        self.results['benchmark_info'] = {
            'total_time': end_time - start_time,
            'timestamp': time.time(),
            'config_summary': self._get_config_summary()
        }
        
        # 保存结果
        self._save_results(self.results)
        
        self.logger.info(f"所有基准测试完成，总耗时: {end_time - start_time:.2f} 秒")
        return self.results
    
    def run_selected_benchmarks(self, algorithm_names: List[str]) -> Dict[str, Any]:
        """运行指定的算法测试"""
        self.logger.info(f"运行指定算法测试: {algorithm_names}")
        
        # 开始系统监控
        if self.monitor:
            self.monitor.start_monitoring()
        
        try:
            for alg_name in algorithm_names:
                alg_name_lower = alg_name.lower()
                
                # 对称加密算法
                if alg_name_lower in [name.lower() for name in self.config.symmetric_algorithms.keys()]:
                    if 'symmetric' not in self.results:
                        self.results['symmetric'] = {}
                    self.results['symmetric'][alg_name] = self._test_single_symmetric_algorithm(alg_name)
                
                # 非对称加密算法
                elif alg_name_lower in [name.lower() for name in self.config.asymmetric_algorithms.keys()]:
                    if 'asymmetric' not in self.results:
                        self.results['asymmetric'] = {}
                    self.results['asymmetric'][alg_name] = self._test_single_asymmetric_algorithm(alg_name)
                
                # 哈希算法
                elif alg_name_lower in [name.lower() for name in self.config.hash_algorithms.keys()]:
                    if 'hash' not in self.results:
                        self.results['hash'] = {}
                    self.results['hash'][alg_name] = self._test_single_hash_algorithm(alg_name)
                
                else:
                    self.logger.warning(f"未知算法: {alg_name}")
        
        finally:
            if self.monitor:
                self.monitor.stop_monitoring()
                self.results['system_monitoring'] = self.monitor.get_summary()
        
        # 保存结果
        self._save_results(self.results)
        return self.results
    
    def _run_symmetric_benchmarks(self) -> Dict[str, Any]:
        """运行对称加密基准测试"""
        results = {}
        
        for alg_name, alg_config in self.config.symmetric_algorithms.items():
            if not alg_config.enabled:
                continue
            
            self.logger.log_test_start(alg_name, "symmetric_encryption")
            
            try:
                results[alg_name] = self._test_single_symmetric_algorithm(alg_name)
                self.logger.info(f"{alg_name} 对称加密测试完成")
            except Exception as e:
                self.logger.log_error(alg_name, "symmetric_encryption", e)
                results[alg_name] = {'error': str(e)}
        
        return results
    
    def _test_single_symmetric_algorithm(self, alg_name: str) -> Dict[str, Any]:
        """测试单个对称加密算法"""
        alg_config = self.config.symmetric_algorithms[alg_name]
        results = {}
        
        for key_size in alg_config.key_sizes:
            for mode in alg_config.modes:
                test_key = f"{key_size}_{mode}"
                results[test_key] = {}
                
                try:
                    cipher = create_symmetric_cipher(alg_name, key_size, mode)
                    
                    for data_size in self.config.test_settings.data_sizes:
                        test_data = b'A' * data_size
                        
                        # 加密性能测试
                        encrypt_result = cipher.benchmark_encrypt(
                            test_data, self.config.test_settings.iterations
                        )
                        
                        # 解密性能测试  
                        decrypt_result = cipher.benchmark_decrypt(
                            test_data, self.config.test_settings.iterations
                        )
                        
                        results[test_key][f'{data_size}_bytes'] = {
                            'encrypt': encrypt_result,
                            'decrypt': decrypt_result
                        }
                        
                        self.logger.log_test_result(
                            f"{alg_name}-{key_size}-{mode}",
                            f"encrypt_{data_size}bytes",
                            encrypt_result
                        )
                
                except Exception as e:
                    self.logger.log_error(f"{alg_name}-{key_size}-{mode}", "test", e)
                    results[test_key] = {'error': str(e)}
        
        return results
    
    def _run_asymmetric_benchmarks(self) -> Dict[str, Any]:
        """运行非对称加密基准测试"""
        suite = AsymmetricBenchmarkSuite()
        results = {}
        
        # RSA测试
        if 'rsa' in self.config.asymmetric_algorithms and self.config.asymmetric_algorithms['rsa'].enabled:
            rsa_config = self.config.asymmetric_algorithms['rsa']
            self.logger.info("开始RSA基准测试")
            
            results['rsa'] = suite.benchmark_rsa_keysizes(
                key_sizes=rsa_config.key_sizes,
                data_size=1000,
                iterations=self.config.test_settings.iterations // 10  # RSA较慢，减少迭代次数
            )
        
        # ECC测试
        if any(name in self.config.asymmetric_algorithms for name in ['ecc', 'ecdsa']):
            curves = []
            for name in ['ecc', 'ecdsa']:
                if name in self.config.asymmetric_algorithms and self.config.asymmetric_algorithms[name].enabled:
                    curves.extend(self.config.asymmetric_algorithms[name].curves)
            
            if curves:
                self.logger.info("开始ECC/ECDSA基准测试")
                results['ecc'] = suite.benchmark_ecc_curves(
                    curves=list(set(curves)),  # 去重
                    data_size=1000,
                    iterations=self.config.test_settings.iterations // 5
                )
        
        return results
    
    def _run_hash_benchmarks(self) -> Dict[str, Any]:
        """运行哈希算法基准测试"""
        results = {}
        
        for alg_name, alg_config in self.config.hash_algorithms.items():
            if not alg_config.enabled:
                continue
            
            self.logger.log_test_start(alg_name, "hash")
            
            try:
                results[alg_name] = self._test_single_hash_algorithm(alg_name)
                self.logger.info(f"{alg_name} 哈希测试完成")
            except Exception as e:
                self.logger.log_error(alg_name, "hash", e)
                results[alg_name] = {'error': str(e)}
        
        return results
    
    def _test_single_hash_algorithm(self, alg_name: str) -> Dict[str, Any]:
        """测试单个哈希算法"""
        results = {}
        
        try:
            hash_func = create_hash_function(alg_name)
            
            for data_size in self.config.test_settings.data_sizes:
                test_data = b'A' * data_size
                
                benchmark_result = hash_func.benchmark(
                    test_data, self.config.test_settings.iterations
                )
                
                results[f'{data_size}_bytes'] = benchmark_result
                
                self.logger.log_test_result(
                    alg_name,
                    f"hash_{data_size}bytes",
                    benchmark_result
                )
        
        except Exception as e:
            self.logger.log_error(alg_name, "hash", e)
            results = {'error': str(e)}
        
        return results
    
    def _test_single_asymmetric_algorithm(self, alg_name: str) -> Dict[str, Any]:
        """测试单个非对称加密算法"""
        alg_config = self.config.asymmetric_algorithms[alg_name]
        results = {}
        
        try:
            if alg_name.lower() == 'rsa':
                for key_size in alg_config.key_sizes:
                    cipher = create_asymmetric_cipher('rsa', key_size=key_size)
                    
                    # 测试数据
                    test_data = b'A' * 100  # RSA加密数据大小限制
                    
                    # 签名测试
                    sign_result = cipher.benchmark_sign(test_data, self.config.test_settings.iterations // 10)
                    verify_result = cipher.benchmark_verify(test_data, self.config.test_settings.iterations // 5)
                    
                    results[f'rsa_{key_size}'] = {
                        'sign': sign_result,
                        'verify': verify_result
                    }
            
            elif alg_name.lower() in ['ecc', 'ecdsa']:
                for curve in alg_config.curves:
                    cipher = create_asymmetric_cipher('ecc', curve=curve)
                    
                    test_data = b'A' * 1000
                    
                    sign_result = cipher.benchmark_sign(test_data, self.config.test_settings.iterations // 5)
                    verify_result = cipher.benchmark_verify(test_data, self.config.test_settings.iterations // 2)
                    
                    results[f'ecc_{curve}'] = {
                        'sign': sign_result,
                        'verify': verify_result
                    }
        
        except Exception as e:
            self.logger.log_error(alg_name, "asymmetric", e)
            results = {'error': str(e)}
        
        return results
    
    def _run_threading_benchmarks(self) -> Dict[str, Any]:
        """运行多线程性能测试"""
        results = {}
        
        # 选择一个快速的算法进行多线程测试
        test_data = b'A' * 65536  # 64KB
        
        for thread_count in self.config.threading.thread_counts:
            self.logger.info(f"测试 {thread_count} 线程性能")
            
            try:
                # 测试SHA256哈希的多线程性能
                results[f'{thread_count}_threads'] = self._benchmark_multithreaded_hash(
                    'sha256', test_data, thread_count, self.config.test_settings.iterations
                )
                
            except Exception as e:
                self.logger.error(f"{thread_count} 线程测试失败: {e}")
                results[f'{thread_count}_threads'] = {'error': str(e)}
        
        return results
    
    def _benchmark_multithreaded_hash(self, algorithm: str, data: bytes, 
                                    thread_count: int, iterations: int) -> Dict[str, Any]:
        """多线程哈希基准测试"""
        def worker(worker_iterations):
            hash_func = create_hash_function(algorithm)
            for _ in range(worker_iterations):
                hash_func.hash(data)
        
        iterations_per_thread = iterations // thread_count
        
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=thread_count) as executor:
            futures = [executor.submit(worker, iterations_per_thread) for _ in range(thread_count)]
            
            for future in as_completed(futures):
                future.result()  # 等待完成
        
        end_time = time.time()
        total_time = end_time - start_time
        
        total_operations = thread_count * iterations_per_thread
        throughput = (len(data) * total_operations) / (total_time * 1024 * 1024)  # MB/s
        ops_per_second = total_operations / total_time
        
        return {
            'algorithm': algorithm,
            'thread_count': thread_count,
            'total_operations': total_operations,
            'total_time': total_time,
            'throughput_mbps': throughput,
            'operations_per_second': ops_per_second,
            'data_size': len(data)
        }
    
    def _save_results(self, results: Dict[str, Any]):
        """保存测试结果"""
        timestamp = int(time.time())
        
        if self.output_format == 'json':
            filename = f"benchmark_results_{timestamp}.json"
            filepath = self.output_dir / filename
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"结果已保存到: {filepath}")
        
        elif self.output_format == 'csv':
            filename = f"benchmark_results_{timestamp}.csv"
            filepath = self.output_dir / filename
            
            # 将结果展平为CSV格式
            csv_data = self._flatten_results_for_csv(results)
            
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                if csv_data:
                    writer = csv.DictWriter(f, fieldnames=csv_data[0].keys())
                    writer.writeheader()
                    writer.writerows(csv_data)
            
            self.logger.info(f"CSV结果已保存到: {filepath}")
        
        # 同时保存原始JSON数据
        if self.config.output.save_raw_data and self.output_format != 'json':
            raw_filename = f"raw_results_{timestamp}.json"
            raw_filepath = self.output_dir / raw_filename
            
            with open(raw_filepath, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
    
    def _flatten_results_for_csv(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """将嵌套的结果展平为CSV格式"""
        csv_rows = []
        
        for category, category_results in results.items():
            if category in ['benchmark_info', 'system_monitoring']:
                continue
            
            if isinstance(category_results, dict):
                for algorithm, alg_results in category_results.items():
                    if isinstance(alg_results, dict) and 'error' not in alg_results:
                        for test_config, test_results in alg_results.items():
                            if isinstance(test_results, dict):
                                row = {
                                    'category': category,
                                    'algorithm': algorithm,
                                    'test_config': test_config
                                }
                                
                                # 递归展平嵌套数据
                                self._flatten_dict(test_results, row, '')
                                csv_rows.append(row)
        
        return csv_rows
    
    def _flatten_dict(self, data: Dict[str, Any], row: Dict[str, Any], prefix: str):
        """递归展平字典"""
        for key, value in data.items():
            new_key = f"{prefix}_{key}" if prefix else key
            
            if isinstance(value, dict):
                self._flatten_dict(value, row, new_key)
            else:
                row[new_key] = value
    
    def _get_config_summary(self) -> Dict[str, Any]:
        """获取配置摘要"""
        return {
            'data_sizes': self.config.test_settings.data_sizes,
            'iterations': self.config.test_settings.iterations,
            'warmup_rounds': self.config.test_settings.warmup_rounds,
            'enabled_symmetric': [name for name, config in self.config.symmetric_algorithms.items() if config.enabled],
            'enabled_asymmetric': [name for name, config in self.config.asymmetric_algorithms.items() if config.enabled],
            'enabled_hash': [name for name, config in self.config.hash_algorithms.items() if config.enabled],
            'threading_enabled': self.config.threading.enabled,
            'monitoring_enabled': self.config.monitoring.enabled
        }
    
    def print_summary(self, results: Dict[str, Any]):
        """打印测试结果摘要"""
        self.logger.info("=" * 60)
        self.logger.info("基准测试结果摘要")
        self.logger.info("=" * 60)
        
        if 'benchmark_info' in results:
            info = results['benchmark_info']
            self.logger.info(f"总测试时间: {info['total_time']:.2f} 秒")
        
        # 显示最佳性能结果
        best_performers = self._find_best_performers(results)
        if best_performers:
            self.logger.info("\n性能最佳算法:")
            for category, winner in best_performers.items():
                self.logger.info(f"  {category}: {winner}")
        
        # 显示系统资源使用情况
        if 'system_monitoring' in results and results['system_monitoring']:
            monitoring = results['system_monitoring']
            if 'cpu_usage' in monitoring:
                cpu = monitoring['cpu_usage']
                self.logger.info(f"\nCPU使用率 - 平均: {cpu['average']:.1f}%, 峰值: {cpu['maximum']:.1f}%")
            
            if 'memory_usage' in monitoring:
                mem = monitoring['memory_usage']
                self.logger.info(f"内存使用率 - 平均: {mem['average_percent']:.1f}%, 峰值: {mem['maximum_percent']:.1f}%")
        
        self.logger.info("=" * 60)
    
    def _find_best_performers(self, results: Dict[str, Any]) -> Dict[str, str]:
        """找出各类别中性能最佳的算法"""
        best_performers = {}
        
        # 分析对称加密
        if 'symmetric' in results:
            best_symmetric = self._find_best_symmetric(results['symmetric'])
            if best_symmetric:
                best_performers['对称加密'] = best_symmetric
        
        # 分析哈希算法
        if 'hash' in results:
            best_hash = self._find_best_hash(results['hash'])
            if best_hash:
                best_performers['哈希算法'] = best_hash
        
        return best_performers
    
    def _find_best_symmetric(self, symmetric_results: Dict[str, Any]) -> Optional[str]:
        """找出最佳对称加密算法"""
        best_alg = None
        best_throughput = 0
        
        for alg_name, alg_results in symmetric_results.items():
            if isinstance(alg_results, dict) and 'error' not in alg_results:
                for config, config_results in alg_results.items():
                    if isinstance(config_results, dict):
                        for size_test, size_results in config_results.items():
                            if isinstance(size_results, dict) and 'encrypt' in size_results:
                                throughput = size_results['encrypt'].get('throughput_mbps', 0)
                                if throughput > best_throughput:
                                    best_throughput = throughput
                                    best_alg = f"{alg_name}-{config} ({throughput:.1f} MB/s)"
        
        return best_alg
    
    def _find_best_hash(self, hash_results: Dict[str, Any]) -> Optional[str]:
        """找出最佳哈希算法"""
        best_alg = None
        best_throughput = 0
        
        for alg_name, alg_results in hash_results.items():
            if isinstance(alg_results, dict) and 'error' not in alg_results:
                for size_test, size_result in alg_results.items():
                    if isinstance(size_result, dict):
                        throughput = size_result.get('throughput_mbps', 0)
                        if throughput > best_throughput:
                            best_throughput = throughput
                            best_alg = f"{alg_name} ({throughput:.1f} MB/s)"
        
        return best_alg


if __name__ == "__main__":
    # 测试代码
    from ..utils.config import create_default_config
    
    config = create_default_config()
    output_dir = Path("./test_results")
    
    runner = BenchmarkRunner(config, output_dir)
    
    # 运行一个简单的测试
    results = runner.run_selected_benchmarks(['aes', 'sha256'])
    print("测试完成!")
