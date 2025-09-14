"""
哈希算法实现
支持SHA-256, SHA-512, SHA-1, MD5, Blake2b, Blake2s等算法
"""

import time
import hashlib
from typing import Dict, Any
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from ..utils.logger import get_logger


class HashFunction:
    """哈希函数基类"""
    
    def __init__(self, algorithm: str):
        self.algorithm = algorithm.upper()
        self.logger = get_logger()
    
    def hash(self, data: bytes) -> bytes:
        """计算哈希值"""
        raise NotImplementedError
    
    def hash_hex(self, data: bytes) -> str:
        """计算哈希值并返回十六进制字符串"""
        return self.hash(data).hex()
    
    def benchmark(self, data: bytes, iterations: int = 1000) -> Dict[str, Any]:
        """基准测试哈希性能"""
        # 预热
        for _ in range(10):
            self.hash(data[:min(1024, len(data))])
        
        # 正式测试
        start_time = time.time()
        for _ in range(iterations):
            self.hash(data)
        end_time = time.time()
        
        total_time = end_time - start_time
        throughput = (len(data) * iterations) / (total_time * 1024 * 1024)  # MB/s
        latency = (total_time * 1000) / iterations  # ms per operation
        ops_per_second = iterations / total_time
        
        return {
            'algorithm': self.algorithm,
            'throughput_mbps': throughput,
            'latency_ms': latency,
            'operations_per_second': ops_per_second,
            'total_time': total_time,
            'data_size': len(data),
            'iterations': iterations,
            'hash_size': len(self.hash(b'test'))
        }
    
    def get_digest_size(self) -> int:
        """获取哈希摘要长度"""
        return len(self.hash(b''))


class SHA256Hash(HashFunction):
    """SHA-256哈希函数"""
    
    def __init__(self):
        super().__init__('SHA256')
    
    def hash(self, data: bytes) -> bytes:
        """计算SHA-256哈希"""
        try:
            return hashlib.sha256(data).digest()
        except Exception as e:
            self.logger.error(f"SHA-256哈希计算失败: {e}")
            raise


class SHA512Hash(HashFunction):
    """SHA-512哈希函数"""
    
    def __init__(self):
        super().__init__('SHA512')
    
    def hash(self, data: bytes) -> bytes:
        """计算SHA-512哈希"""
        try:
            return hashlib.sha512(data).digest()
        except Exception as e:
            self.logger.error(f"SHA-512哈希计算失败: {e}")
            raise


class SHA1Hash(HashFunction):
    """SHA-1哈希函数"""
    
    def __init__(self):
        super().__init__('SHA1')
    
    def hash(self, data: bytes) -> bytes:
        """计算SHA-1哈希"""
        try:
            return hashlib.sha1(data).digest()
        except Exception as e:
            self.logger.error(f"SHA-1哈希计算失败: {e}")
            raise


class MD5Hash(HashFunction):
    """MD5哈希函数"""
    
    def __init__(self):
        super().__init__('MD5')
    
    def hash(self, data: bytes) -> bytes:
        """计算MD5哈希"""
        try:
            return hashlib.md5(data).digest()
        except Exception as e:
            self.logger.error(f"MD5哈希计算失败: {e}")
            raise


class Blake2bHash(HashFunction):
    """Blake2b哈希函数"""
    
    def __init__(self, digest_size: int = 64):
        super().__init__('BLAKE2B')
        self.digest_size = digest_size
    
    def hash(self, data: bytes) -> bytes:
        """计算Blake2b哈希"""
        try:
            return hashlib.blake2b(data, digest_size=self.digest_size).digest()
        except Exception as e:
            self.logger.error(f"Blake2b哈希计算失败: {e}")
            raise


class Blake2sHash(HashFunction):
    """Blake2s哈希函数"""
    
    def __init__(self, digest_size: int = 32):
        super().__init__('BLAKE2S')
        self.digest_size = digest_size
    
    def hash(self, data: bytes) -> bytes:
        """计算Blake2s哈希"""
        try:
            return hashlib.blake2s(data, digest_size=self.digest_size).digest()
        except Exception as e:
            self.logger.error(f"Blake2s哈希计算失败: {e}")
            raise


class SHA3_256Hash(HashFunction):
    """SHA3-256哈希函数"""
    
    def __init__(self):
        super().__init__('SHA3_256')
    
    def hash(self, data: bytes) -> bytes:
        """计算SHA3-256哈希"""
        try:
            return hashlib.sha3_256(data).digest()
        except Exception as e:
            self.logger.error(f"SHA3-256哈希计算失败: {e}")
            raise


class SHA3_512Hash(HashFunction):
    """SHA3-512哈希函数"""
    
    def __init__(self):
        super().__init__('SHA3_512')
    
    def hash(self, data: bytes) -> bytes:
        """计算SHA3-512哈希"""
        try:
            return hashlib.sha3_512(data).digest()
        except Exception as e:
            self.logger.error(f"SHA3-512哈希计算失败: {e}")
            raise


class CryptographyHashFunction(HashFunction):
    """使用cryptography库的哈希函数包装器"""
    
    def __init__(self, hash_algorithm):
        self.hash_algorithm = hash_algorithm
        super().__init__(hash_algorithm.name)
    
    def hash(self, data: bytes) -> bytes:
        """使用cryptography库计算哈希"""
        try:
            digest = hashes.Hash(self.hash_algorithm, backend=default_backend())
            digest.update(data)
            return digest.finalize()
        except Exception as e:
            self.logger.error(f"{self.algorithm}哈希计算失败: {e}")
            raise


def create_hash_function(algorithm: str, **kwargs) -> HashFunction:
    """
    创建哈希函数实例
    
    Args:
        algorithm: 哈希算法名称
        **kwargs: 算法特定参数
    
    Returns:
        哈希函数实例
    """
    algorithm = algorithm.upper()
    
    if algorithm == 'SHA256':
        return SHA256Hash()
    elif algorithm == 'SHA512':
        return SHA512Hash()
    elif algorithm == 'SHA1':
        return SHA1Hash()
    elif algorithm == 'MD5':
        return MD5Hash()
    elif algorithm == 'BLAKE2B':
        digest_size = kwargs.get('digest_size', 64)
        return Blake2bHash(digest_size)
    elif algorithm == 'BLAKE2S':
        digest_size = kwargs.get('digest_size', 32)
        return Blake2sHash(digest_size)
    elif algorithm == 'SHA3_256':
        return SHA3_256Hash()
    elif algorithm == 'SHA3_512':
        return SHA3_512Hash()
    elif algorithm == 'SHA224':
        return CryptographyHashFunction(hashes.SHA224())
    elif algorithm == 'SHA384':
        return CryptographyHashFunction(hashes.SHA384())
    else:
        raise ValueError(f"不支持的哈希算法: {algorithm}")


class HashBenchmarkSuite:
    """哈希算法基准测试套件"""
    
    def __init__(self):
        self.logger = get_logger()
        self.algorithms = [
            'SHA256', 'SHA512', 'SHA1', 'MD5', 
            'BLAKE2B', 'BLAKE2S', 'SHA3_256', 'SHA3_512'
        ]
    
    def run_all_benchmarks(self, test_data_sizes: list = None, 
                          iterations: int = 1000) -> Dict[str, Dict[str, Any]]:
        """
        运行所有哈希算法的基准测试
        
        Args:
            test_data_sizes: 测试数据大小列表
            iterations: 每个测试的迭代次数
        
        Returns:
            所有测试结果
        """
        if test_data_sizes is None:
            test_data_sizes = [1024, 8192, 65536, 1048576]  # 1KB, 8KB, 64KB, 1MB
        
        results = {}
        
        for algorithm in self.algorithms:
            self.logger.info(f"开始测试 {algorithm}")
            algorithm_results = {}
            
            try:
                hash_func = create_hash_function(algorithm)
                
                for data_size in test_data_sizes:
                    # 生成测试数据
                    test_data = b'A' * data_size
                    
                    # 运行基准测试
                    benchmark_result = hash_func.benchmark(test_data, iterations)
                    algorithm_results[f'{data_size}_bytes'] = benchmark_result
                    
                    self.logger.info(f"{algorithm} ({data_size} bytes): "
                                   f"{benchmark_result['throughput_mbps']:.2f} MB/s")
                
                results[algorithm] = algorithm_results
                
            except Exception as e:
                self.logger.error(f"{algorithm} 测试失败: {e}")
                results[algorithm] = {'error': str(e)}
        
        return results
    
    def compare_algorithms(self, data_size: int = 65536, 
                          iterations: int = 1000) -> Dict[str, float]:
        """
        比较不同哈希算法的性能
        
        Args:
            data_size: 测试数据大小
            iterations: 迭代次数
        
        Returns:
            性能比较结果
        """
        test_data = b'A' * data_size
        results = {}
        
        for algorithm in self.algorithms:
            try:
                hash_func = create_hash_function(algorithm)
                benchmark_result = hash_func.benchmark(test_data, iterations)
                results[algorithm] = benchmark_result['throughput_mbps']
            except Exception as e:
                self.logger.error(f"{algorithm} 测试失败: {e}")
                results[algorithm] = 0.0
        
        # 按性能排序
        sorted_results = dict(sorted(results.items(), 
                                   key=lambda x: x[1], reverse=True))
        
        self.logger.info(f"哈希算法性能排行 (数据大小: {data_size} bytes):")
        for i, (alg, throughput) in enumerate(sorted_results.items(), 1):
            self.logger.info(f"{i}. {alg}: {throughput:.2f} MB/s")
        
        return sorted_results
    
    def test_correctness(self) -> Dict[str, bool]:
        """
        测试哈希算法的正确性
        
        Returns:
            正确性测试结果
        """
        test_data = b"Hello, World!"
        expected_hashes = {
            'SHA256': '315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3',
            'SHA1': '0a0a9f2a6772942557ab5355d76af442f8f65e01',
            'MD5': '65a8e27d8879283831b664bd8b7f0ad4'
        }
        
        results = {}
        
        for algorithm in self.algorithms:
            try:
                hash_func = create_hash_function(algorithm)
                computed_hash = hash_func.hash_hex(test_data)
                
                if algorithm in expected_hashes:
                    results[algorithm] = computed_hash == expected_hashes[algorithm]
                    if not results[algorithm]:
                        self.logger.warning(f"{algorithm} 哈希值不匹配: "
                                          f"期望 {expected_hashes[algorithm]}, "
                                          f"得到 {computed_hash}")
                else:
                    # 对于没有预期值的算法，检查是否能正常计算
                    results[algorithm] = len(computed_hash) > 0
                    
                self.logger.info(f"{algorithm} 正确性测试: "
                               f"{'通过' if results[algorithm] else '失败'}")
                
            except Exception as e:
                self.logger.error(f"{algorithm} 正确性测试失败: {e}")
                results[algorithm] = False
        
        return results


if __name__ == "__main__":
    # 测试代码
    print("开始哈希算法测试...")
    
    # 基本功能测试
    test_data = b"Hello, World! This is a test message."
    
    # 测试各种哈希算法
    algorithms = ['SHA256', 'SHA512', 'MD5', 'BLAKE2B']
    
    for alg in algorithms:
        print(f"\n测试 {alg}:")
        hash_func = create_hash_function(alg)
        hash_value = hash_func.hash_hex(test_data)
        print(f"哈希值: {hash_value}")
        print(f"摘要长度: {hash_func.get_digest_size()} bytes")
    
    # 性能基准测试
    print("\n\n性能基准测试:")
    benchmark_suite = HashBenchmarkSuite()
    
    # 测试正确性
    print("正确性测试:")
    correctness_results = benchmark_suite.test_correctness()
    
    # 性能比较
    print("\n性能比较:")
    performance_results = benchmark_suite.compare_algorithms(data_size=65536, iterations=100)
