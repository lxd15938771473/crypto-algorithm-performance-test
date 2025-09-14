"""
基本功能测试
测试各个模块的基本功能是否正常
"""

import unittest
import os
import sys
from pathlib import Path

# 添加src目录到Python路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from src.algorithms import create_symmetric_cipher, create_hash_function, create_asymmetric_cipher
from src.utils import SystemInfo, load_config, create_default_config
from src.benchmarks import BenchmarkRunner


class TestSymmetricAlgorithms(unittest.TestCase):
    """测试对称加密算法"""
    
    def test_aes_encryption(self):
        """测试AES加密解密"""
        test_data = b"Hello, World! This is a test message."
        
        # 测试不同的AES配置
        configs = [
            (128, 'CBC'),
            (192, 'CBC'), 
            (256, 'CBC'),
            (256, 'CTR'),
            (256, 'GCM')
        ]
        
        for key_size, mode in configs:
            with self.subTest(key_size=key_size, mode=mode):
                cipher = create_symmetric_cipher('aes', key_size, mode)
                encrypted = cipher.encrypt(test_data)
                decrypted = cipher.decrypt(encrypted)
                
                self.assertEqual(test_data, decrypted)
                self.assertNotEqual(test_data, encrypted)
    
    def test_des_encryption(self):
        """测试DES加密解密"""
        test_data = b"Hello, World!"
        
        cipher = create_symmetric_cipher('des')
        encrypted = cipher.encrypt(test_data)
        decrypted = cipher.decrypt(encrypted)
        
        self.assertEqual(test_data, decrypted)
    
    def test_chacha20_encryption(self):
        """测试ChaCha20加密解密"""
        test_data = b"Hello, World! This is a test message."
        
        cipher = create_symmetric_cipher('chacha20')
        encrypted = cipher.encrypt(test_data)
        decrypted = cipher.decrypt(encrypted)
        
        self.assertEqual(test_data, decrypted)


class TestHashFunctions(unittest.TestCase):
    """测试哈希函数"""
    
    def test_hash_functions(self):
        """测试各种哈希函数"""
        test_data = b"Hello, World!"
        
        hash_algorithms = ['sha256', 'sha512', 'sha1', 'md5', 'blake2b', 'blake2s']
        
        for algorithm in hash_algorithms:
            with self.subTest(algorithm=algorithm):
                hash_func = create_hash_function(algorithm)
                hash_value = hash_func.hash(test_data)
                hash_hex = hash_func.hash_hex(test_data)
                
                # 哈希值不应为空
                self.assertGreater(len(hash_value), 0)
                self.assertGreater(len(hash_hex), 0)
                
                # 相同输入应产生相同哈希
                hash_value2 = hash_func.hash(test_data)
                self.assertEqual(hash_value, hash_value2)
    
    def test_hash_correctness(self):
        """测试哈希值正确性"""
        test_data = b"Hello, World!"
        
        # SHA256的已知哈希值
        sha256_func = create_hash_function('sha256')
        sha256_hash = sha256_func.hash_hex(test_data)
        expected_sha256 = "315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3"
        
        self.assertEqual(sha256_hash, expected_sha256)


class TestAsymmetricAlgorithms(unittest.TestCase):
    """测试非对称加密算法"""
    
    def test_rsa_operations(self):
        """测试RSA加密、解密、签名、验签"""
        test_data = b"Hello, World!"
        
        # 使用较小的密钥长度以提高测试速度
        rsa_cipher = create_asymmetric_cipher('rsa', key_size=1024)
        
        # 测试签名和验证
        signature = rsa_cipher.sign(test_data)
        is_valid = rsa_cipher.verify(test_data, signature)
        
        self.assertTrue(is_valid)
        
        # 测试错误数据的验证应该失败
        wrong_data = b"Wrong message"
        is_valid_wrong = rsa_cipher.verify(wrong_data, signature)
        self.assertFalse(is_valid_wrong)
        
        # 测试加密解密（小数据）
        small_data = b"Test"
        encrypted = rsa_cipher.encrypt(small_data)
        decrypted = rsa_cipher.decrypt(encrypted)
        
        self.assertEqual(small_data, decrypted)
    
    def test_ecc_operations(self):
        """测试ECC签名和验证"""
        test_data = b"Hello, World!"
        
        ecc_cipher = create_asymmetric_cipher('ecc', curve='secp256r1')
        
        # 测试签名和验证
        signature = ecc_cipher.sign(test_data)
        is_valid = ecc_cipher.verify(test_data, signature)
        
        self.assertTrue(is_valid)
        
        # 测试错误数据的验证应该失败
        wrong_data = b"Wrong message"
        is_valid_wrong = ecc_cipher.verify(wrong_data, signature)
        self.assertFalse(is_valid_wrong)


class TestUtilities(unittest.TestCase):
    """测试工具函数"""
    
    def test_system_info(self):
        """测试系统信息获取"""
        system_info = SystemInfo()
        
        # 测试基本信息获取
        cpu_info = system_info.get_cpu_info()
        memory_info = system_info.get_memory_info()
        python_version = system_info.get_python_version()
        
        self.assertIsInstance(cpu_info, str)
        self.assertIsInstance(memory_info, str)
        self.assertIsInstance(python_version, str)
        
        # 测试动态信息获取
        cpu_usage = system_info.get_current_cpu_usage()
        memory_usage = system_info.get_current_memory_usage()
        
        self.assertIsInstance(cpu_usage, float)
        self.assertIsInstance(memory_usage, dict)
        self.assertIn('percent', memory_usage)
    
    def test_config_loading(self):
        """测试配置加载"""
        # 测试默认配置创建
        default_config = create_default_config()
        
        self.assertIsInstance(default_config.test_settings.data_sizes, list)
        self.assertGreater(default_config.test_settings.iterations, 0)
        
        # 测试配置中的算法设置
        self.assertIn('aes', default_config.symmetric_algorithms)
        self.assertIn('rsa', default_config.asymmetric_algorithms)
        self.assertIn('sha256', default_config.hash_algorithms)


class TestBenchmarkRunner(unittest.TestCase):
    """测试基准测试运行器"""
    
    def setUp(self):
        """测试设置"""
        self.test_dir = Path("./test_output")
        self.test_dir.mkdir(exist_ok=True)
        
        # 创建一个简化的配置用于快速测试
        self.config = create_default_config()
        # 减少迭代次数以提高测试速度
        self.config.test_settings.iterations = 10
        self.config.test_settings.data_sizes = [1024]  # 只测试1KB
        
        # 只启用少数算法
        for alg_name in self.config.symmetric_algorithms:
            self.config.symmetric_algorithms[alg_name].enabled = False
        self.config.symmetric_algorithms['aes'].enabled = True
        self.config.symmetric_algorithms['aes'].key_sizes = [256]
        self.config.symmetric_algorithms['aes'].modes = ['CBC']
        
        for alg_name in self.config.asymmetric_algorithms:
            self.config.asymmetric_algorithms[alg_name].enabled = False
        
        for alg_name in self.config.hash_algorithms:
            self.config.hash_algorithms[alg_name].enabled = False
        self.config.hash_algorithms['sha256'].enabled = True
        
        self.config.threading.enabled = False
        self.config.monitoring.enabled = False
    
    def tearDown(self):
        """测试清理"""
        # 清理测试文件
        import shutil
        if self.test_dir.exists():
            shutil.rmtree(self.test_dir)
    
    def test_benchmark_runner_creation(self):
        """测试基准测试运行器创建"""
        runner = BenchmarkRunner(self.config, self.test_dir)
        
        self.assertEqual(runner.config, self.config)
        self.assertEqual(runner.output_dir, self.test_dir)
    
    def test_single_algorithm_benchmark(self):
        """测试单个算法基准测试"""
        runner = BenchmarkRunner(self.config, self.test_dir)
        
        # 测试单个算法
        results = runner.run_selected_benchmarks(['aes'])
        
        self.assertIn('symmetric', results)
        self.assertIn('aes', results['symmetric'])
        
        # 检查结果结构
        aes_results = results['symmetric']['aes']
        self.assertIsInstance(aes_results, dict)
    
    def test_hash_benchmark(self):
        """测试哈希算法基准测试"""
        runner = BenchmarkRunner(self.config, self.test_dir)
        
        results = runner.run_selected_benchmarks(['sha256'])
        
        self.assertIn('hash', results)
        self.assertIn('sha256', results['hash'])
        
        # 检查哈希结果
        sha256_results = results['hash']['sha256']
        self.assertIsInstance(sha256_results, dict)
        
        # 应该包含性能指标
        for size_test in sha256_results:
            if isinstance(sha256_results[size_test], dict):
                self.assertIn('throughput_mbps', sha256_results[size_test])


class TestPerformanceBenchmarks(unittest.TestCase):
    """性能基准测试"""
    
    def test_symmetric_performance(self):
        """测试对称加密性能"""
        test_data = b"A" * 10000  # 10KB测试数据
        
        aes_cipher = create_symmetric_cipher('aes', 256, 'CBC')
        
        # 运行性能测试
        encrypt_result = aes_cipher.benchmark_encrypt(test_data, 50)
        decrypt_result = aes_cipher.benchmark_decrypt(test_data, 50)
        
        # 检查结果包含必要的性能指标
        self.assertIn('throughput_mbps', encrypt_result)
        self.assertIn('latency_ms', encrypt_result)
        self.assertIn('operations_per_second', encrypt_result)
        
        # 性能应该大于0
        self.assertGreater(encrypt_result['throughput_mbps'], 0)
        self.assertGreater(encrypt_result['operations_per_second'], 0)
    
    def test_hash_performance(self):
        """测试哈希算法性能"""
        test_data = b"A" * 10000  # 10KB测试数据
        
        sha256_func = create_hash_function('sha256')
        
        # 运行性能测试
        result = sha256_func.benchmark(test_data, 100)
        
        # 检查结果
        self.assertIn('throughput_mbps', result)
        self.assertIn('latency_ms', result)
        self.assertIn('operations_per_second', result)
        
        # 性能应该大于0
        self.assertGreater(result['throughput_mbps'], 0)
        self.assertGreater(result['operations_per_second'], 0)


def run_tests():
    """运行所有测试"""
    # 创建测试套件
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # 添加测试类
    test_classes = [
        TestSymmetricAlgorithms,
        TestHashFunctions,
        TestAsymmetricAlgorithms,
        TestUtilities,
        TestBenchmarkRunner,
        TestPerformanceBenchmarks
    ]
    
    for test_class in test_classes:
        tests = loader.loadTestsFromTestCase(test_class)
        suite.addTests(tests)
    
    # 运行测试
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result.wasSuccessful()


if __name__ == "__main__":
    print("开始运行密码算法性能测试工具的单元测试...")
    success = run_tests()
    
    if success:
        print("\n✅ 所有测试通过！")
        sys.exit(0)
    else:
        print("\n❌ 部分测试失败！")
        sys.exit(1)
