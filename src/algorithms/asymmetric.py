"""
非对称加密算法实现
支持RSA、ECC、ECDSA等算法
"""

import time
import os
from typing import Tuple, Dict, Any, Optional
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

from ..utils.logger import get_logger


class AsymmetricCipher:
    """非对称加密算法基类"""
    
    def __init__(self, algorithm: str):
        self.algorithm = algorithm.upper()
        self.logger = get_logger()
        self.private_key = None
        self.public_key = None
    
    def generate_keypair(self):
        """生成密钥对"""
        raise NotImplementedError
    
    def encrypt(self, plaintext: bytes) -> bytes:
        """加密数据"""
        raise NotImplementedError
    
    def decrypt(self, ciphertext: bytes) -> bytes:
        """解密数据"""
        raise NotImplementedError
    
    def sign(self, data: bytes) -> bytes:
        """数字签名"""
        raise NotImplementedError
    
    def verify(self, data: bytes, signature: bytes) -> bool:
        """验证签名"""
        raise NotImplementedError
    
    def benchmark_encrypt(self, data: bytes, iterations: int = 100) -> Dict[str, Any]:
        """基准测试加密性能"""
        if not self.public_key:
            self.generate_keypair()
        
        # 预热
        test_data = data[:min(len(data), self._get_max_encrypt_size())]
        for _ in range(5):
            try:
                self.encrypt(test_data)
            except:
                break
        
        # 正式测试
        successful_ops = 0
        start_time = time.time()
        
        for _ in range(iterations):
            try:
                self.encrypt(test_data)
                successful_ops += 1
            except Exception as e:
                self.logger.debug(f"加密操作失败: {e}")
        
        end_time = time.time()
        
        if successful_ops == 0:
            return {'error': 'All encryption operations failed'}
        
        total_time = end_time - start_time
        ops_per_second = successful_ops / total_time
        latency = (total_time * 1000) / successful_ops  # ms per operation
        
        return {
            'algorithm': self.algorithm,
            'operation': 'encrypt',
            'operations_per_second': ops_per_second,
            'latency_ms': latency,
            'total_time': total_time,
            'successful_operations': successful_ops,
            'total_operations': iterations,
            'data_size': len(test_data)
        }
    
    def benchmark_decrypt(self, data: bytes, iterations: int = 100) -> Dict[str, Any]:
        """基准测试解密性能"""
        if not self.private_key:
            self.generate_keypair()
        
        # 准备加密数据
        test_data = data[:min(len(data), self._get_max_encrypt_size())]
        try:
            ciphertext = self.encrypt(test_data)
        except Exception as e:
            return {'error': f'无法准备测试数据: {e}'}
        
        # 预热
        for _ in range(5):
            try:
                self.decrypt(ciphertext)
            except:
                break
        
        # 正式测试
        successful_ops = 0
        start_time = time.time()
        
        for _ in range(iterations):
            try:
                self.decrypt(ciphertext)
                successful_ops += 1
            except Exception as e:
                self.logger.debug(f"解密操作失败: {e}")
        
        end_time = time.time()
        
        if successful_ops == 0:
            return {'error': 'All decryption operations failed'}
        
        total_time = end_time - start_time
        ops_per_second = successful_ops / total_time
        latency = (total_time * 1000) / successful_ops
        
        return {
            'algorithm': self.algorithm,
            'operation': 'decrypt',
            'operations_per_second': ops_per_second,
            'latency_ms': latency,
            'total_time': total_time,
            'successful_operations': successful_ops,
            'total_operations': iterations,
            'data_size': len(test_data)
        }
    
    def benchmark_sign(self, data: bytes, iterations: int = 1000) -> Dict[str, Any]:
        """基准测试签名性能"""
        if not self.private_key:
            self.generate_keypair()
        
        # 预热
        for _ in range(10):
            try:
                self.sign(data)
            except:
                break
        
        # 正式测试
        successful_ops = 0
        start_time = time.time()
        
        for _ in range(iterations):
            try:
                self.sign(data)
                successful_ops += 1
            except Exception as e:
                self.logger.debug(f"签名操作失败: {e}")
        
        end_time = time.time()
        
        if successful_ops == 0:
            return {'error': 'All signing operations failed'}
        
        total_time = end_time - start_time
        ops_per_second = successful_ops / total_time
        latency = (total_time * 1000) / successful_ops
        
        return {
            'algorithm': self.algorithm,
            'operation': 'sign',
            'operations_per_second': ops_per_second,
            'latency_ms': latency,
            'total_time': total_time,
            'successful_operations': successful_ops,
            'total_operations': iterations,
            'data_size': len(data)
        }
    
    def benchmark_verify(self, data: bytes, iterations: int = 1000) -> Dict[str, Any]:
        """基准测试验签性能"""
        if not self.private_key:
            self.generate_keypair()
        
        # 准备签名数据
        try:
            signature = self.sign(data)
        except Exception as e:
            return {'error': f'无法准备签名数据: {e}'}
        
        # 预热
        for _ in range(10):
            try:
                self.verify(data, signature)
            except:
                break
        
        # 正式测试
        successful_ops = 0
        start_time = time.time()
        
        for _ in range(iterations):
            try:
                self.verify(data, signature)
                successful_ops += 1
            except Exception as e:
                self.logger.debug(f"验签操作失败: {e}")
        
        end_time = time.time()
        
        if successful_ops == 0:
            return {'error': 'All verification operations failed'}
        
        total_time = end_time - start_time
        ops_per_second = successful_ops / total_time
        latency = (total_time * 1000) / successful_ops
        
        return {
            'algorithm': self.algorithm,
            'operation': 'verify',
            'operations_per_second': ops_per_second,
            'latency_ms': latency,
            'total_time': total_time,
            'successful_operations': successful_ops,
            'total_operations': iterations,
            'data_size': len(data)
        }
    
    def _get_max_encrypt_size(self) -> int:
        """获取最大加密数据大小"""
        return 1024  # 默认值，子类应该重写


class RSACipher(AsymmetricCipher):
    """RSA加密算法"""
    
    def __init__(self, key_size: int = 2048):
        super().__init__('RSA')
        self.key_size = key_size
        self.generate_keypair()
    
    def generate_keypair(self):
        """生成RSA密钥对"""
        try:
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=self.key_size,
                backend=default_backend()
            )
            self.public_key = self.private_key.public_key()
            self.logger.debug(f"生成RSA-{self.key_size}密钥对成功")
        except Exception as e:
            self.logger.error(f"RSA密钥对生成失败: {e}")
            raise
    
    def encrypt(self, plaintext: bytes) -> bytes:
        """RSA加密"""
        try:
            return self.public_key.encrypt(
                plaintext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except Exception as e:
            self.logger.error(f"RSA加密失败: {e}")
            raise
    
    def decrypt(self, ciphertext: bytes) -> bytes:
        """RSA解密"""
        try:
            return self.private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except Exception as e:
            self.logger.error(f"RSA解密失败: {e}")
            raise
    
    def sign(self, data: bytes) -> bytes:
        """RSA签名"""
        try:
            return self.private_key.sign(
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        except Exception as e:
            self.logger.error(f"RSA签名失败: {e}")
            raise
    
    def verify(self, data: bytes, signature: bytes) -> bool:
        """RSA验签"""
        try:
            self.public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False
        except Exception as e:
            self.logger.error(f"RSA验签失败: {e}")
            raise
    
    def _get_max_encrypt_size(self) -> int:
        """获取RSA最大加密数据大小"""
        # OAEP padding: key_size/8 - 2*hash_length - 2
        # SHA256 hash length is 32 bytes
        return (self.key_size // 8) - 2 * 32 - 2


class ECCCipher(AsymmetricCipher):
    """椭圆曲线加密算法"""
    
    def __init__(self, curve_name: str = 'secp256r1'):
        super().__init__(f'ECC-{curve_name}')
        self.curve_name = curve_name
        self.curve = self._get_curve()
        self.generate_keypair()
    
    def _get_curve(self):
        """获取椭圆曲线"""
        curve_map = {
            'secp256r1': ec.SECP256R1(),
            'secp384r1': ec.SECP384R1(), 
            'secp521r1': ec.SECP521R1(),
            'secp256k1': ec.SECP256K1()
        }
        
        if self.curve_name not in curve_map:
            raise ValueError(f"不支持的椭圆曲线: {self.curve_name}")
        
        return curve_map[self.curve_name]
    
    def generate_keypair(self):
        """生成ECC密钥对"""
        try:
            self.private_key = ec.generate_private_key(
                self.curve,
                backend=default_backend()
            )
            self.public_key = self.private_key.public_key()
            self.logger.debug(f"生成ECC-{self.curve_name}密钥对成功")
        except Exception as e:
            self.logger.error(f"ECC密钥对生成失败: {e}")
            raise
    
    def encrypt(self, plaintext: bytes) -> bytes:
        """ECC加密（ECIES）"""
        # ECC本身不直接支持加密，这里实现简化版ECIES
        # 实际应用中建议使用专门的ECIES库
        raise NotImplementedError("ECC加密需要实现ECIES，当前版本暂不支持")
    
    def decrypt(self, ciphertext: bytes) -> bytes:
        """ECC解密（ECIES）"""
        raise NotImplementedError("ECC解密需要实现ECIES，当前版本暂不支持")
    
    def sign(self, data: bytes) -> bytes:
        """ECDSA签名"""
        try:
            return self.private_key.sign(
                data,
                ec.ECDSA(hashes.SHA256())
            )
        except Exception as e:
            self.logger.error(f"ECDSA签名失败: {e}")
            raise
    
    def verify(self, data: bytes, signature: bytes) -> bool:
        """ECDSA验签"""
        try:
            self.public_key.verify(
                signature,
                data,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except InvalidSignature:
            return False
        except Exception as e:
            self.logger.error(f"ECDSA验签失败: {e}")
            raise
    
    def _get_max_encrypt_size(self) -> int:
        """ECC不支持直接加密"""
        return 0


def create_asymmetric_cipher(algorithm: str, **kwargs) -> AsymmetricCipher:
    """
    创建非对称加密算法实例
    
    Args:
        algorithm: 算法名称 (RSA, ECC, ECDSA)
        **kwargs: 算法特定参数
    
    Returns:
        非对称加密算法实例
    """
    algorithm = algorithm.upper()
    
    if algorithm == 'RSA':
        key_size = kwargs.get('key_size', 2048)
        return RSACipher(key_size)
    elif algorithm in ['ECC', 'ECDSA']:
        curve = kwargs.get('curve', 'secp256r1')
        return ECCCipher(curve)
    else:
        raise ValueError(f"不支持的非对称加密算法: {algorithm}")


class AsymmetricBenchmarkSuite:
    """非对称加密算法基准测试套件"""
    
    def __init__(self):
        self.logger = get_logger()
    
    def benchmark_rsa_keysizes(self, key_sizes: list = None, 
                              data_size: int = 100, iterations: int = 50) -> Dict[str, Dict[str, Any]]:
        """
        测试不同RSA密钥长度的性能
        
        Args:
            key_sizes: RSA密钥长度列表
            data_size: 测试数据大小
            iterations: 迭代次数
        
        Returns:
            测试结果
        """
        if key_sizes is None:
            key_sizes = [1024, 2048, 3072, 4096]
        
        test_data = b'A' * data_size
        results = {}
        
        for key_size in key_sizes:
            self.logger.info(f"开始测试RSA-{key_size}")
            
            try:
                rsa_cipher = RSACipher(key_size)
                
                # 测试加密/解密性能
                encrypt_result = rsa_cipher.benchmark_encrypt(test_data, iterations)
                decrypt_result = rsa_cipher.benchmark_decrypt(test_data, iterations)
                sign_result = rsa_cipher.benchmark_sign(test_data, iterations * 2)
                verify_result = rsa_cipher.benchmark_verify(test_data, iterations * 2)
                
                results[f'RSA-{key_size}'] = {
                    'key_size': key_size,
                    'encrypt': encrypt_result,
                    'decrypt': decrypt_result,
                    'sign': sign_result,
                    'verify': verify_result
                }
                
                self.logger.info(f"RSA-{key_size} 测试完成")
                
            except Exception as e:
                self.logger.error(f"RSA-{key_size} 测试失败: {e}")
                results[f'RSA-{key_size}'] = {'error': str(e)}
        
        return results
    
    def benchmark_ecc_curves(self, curves: list = None, 
                           data_size: int = 1000, iterations: int = 200) -> Dict[str, Dict[str, Any]]:
        """
        测试不同ECC曲线的性能
        
        Args:
            curves: 椭圆曲线列表
            data_size: 测试数据大小
            iterations: 迭代次数
        
        Returns:
            测试结果
        """
        if curves is None:
            curves = ['secp256r1', 'secp384r1', 'secp521r1']
        
        test_data = b'A' * data_size
        results = {}
        
        for curve in curves:
            self.logger.info(f"开始测试ECC-{curve}")
            
            try:
                ecc_cipher = ECCCipher(curve)
                
                # ECC主要用于签名，测试签名/验证性能
                sign_result = ecc_cipher.benchmark_sign(test_data, iterations)
                verify_result = ecc_cipher.benchmark_verify(test_data, iterations)
                
                results[f'ECC-{curve}'] = {
                    'curve': curve,
                    'sign': sign_result,
                    'verify': verify_result
                }
                
                self.logger.info(f"ECC-{curve} 测试完成")
                
            except Exception as e:
                self.logger.error(f"ECC-{curve} 测试失败: {e}")
                results[f'ECC-{curve}'] = {'error': str(e)}
        
        return results
    
    def compare_signature_algorithms(self, data_size: int = 1000, 
                                   iterations: int = 200) -> Dict[str, Any]:
        """
        比较不同签名算法的性能
        
        Args:
            data_size: 测试数据大小
            iterations: 迭代次数
        
        Returns:
            比较结果
        """
        test_data = b'A' * data_size
        results = {}
        
        # 测试RSA签名
        rsa_configs = [
            ('RSA-2048', RSACipher(2048)),
            ('RSA-3072', RSACipher(3072)),
        ]
        
        # 测试ECC签名
        ecc_configs = [
            ('ECDSA-P256', ECCCipher('secp256r1')),
            ('ECDSA-P384', ECCCipher('secp384r1')),
            ('ECDSA-P521', ECCCipher('secp521r1')),
        ]
        
        all_configs = rsa_configs + ecc_configs
        
        for name, cipher in all_configs:
            self.logger.info(f"测试 {name} 签名性能")
            
            try:
                sign_result = cipher.benchmark_sign(test_data, iterations)
                verify_result = cipher.benchmark_verify(test_data, iterations)
                
                results[name] = {
                    'sign_ops_per_sec': sign_result.get('operations_per_second', 0),
                    'verify_ops_per_sec': verify_result.get('operations_per_second', 0),
                    'sign_latency_ms': sign_result.get('latency_ms', float('inf')),
                    'verify_latency_ms': verify_result.get('latency_ms', float('inf'))
                }
                
            except Exception as e:
                self.logger.error(f"{name} 测试失败: {e}")
                results[name] = {'error': str(e)}
        
        # 按签名性能排序
        valid_results = {k: v for k, v in results.items() if 'error' not in v}
        sorted_by_sign = sorted(valid_results.items(), 
                              key=lambda x: x[1]['sign_ops_per_sec'], 
                              reverse=True)
        sorted_by_verify = sorted(valid_results.items(), 
                                key=lambda x: x[1]['verify_ops_per_sec'], 
                                reverse=True)
        
        self.logger.info("签名性能排行:")
        for i, (name, result) in enumerate(sorted_by_sign[:5], 1):
            self.logger.info(f"{i}. {name}: {result['sign_ops_per_sec']:.1f} ops/sec")
        
        self.logger.info("验签性能排行:")
        for i, (name, result) in enumerate(sorted_by_verify[:5], 1):
            self.logger.info(f"{i}. {name}: {result['verify_ops_per_sec']:.1f} ops/sec")
        
        return {
            'detailed_results': results,
            'sign_ranking': sorted_by_sign,
            'verify_ranking': sorted_by_verify
        }


if __name__ == "__main__":
    # 测试代码
    print("开始非对称加密算法测试...")
    
    # 基本功能测试
    test_data = b"Hello, World! This is a test message for asymmetric crypto."
    
    # 测试RSA
    print("\n测试RSA-2048:")
    rsa = RSACipher(2048)
    
    # RSA加密/解密测试
    small_data = test_data[:100]  # RSA加密数据大小有限制
    encrypted = rsa.encrypt(small_data)
    decrypted = rsa.decrypt(encrypted)
    print(f"RSA加密/解密测试: {'通过' if decrypted == small_data else '失败'}")
    
    # RSA签名/验签测试
    signature = rsa.sign(test_data)
    is_valid = rsa.verify(test_data, signature)
    print(f"RSA签名/验签测试: {'通过' if is_valid else '失败'}")
    
    # 测试ECC
    print("\n测试ECC-secp256r1:")
    ecc = ECCCipher('secp256r1')
    
    # ECC签名/验签测试
    signature = ecc.sign(test_data)
    is_valid = ecc.verify(test_data, signature)
    print(f"ECC签名/验签测试: {'通过' if is_valid else '失败'}")
    
    # 性能测试
    print("\n性能测试:")
    benchmark_suite = AsymmetricBenchmarkSuite()
    
    # 比较签名算法性能
    print("比较签名算法性能:")
    comparison_results = benchmark_suite.compare_signature_algorithms(
        data_size=1000, iterations=50
    )
