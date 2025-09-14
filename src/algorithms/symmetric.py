"""
对称加密算法实现
支持AES, DES, 3DES, ChaCha20等算法
"""

import os
import time
from typing import Tuple, Dict, Any, Union
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES as PyCrypto_AES, DES, DES3, ChaCha20
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

from ..utils.logger import get_logger


class SymmetricCipher:
    """对称加密算法基类"""
    
    def __init__(self, algorithm: str, key_size: int, mode: str = 'CBC'):
        self.algorithm = algorithm.upper()
        self.key_size = key_size
        self.mode = mode.upper()
        self.logger = get_logger()
        
        self.key = self._generate_key()
        self.iv = self._generate_iv()
    
    def _generate_key(self) -> bytes:
        """生成密钥"""
        return os.urandom(self.key_size // 8)
    
    def _generate_iv(self) -> bytes:
        """生成初始化向量"""
        if self.algorithm == 'CHACHA20':
            return os.urandom(12)  # ChaCha20使用12字节nonce
        elif self.algorithm in ['AES', 'DES', 'DES3']:
            if self.mode in ['CBC', 'CFB', 'OFB']:
                block_size = 16 if self.algorithm == 'AES' else 8
                return os.urandom(block_size)
        return b''
    
    def encrypt(self, plaintext: bytes) -> bytes:
        """加密数据"""
        raise NotImplementedError
    
    def decrypt(self, ciphertext: bytes) -> bytes:
        """解密数据"""
        raise NotImplementedError
    
    def benchmark_encrypt(self, data: bytes, iterations: int = 1000) -> Dict[str, float]:
        """基准测试加密性能"""
        # 预热
        for _ in range(10):
            self.encrypt(data[:min(1024, len(data))])
        
        # 正式测试
        start_time = time.time()
        for _ in range(iterations):
            self.encrypt(data)
        end_time = time.time()
        
        total_time = end_time - start_time
        throughput = (len(data) * iterations) / (total_time * 1024 * 1024)  # MB/s
        latency = (total_time * 1000) / iterations  # ms per operation
        ops_per_second = iterations / total_time
        
        return {
            'throughput_mbps': throughput,
            'latency_ms': latency,
            'operations_per_second': ops_per_second,
            'total_time': total_time,
            'data_size': len(data),
            'iterations': iterations
        }
    
    def benchmark_decrypt(self, data: bytes, iterations: int = 1000) -> Dict[str, float]:
        """基准测试解密性能"""
        # 先加密数据
        ciphertext = self.encrypt(data)
        
        # 预热
        for _ in range(10):
            self.decrypt(ciphertext)
        
        # 正式测试
        start_time = time.time()
        for _ in range(iterations):
            self.decrypt(ciphertext)
        end_time = time.time()
        
        total_time = end_time - start_time
        throughput = (len(data) * iterations) / (total_time * 1024 * 1024)  # MB/s
        latency = (total_time * 1000) / iterations  # ms per operation
        ops_per_second = iterations / total_time
        
        return {
            'throughput_mbps': throughput,
            'latency_ms': latency,
            'operations_per_second': ops_per_second,
            'total_time': total_time,
            'data_size': len(data),
            'iterations': iterations
        }


class AESCipher(SymmetricCipher):
    """AES加密算法"""
    
    def __init__(self, key_size: int = 256, mode: str = 'CBC'):
        super().__init__('AES', key_size, mode)
        self._setup_cipher()
    
    def _setup_cipher(self):
        """设置加密器"""
        if self.mode == 'CBC':
            self.cipher_mode = modes.CBC(self.iv)
        elif self.mode == 'ECB':
            self.cipher_mode = modes.ECB()
        elif self.mode == 'CTR':
            self.cipher_mode = modes.CTR(self.iv)
        elif self.mode == 'GCM':
            self.cipher_mode = modes.GCM(self.iv)
        else:
            raise ValueError(f"不支持的AES模式: {self.mode}")
        
        self.algorithm_obj = algorithms.AES(self.key)
    
    def encrypt(self, plaintext: bytes) -> bytes:
        """AES加密"""
        try:
            cipher = Cipher(self.algorithm_obj, self.cipher_mode, backend=default_backend())
            encryptor = cipher.encryptor()
            
            if self.mode in ['CBC', 'ECB']:
                # 需要填充
                padder = padding.PKCS7(128).padder()
                padded_data = padder.update(plaintext) + padder.finalize()
                ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            else:
                # CTR和GCM模式不需要填充
                ciphertext = encryptor.update(plaintext) + encryptor.finalize()
            
            if self.mode == 'GCM':
                # GCM模式需要返回tag
                return ciphertext + encryptor.tag
            
            return ciphertext
            
        except Exception as e:
            self.logger.error(f"AES加密失败: {e}")
            raise
    
    def decrypt(self, ciphertext: bytes) -> bytes:
        """AES解密"""
        try:
            if self.mode == 'GCM':
                # GCM模式需要分离tag
                actual_ciphertext = ciphertext[:-16]
                tag = ciphertext[-16:]
                cipher = Cipher(self.algorithm_obj, modes.GCM(self.iv, tag), 
                              backend=default_backend())
            else:
                cipher = Cipher(self.algorithm_obj, self.cipher_mode, 
                              backend=default_backend())
                actual_ciphertext = ciphertext
            
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()
            
            if self.mode in ['CBC', 'ECB']:
                # 去除填充
                unpadder = padding.PKCS7(128).unpadder()
                plaintext = unpadder.update(plaintext) + unpadder.finalize()
            
            return plaintext
            
        except Exception as e:
            self.logger.error(f"AES解密失败: {e}")
            raise


class DESCipher(SymmetricCipher):
    """DES加密算法"""
    
    def __init__(self, mode: str = 'CBC'):
        super().__init__('DES', 64, mode)
    
    def encrypt(self, plaintext: bytes) -> bytes:
        """DES加密"""
        try:
            if self.mode == 'CBC':
                cipher = DES.new(self.key, DES.MODE_CBC, self.iv)
            elif self.mode == 'ECB':
                cipher = DES.new(self.key, DES.MODE_ECB)
            else:
                raise ValueError(f"DES不支持模式: {self.mode}")
            
            # DES需要8字节填充
            padded_data = pad(plaintext, 8)
            return cipher.encrypt(padded_data)
            
        except Exception as e:
            self.logger.error(f"DES加密失败: {e}")
            raise
    
    def decrypt(self, ciphertext: bytes) -> bytes:
        """DES解密"""
        try:
            if self.mode == 'CBC':
                cipher = DES.new(self.key, DES.MODE_CBC, self.iv)
            elif self.mode == 'ECB':
                cipher = DES.new(self.key, DES.MODE_ECB)
            
            plaintext = cipher.decrypt(ciphertext)
            return unpad(plaintext, 8)
            
        except Exception as e:
            self.logger.error(f"DES解密失败: {e}")
            raise


class DES3Cipher(SymmetricCipher):
    """3DES加密算法"""
    
    def __init__(self, mode: str = 'CBC'):
        super().__init__('DES3', 192, mode)  # 3DES使用192位密钥
    
    def encrypt(self, plaintext: bytes) -> bytes:
        """3DES加密"""
        try:
            if self.mode == 'CBC':
                cipher = DES3.new(self.key, DES3.MODE_CBC, self.iv)
            elif self.mode == 'ECB':
                cipher = DES3.new(self.key, DES3.MODE_ECB)
            else:
                raise ValueError(f"3DES不支持模式: {self.mode}")
            
            # 3DES需要8字节填充
            padded_data = pad(plaintext, 8)
            return cipher.encrypt(padded_data)
            
        except Exception as e:
            self.logger.error(f"3DES加密失败: {e}")
            raise
    
    def decrypt(self, ciphertext: bytes) -> bytes:
        """3DES解密"""
        try:
            if self.mode == 'CBC':
                cipher = DES3.new(self.key, DES3.MODE_CBC, self.iv)
            elif self.mode == 'ECB':
                cipher = DES3.new(self.key, DES3.MODE_ECB)
            
            plaintext = cipher.decrypt(ciphertext)
            return unpad(plaintext, 8)
            
        except Exception as e:
            self.logger.error(f"3DES解密失败: {e}")
            raise


class ChaCha20Cipher(SymmetricCipher):
    """ChaCha20加密算法"""
    
    def __init__(self):
        super().__init__('CHACHA20', 256, 'ChaCha20')
    
    def encrypt(self, plaintext: bytes) -> bytes:
        """ChaCha20加密"""
        try:
            cipher = ChaCha20.new(key=self.key, nonce=self.iv)
            return cipher.encrypt(plaintext)
            
        except Exception as e:
            self.logger.error(f"ChaCha20加密失败: {e}")
            raise
    
    def decrypt(self, ciphertext: bytes) -> bytes:
        """ChaCha20解密"""
        try:
            cipher = ChaCha20.new(key=self.key, nonce=self.iv)
            return cipher.decrypt(ciphertext)
            
        except Exception as e:
            self.logger.error(f"ChaCha20解密失败: {e}")
            raise


def create_symmetric_cipher(algorithm: str, key_size: int = None, mode: str = 'CBC') -> SymmetricCipher:
    """
    创建对称加密算法实例
    
    Args:
        algorithm: 算法名称 (AES, DES, DES3, ChaCha20)
        key_size: 密钥长度
        mode: 加密模式
    
    Returns:
        对称加密算法实例
    """
    algorithm = algorithm.upper()
    
    if algorithm == 'AES':
        key_size = key_size or 256
        return AESCipher(key_size, mode)
    elif algorithm == 'DES':
        return DESCipher(mode)
    elif algorithm == 'DES3':
        return DES3Cipher(mode)
    elif algorithm == 'CHACHA20':
        return ChaCha20Cipher()
    else:
        raise ValueError(f"不支持的对称加密算法: {algorithm}")


if __name__ == "__main__":
    # 测试代码
    test_data = b"Hello, World! This is a test message for encryption." * 100
    
    # 测试AES
    print("测试AES-256-CBC:")
    aes = AESCipher(256, 'CBC')
    encrypted = aes.encrypt(test_data)
    decrypted = aes.decrypt(encrypted)
    print(f"加密测试: {'通过' if decrypted == test_data else '失败'}")
    
    # 性能测试
    results = aes.benchmark_encrypt(test_data, 100)
    print(f"AES加密性能: {results['throughput_mbps']:.2f} MB/s")
    
    # 测试ChaCha20
    print("\n测试ChaCha20:")
    chacha = ChaCha20Cipher()
    encrypted = chacha.encrypt(test_data)
    decrypted = chacha.decrypt(encrypted)
    print(f"加密测试: {'通过' if decrypted == test_data else '失败'}")
    
    results = chacha.benchmark_encrypt(test_data, 100)
    print(f"ChaCha20加密性能: {results['throughput_mbps']:.2f} MB/s")
