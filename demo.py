#!/usr/bin/env python3
"""
密码算法性能测试工具快速开始示例
演示如何使用本工具进行基本的密码算法性能测试
"""

import os
import sys
from pathlib import Path

# 添加src目录到Python路径
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from src.algorithms import (
    create_symmetric_cipher, 
    create_hash_function, 
    create_asymmetric_cipher,
    HashBenchmarkSuite,
    AsymmetricBenchmarkSuite
)
from src.utils import SystemInfo, create_default_config
from src.benchmarks import BenchmarkRunner


def demo_symmetric_encryption():
    """演示对称加密算法测试"""
    print("=" * 60)
    print("对称加密算法演示")
    print("=" * 60)
    
    test_data = b"Hello, World! This is a demo message." * 100  # ~3.7KB
    
    # 测试AES算法
    print("\n🔐 测试AES-256-CBC:")
    aes_cipher = create_symmetric_cipher('aes', 256, 'CBC')
    
    # 基本功能测试
    encrypted = aes_cipher.encrypt(test_data)
    decrypted = aes_cipher.decrypt(encrypted)
    print(f"✅ 加密解密功能: {'正常' if decrypted == test_data else '异常'}")
    
    # 性能测试
    result = aes_cipher.benchmark_encrypt(test_data, 1000)
    print(f"📊 加密性能: {result['throughput_mbps']:.2f} MB/s, "
          f"{result['operations_per_second']:.0f} ops/sec")
    
    # 测试ChaCha20算法
    print("\n🔐 测试ChaCha20:")
    chacha_cipher = create_symmetric_cipher('chacha20')
    
    encrypted = chacha_cipher.encrypt(test_data)
    decrypted = chacha_cipher.decrypt(encrypted)
    print(f"✅ 加密解密功能: {'正常' if decrypted == test_data else '异常'}")
    
    result = chacha_cipher.benchmark_encrypt(test_data, 1000)
    print(f"📊 加密性能: {result['throughput_mbps']:.2f} MB/s, "
          f"{result['operations_per_second']:.0f} ops/sec")


def demo_hash_functions():
    """演示哈希函数测试"""
    print("\n" + "=" * 60)
    print("哈希函数演示")
    print("=" * 60)
    
    test_data = b"Hello, World!" * 1000  # ~13KB
    
    hash_algorithms = ['sha256', 'sha512', 'blake2b', 'md5']
    
    print(f"\n📝 测试数据大小: {len(test_data)} bytes")
    print("\n哈希算法性能比较:")
    print("-" * 50)
    
    results = []
    
    for alg_name in hash_algorithms:
        try:
            hash_func = create_hash_function(alg_name)
            
            # 计算哈希值
            hash_value = hash_func.hash_hex(test_data)
            
            # 性能测试
            benchmark = hash_func.benchmark(test_data, 2000)
            
            results.append((alg_name, benchmark['throughput_mbps'], benchmark['operations_per_second']))
            
            print(f"{alg_name.upper():>10}: {benchmark['throughput_mbps']:>8.2f} MB/s, "
                  f"{benchmark['operations_per_second']:>8.0f} ops/sec")
            print(f"           哈希值: {hash_value[:32]}...")
            
        except Exception as e:
            print(f"{alg_name.upper():>10}: ❌ 测试失败 - {e}")
    
    # 显示最佳性能
    if results:
        best_throughput = max(results, key=lambda x: x[1])
        best_ops = max(results, key=lambda x: x[2])
        
        print(f"\n🏆 最高吞吐量: {best_throughput[0].upper()} ({best_throughput[1]:.2f} MB/s)")
        print(f"🏆 最高操作数: {best_ops[0].upper()} ({best_ops[2]:.0f} ops/sec)")


def demo_asymmetric_crypto():
    """演示非对称加密算法测试"""
    print("\n" + "=" * 60)
    print("非对称加密算法演示")
    print("=" * 60)
    
    test_data = b"Hello, World! This is a digital signature test message."
    
    # RSA演示
    print("\n🔑 RSA-2048 签名验证测试:")
    try:
        rsa_cipher = create_asymmetric_cipher('rsa', key_size=2048)
        
        # 签名和验证
        signature = rsa_cipher.sign(test_data)
        is_valid = rsa_cipher.verify(test_data, signature)
        print(f"✅ 签名验证: {'通过' if is_valid else '失败'}")
        
        # 性能测试（使用较少迭代次数，因为RSA较慢）
        sign_result = rsa_cipher.benchmark_sign(test_data, 100)
        verify_result = rsa_cipher.benchmark_verify(test_data, 200)
        
        print(f"📊 签名性能: {sign_result['operations_per_second']:.1f} ops/sec, "
              f"延迟: {sign_result['latency_ms']:.2f} ms")
        print(f"📊 验证性能: {verify_result['operations_per_second']:.1f} ops/sec, "
              f"延迟: {verify_result['latency_ms']:.2f} ms")
        
    except Exception as e:
        print(f"❌ RSA测试失败: {e}")
    
    # ECDSA演示
    print("\n🔑 ECDSA-P256 签名验证测试:")
    try:
        ecc_cipher = create_asymmetric_cipher('ecc', curve='secp256r1')
        
        signature = ecc_cipher.sign(test_data)
        is_valid = ecc_cipher.verify(test_data, signature)
        print(f"✅ 签名验证: {'通过' if is_valid else '失败'}")
        
        sign_result = ecc_cipher.benchmark_sign(test_data, 500)
        verify_result = ecc_cipher.benchmark_verify(test_data, 500)
        
        print(f"📊 签名性能: {sign_result['operations_per_second']:.1f} ops/sec, "
              f"延迟: {sign_result['latency_ms']:.2f} ms")
        print(f"📊 验证性能: {verify_result['operations_per_second']:.1f} ops/sec, "
              f"延迟: {verify_result['latency_ms']:.2f} ms")
        
    except Exception as e:
        print(f"❌ ECDSA测试失败: {e}")


def demo_comprehensive_benchmark():
    """演示综合基准测试"""
    print("\n" + "=" * 60)
    print("综合基准测试演示")
    print("=" * 60)
    
    # 创建快速测试配置
    config = create_default_config()
    
    # 调整配置以进行快速演示
    config.test_settings.iterations = 100
    config.test_settings.data_sizes = [1024, 8192]  # 只测试1KB和8KB
    
    # 只启用部分算法以节省时间
    algorithms_to_enable = {
        'symmetric': ['aes'],
        'hash': ['sha256', 'blake2b'],
        'asymmetric': []  # 跳过非对称算法以节省时间
    }
    
    # 禁用所有算法
    for alg_name in config.symmetric_algorithms:
        config.symmetric_algorithms[alg_name].enabled = False
    for alg_name in config.asymmetric_algorithms:
        config.asymmetric_algorithms[alg_name].enabled = False
    for alg_name in config.hash_algorithms:
        config.hash_algorithms[alg_name].enabled = False
    
    # 启用选定的算法
    for alg in algorithms_to_enable['symmetric']:
        if alg in config.symmetric_algorithms:
            config.symmetric_algorithms[alg].enabled = True
            config.symmetric_algorithms[alg].key_sizes = [256]  # 只测试256位
            config.symmetric_algorithms[alg].modes = ['CBC']    # 只测试CBC模式
    
    for alg in algorithms_to_enable['hash']:
        if alg in config.hash_algorithms:
            config.hash_algorithms[alg].enabled = True
    
    # 禁用多线程和监控以简化演示
    config.threading.enabled = False
    config.monitoring.enabled = False
    
    # 创建输出目录
    output_dir = Path("./demo_results")
    output_dir.mkdir(exist_ok=True)
    
    print(f"\n🚀 运行综合基准测试...")
    print(f"📁 结果将保存到: {output_dir.absolute()}")
    
    try:
        runner = BenchmarkRunner(config, output_dir, output_format='json')
        results = runner.run_all_benchmarks()
        
        print(f"\n✅ 测试完成!")
        runner.print_summary(results)
        
        # 显示一些关键结果
        if 'symmetric' in results and 'aes' in results['symmetric']:
            aes_results = results['symmetric']['aes']
            print(f"\n🔐 AES-256-CBC 性能亮点:")
            for test_config, test_results in aes_results.items():
                for size_test, size_results in test_results.items():
                    if 'encrypt' in size_results:
                        throughput = size_results['encrypt']['throughput_mbps']
                        print(f"   {size_test}: {throughput:.2f} MB/s")
        
        if 'hash' in results:
            print(f"\n🧮 哈希算法性能亮点:")
            for alg_name, alg_results in results['hash'].items():
                if isinstance(alg_results, dict) and 'error' not in alg_results:
                    # 找到最大数据大小的测试结果
                    max_size_result = None
                    max_size = 0
                    for size_test, size_result in alg_results.items():
                        if isinstance(size_result, dict) and 'data_size' in size_result:
                            if size_result['data_size'] > max_size:
                                max_size = size_result['data_size']
                                max_size_result = size_result
                    
                    if max_size_result:
                        print(f"   {alg_name.upper()}: {max_size_result['throughput_mbps']:.2f} MB/s")
    
    except Exception as e:
        print(f"❌ 综合测试失败: {e}")


def show_system_info():
    """显示系统信息"""
    print("=" * 60)
    print("系统信息")
    print("=" * 60)
    
    system_info = SystemInfo()
    system_info.print_system_info()


def main():
    """主函数"""
    print("🔐 密码算法性能测试工具 - 快速开始演示")
    print("=" * 60)
    print("本演示将展示工具的主要功能:")
    print("1. 对称加密算法测试")
    print("2. 哈希函数测试") 
    print("3. 非对称加密算法测试")
    print("4. 综合基准测试")
    print("=" * 60)
    
    try:
        # 显示系统信息
        show_system_info()
        
        # 运行各种演示
        demo_symmetric_encryption()
        demo_hash_functions()
        demo_asymmetric_crypto()
        demo_comprehensive_benchmark()
        
        print("\n" + "=" * 60)
        print("🎉 演示完成!")
        print("=" * 60)
        print("\n💡 使用提示:")
        print("- 运行 'python main.py --help' 查看完整选项")
        print("- 运行 'python main.py -c config/default.yaml' 使用配置文件")
        print("- 运行 'python tests/test_basic_functionality.py' 执行单元测试")
        print("- 查看 demo_results/ 目录中的详细测试结果")
        print("\n📖 更多信息请参考 README.md 文档")
        
    except KeyboardInterrupt:
        print("\n\n⚠️  演示被用户中断")
    except Exception as e:
        print(f"\n❌ 演示过程中发生错误: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
