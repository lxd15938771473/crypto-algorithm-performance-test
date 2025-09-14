"""
配置文件加载工具
"""

import yaml
import json
from pathlib import Path
from typing import Dict, Any, Union
from dataclasses import dataclass, field
from src.utils.logger import get_logger


@dataclass
class TestSettings:
    """测试设置配置"""
    data_sizes: list = field(default_factory=lambda: [1024, 8192, 65536, 1048576])
    iterations: int = 100
    warmup_rounds: int = 10
    timeout: int = 300


@dataclass
class AlgorithmConfig:
    """算法配置"""
    enabled: bool = True
    key_sizes: list = field(default_factory=list)
    modes: list = field(default_factory=list)
    curves: list = field(default_factory=list)


@dataclass
class MetricsConfig:
    """性能指标配置"""
    throughput: bool = True
    latency: bool = True
    cpu_usage: bool = True
    memory_usage: bool = True
    operations_per_second: bool = True


@dataclass
class OutputConfig:
    """输出配置"""
    generate_charts: bool = True
    generate_html_report: bool = True
    save_raw_data: bool = True
    compare_with_history: bool = False


@dataclass
class ThreadingConfig:
    """多线程测试配置"""
    enabled: bool = True
    thread_counts: list = field(default_factory=lambda: [1, 2, 4, 8, 16])


@dataclass
class MonitoringConfig:
    """系统监控配置"""
    enabled: bool = True
    sample_interval: float = 0.1


@dataclass
class BenchmarkConfig:
    """完整的基准测试配置"""
    test_settings: TestSettings = field(default_factory=TestSettings)
    symmetric_algorithms: Dict[str, AlgorithmConfig] = field(default_factory=dict)
    asymmetric_algorithms: Dict[str, AlgorithmConfig] = field(default_factory=dict)
    hash_algorithms: Dict[str, AlgorithmConfig] = field(default_factory=dict)
    metrics: MetricsConfig = field(default_factory=MetricsConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    threading: ThreadingConfig = field(default_factory=ThreadingConfig)
    monitoring: MonitoringConfig = field(default_factory=MonitoringConfig)


def load_config(config_path: Union[str, Path]) -> BenchmarkConfig:
    """
    从文件加载配置
    
    Args:
        config_path: 配置文件路径
    
    Returns:
        解析后的配置对象
    """
    logger = get_logger()
    config_path = Path(config_path)
    
    if not config_path.exists():
        logger.warning(f"配置文件不存在: {config_path}，使用默认配置")
        return BenchmarkConfig()
    
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            if config_path.suffix.lower() in ['.yaml', '.yml']:
                raw_config = yaml.safe_load(f)
            elif config_path.suffix.lower() == '.json':
                raw_config = json.load(f)
            else:
                logger.error(f"不支持的配置文件格式: {config_path.suffix}")
                return BenchmarkConfig()
        
        logger.info(f"成功加载配置文件: {config_path}")
        return _parse_config(raw_config)
        
    except Exception as e:
        logger.error(f"加载配置文件失败: {e}")
        logger.info("使用默认配置")
        return BenchmarkConfig()


def _parse_config(raw_config: Dict[str, Any]) -> BenchmarkConfig:
    """
    解析原始配置数据
    
    Args:
        raw_config: 原始配置字典
    
    Returns:
        解析后的配置对象
    """
    config = BenchmarkConfig()
    
    # 解析测试设置
    if 'test_settings' in raw_config:
        test_data = raw_config['test_settings']
        config.test_settings = TestSettings(
            data_sizes=test_data.get('data_sizes', [1024, 8192, 65536, 1048576]),
            iterations=test_data.get('iterations', 100),
            warmup_rounds=test_data.get('warmup_rounds', 10),
            timeout=test_data.get('timeout', 300)
        )
    
    # 解析算法配置
    config.symmetric_algorithms = _parse_algorithms(
        raw_config.get('symmetric_algorithms', {})
    )
    config.asymmetric_algorithms = _parse_algorithms(
        raw_config.get('asymmetric_algorithms', {})
    )
    config.hash_algorithms = _parse_algorithms(
        raw_config.get('hash_algorithms', {})
    )
    
    # 解析性能指标配置
    if 'metrics' in raw_config:
        metrics_data = raw_config['metrics']
        config.metrics = MetricsConfig(
            throughput=metrics_data.get('throughput', True),
            latency=metrics_data.get('latency', True),
            cpu_usage=metrics_data.get('cpu_usage', True),
            memory_usage=metrics_data.get('memory_usage', True),
            operations_per_second=metrics_data.get('operations_per_second', True)
        )
    
    # 解析输出配置
    if 'output' in raw_config:
        output_data = raw_config['output']
        config.output = OutputConfig(
            generate_charts=output_data.get('generate_charts', True),
            generate_html_report=output_data.get('generate_html_report', True),
            save_raw_data=output_data.get('save_raw_data', True),
            compare_with_history=output_data.get('compare_with_history', False)
        )
    
    # 解析多线程配置
    if 'threading' in raw_config:
        threading_data = raw_config['threading']
        config.threading = ThreadingConfig(
            enabled=threading_data.get('enabled', True),
            thread_counts=threading_data.get('thread_counts', [1, 2, 4, 8, 16])
        )
    
    # 解析监控配置
    if 'monitoring' in raw_config:
        monitoring_data = raw_config['monitoring']
        config.monitoring = MonitoringConfig(
            enabled=monitoring_data.get('enabled', True),
            sample_interval=monitoring_data.get('sample_interval', 0.1)
        )
    
    return config


def _parse_algorithms(algorithms_data: Dict[str, Any]) -> Dict[str, AlgorithmConfig]:
    """
    解析算法配置数据
    
    Args:
        algorithms_data: 算法配置字典
    
    Returns:
        解析后的算法配置字典
    """
    result = {}
    
    for alg_name, alg_data in algorithms_data.items():
        if isinstance(alg_data, dict):
            result[alg_name] = AlgorithmConfig(
                enabled=alg_data.get('enabled', True),
                key_sizes=alg_data.get('key_sizes', []),
                modes=alg_data.get('modes', []),
                curves=alg_data.get('curves', [])
            )
        else:
            # 简单的布尔值配置
            result[alg_name] = AlgorithmConfig(enabled=bool(alg_data))
    
    return result


def save_config(config: BenchmarkConfig, config_path: Union[str, Path]):
    """
    保存配置到文件
    
    Args:
        config: 配置对象
        config_path: 配置文件路径
    """
    logger = get_logger()
    config_path = Path(config_path)
    
    # 确保目录存在
    config_path.parent.mkdir(parents=True, exist_ok=True)
    
    # 转换为字典格式
    config_dict = _config_to_dict(config)
    
    try:
        with open(config_path, 'w', encoding='utf-8') as f:
            if config_path.suffix.lower() in ['.yaml', '.yml']:
                yaml.dump(config_dict, f, default_flow_style=False, 
                         allow_unicode=True, indent=2)
            elif config_path.suffix.lower() == '.json':
                json.dump(config_dict, f, indent=2, ensure_ascii=False)
            else:
                logger.error(f"不支持的配置文件格式: {config_path.suffix}")
                return
        
        logger.info(f"配置已保存到: {config_path}")
        
    except Exception as e:
        logger.error(f"保存配置文件失败: {e}")


def _config_to_dict(config: BenchmarkConfig) -> Dict[str, Any]:
    """
    将配置对象转换为字典
    
    Args:
        config: 配置对象
    
    Returns:
        配置字典
    """
    return {
        'test_settings': {
            'data_sizes': config.test_settings.data_sizes,
            'iterations': config.test_settings.iterations,
            'warmup_rounds': config.test_settings.warmup_rounds,
            'timeout': config.test_settings.timeout
        },
        'symmetric_algorithms': _algorithms_to_dict(config.symmetric_algorithms),
        'asymmetric_algorithms': _algorithms_to_dict(config.asymmetric_algorithms),
        'hash_algorithms': _algorithms_to_dict(config.hash_algorithms),
        'metrics': {
            'throughput': config.metrics.throughput,
            'latency': config.metrics.latency,
            'cpu_usage': config.metrics.cpu_usage,
            'memory_usage': config.metrics.memory_usage,
            'operations_per_second': config.metrics.operations_per_second
        },
        'output': {
            'generate_charts': config.output.generate_charts,
            'generate_html_report': config.output.generate_html_report,
            'save_raw_data': config.output.save_raw_data,
            'compare_with_history': config.output.compare_with_history
        },
        'threading': {
            'enabled': config.threading.enabled,
            'thread_counts': config.threading.thread_counts
        },
        'monitoring': {
            'enabled': config.monitoring.enabled,
            'sample_interval': config.monitoring.sample_interval
        }
    }


def _algorithms_to_dict(algorithms: Dict[str, AlgorithmConfig]) -> Dict[str, Any]:
    """
    将算法配置转换为字典
    
    Args:
        algorithms: 算法配置字典
    
    Returns:
        算法配置字典
    """
    result = {}
    
    for name, config in algorithms.items():
        alg_dict = {'enabled': config.enabled}
        
        if config.key_sizes:
            alg_dict['key_sizes'] = config.key_sizes
        if config.modes:
            alg_dict['modes'] = config.modes
        if config.curves:
            alg_dict['curves'] = config.curves
            
        result[name] = alg_dict
    
    return result


def create_default_config() -> BenchmarkConfig:
    """
    创建默认配置
    
    Returns:
        默认配置对象
    """
    config = BenchmarkConfig()
    
    # 设置默认的对称加密算法
    config.symmetric_algorithms = {
        'aes': AlgorithmConfig(
            enabled=True,
            key_sizes=[128, 192, 256],
            modes=['CBC', 'ECB', 'CTR', 'GCM']
        ),
        'des': AlgorithmConfig(
            enabled=True,
            key_sizes=[64],
            modes=['CBC', 'ECB']
        ),
        'des3': AlgorithmConfig(
            enabled=True,
            key_sizes=[192],
            modes=['CBC', 'ECB']
        ),
        'chacha20': AlgorithmConfig(
            enabled=True,
            key_sizes=[256],
            modes=['ChaCha20']
        )
    }
    
    # 设置默认的非对称加密算法
    config.asymmetric_algorithms = {
        'rsa': AlgorithmConfig(
            enabled=True,
            key_sizes=[1024, 2048, 3072, 4096]
        ),
        'ecc': AlgorithmConfig(
            enabled=True,
            curves=['secp256r1', 'secp384r1', 'secp521r1']
        ),
        'ecdsa': AlgorithmConfig(
            enabled=True,
            curves=['secp256r1', 'secp384r1', 'secp521r1']
        )
    }
    
    # 设置默认的哈希算法
    config.hash_algorithms = {
        'sha256': AlgorithmConfig(enabled=True),
        'sha512': AlgorithmConfig(enabled=True),
        'sha1': AlgorithmConfig(enabled=True),
        'md5': AlgorithmConfig(enabled=True),
        'blake2b': AlgorithmConfig(enabled=True),
        'blake2s': AlgorithmConfig(enabled=True)
    }
    
    return config


if __name__ == "__main__":
    # 测试代码
    config = create_default_config()
    save_config(config, "test_config.yaml")
    loaded_config = load_config("test_config.yaml")
    print("配置加载测试完成")
