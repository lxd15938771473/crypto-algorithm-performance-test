"""
日志配置工具
"""

import logging
import sys
from pathlib import Path
from datetime import datetime
from rich.console import Console
from rich.logging import RichHandler
from typing import Optional


def setup_logger(
    name: str = "crypto_benchmark",
    level: int = logging.INFO,
    verbose: bool = False,
    log_file: Optional[str] = None,
    console_output: bool = True
) -> logging.Logger:
    """
    设置日志记录器
    
    Args:
        name: 日志记录器名称
        level: 日志级别
        verbose: 是否启用详细模式
        log_file: 日志文件路径
        console_output: 是否输出到控制台
    
    Returns:
        配置好的日志记录器
    """
    
    # 如果启用verbose模式，设置为DEBUG级别
    if verbose:
        level = logging.DEBUG
    
    # 创建日志记录器
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # 清除现有的处理器
    logger.handlers.clear()
    
    # 创建格式化器
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # 添加控制台处理器（使用Rich进行美化）
    if console_output:
        console = Console()
        console_handler = RichHandler(
            console=console,
            show_time=True,
            show_level=True,
            show_path=False,
            markup=True,
            rich_tracebacks=True
        )
        console_handler.setLevel(level)
        logger.addHandler(console_handler)
    
    # 添加文件处理器
    if log_file:
        # 确保日志目录存在
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    return logger


def create_log_filename(prefix: str = "benchmark", extension: str = "log") -> str:
    """
    创建带时间戳的日志文件名
    
    Args:
        prefix: 文件名前缀
        extension: 文件扩展名
    
    Returns:
        生成的日志文件名
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{prefix}_{timestamp}.{extension}"


class BenchmarkLogger:
    """基准测试专用日志记录器"""
    
    def __init__(self, output_dir: Path, verbose: bool = False):
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # 创建日志文件名
        log_filename = create_log_filename("crypto_benchmark")
        log_file = self.output_dir / "logs" / log_filename
        
        # 设置日志记录器
        self.logger = setup_logger(
            name="benchmark",
            verbose=verbose,
            log_file=str(log_file)
        )
        
        self.test_results = []
    
    def info(self, message: str):
        """记录信息日志"""
        self.logger.info(message)
    
    def debug(self, message: str):
        """记录调试日志"""
        self.logger.debug(message)
    
    def warning(self, message: str):
        """记录警告日志"""
        self.logger.warning(message)
    
    def error(self, message: str):
        """记录错误日志"""
        self.logger.error(message)
    
    def log_test_start(self, algorithm: str, test_type: str, **kwargs):
        """记录测试开始"""
        params = ", ".join(f"{k}={v}" for k, v in kwargs.items())
        message = f"开始测试 {algorithm} - {test_type}"
        if params:
            message += f" ({params})"
        self.info(message)
    
    def log_test_result(self, algorithm: str, test_type: str, result: dict):
        """记录测试结果"""
        self.test_results.append({
            'algorithm': algorithm,
            'test_type': test_type,
            'result': result,
            'timestamp': datetime.now().isoformat()
        })
        
        # 格式化结果信息
        if 'throughput' in result:
            throughput = result['throughput']
            self.info(f"{algorithm} {test_type} - 吞吐量: {throughput:.2f} MB/s")
        
        if 'latency' in result:
            latency = result['latency']
            self.info(f"{algorithm} {test_type} - 平均延迟: {latency:.2f} ms")
        
        if 'operations_per_second' in result:
            ops = result['operations_per_second']
            self.info(f"{algorithm} {test_type} - 操作/秒: {ops:.0f}")
    
    def log_error(self, algorithm: str, test_type: str, error: Exception):
        """记录测试错误"""
        self.error(f"{algorithm} {test_type} 测试失败: {str(error)}")
    
    def log_system_info(self, system_info: dict):
        """记录系统信息"""
        self.info("系统信息:")
        for key, value in system_info.items():
            self.info(f"  {key}: {value}")
    
    def get_test_summary(self) -> dict:
        """获取测试摘要"""
        if not self.test_results:
            return {"total_tests": 0, "successful_tests": 0, "failed_tests": 0}
        
        total = len(self.test_results)
        successful = len([r for r in self.test_results if 'error' not in r['result']])
        failed = total - successful
        
        return {
            "total_tests": total,
            "successful_tests": successful,
            "failed_tests": failed,
            "success_rate": (successful / total) * 100 if total > 0 else 0
        }


# 全局日志记录器实例
_global_logger = None

def get_logger() -> logging.Logger:
    """获取全局日志记录器"""
    global _global_logger
    if _global_logger is None:
        _global_logger = setup_logger()
    return _global_logger


if __name__ == "__main__":
    # 测试代码
    logger = setup_logger(verbose=True)
    logger.info("这是一个信息日志")
    logger.debug("这是一个调试日志")
    logger.warning("这是一个警告日志")
    logger.error("这是一个错误日志")
    
    # 测试基准测试日志记录器
    benchmark_logger = BenchmarkLogger(Path("./test_logs"), verbose=True)
    benchmark_logger.log_test_start("AES-256", "encryption", key_size=256, data_size=1024)
    benchmark_logger.log_test_result("AES-256", "encryption", {
        "throughput": 150.5,
        "latency": 6.67,
        "operations_per_second": 15000
    })
    
    print("测试摘要:", benchmark_logger.get_test_summary())
