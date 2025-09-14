#!/usr/bin/env python3
"""
密码算法性能测试工具
主入口文件
"""

import os
import sys
import time
import argparse
from pathlib import Path

# 添加src目录到Python路径
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from src.benchmarks.benchmark_runner import BenchmarkRunner
from src.utils.logger import setup_logger
from src.utils.config import load_config
from src.utils.system_info import SystemInfo

def main():
    """主函数"""
    parser = argparse.ArgumentParser(description='密码算法性能测试工具')
    parser.add_argument('--config', '-c', default='config/default.yaml', 
                       help='配置文件路径')
    parser.add_argument('--algorithms', '-a', nargs='+', 
                       help='指定要测试的算法')
    parser.add_argument('--output', '-o', default='results', 
                       help='结果输出目录')
    parser.add_argument('--verbose', '-v', action='store_true', 
                       help='详细输出')
    parser.add_argument('--format', '-f', choices=['json', 'csv', 'html'], 
                       default='json', help='输出格式')
    
    args = parser.parse_args()
    
    # 设置日志
    logger = setup_logger(verbose=args.verbose)
    
    # 显示系统信息
    system_info = SystemInfo()
    logger.info("系统信息:")
    logger.info(f"CPU: {system_info.get_cpu_info()}")
    logger.info(f"内存: {system_info.get_memory_info()}")
    logger.info(f"Python版本: {system_info.get_python_version()}")
    
    # 加载配置
    config = load_config(args.config)
    
    # 创建输出目录
    output_dir = Path(args.output)
    output_dir.mkdir(exist_ok=True)
    
    # 运行基准测试
    runner = BenchmarkRunner(config, output_dir, args.format)
    
    logger.info("开始运行密码算法性能测试...")
    start_time = time.time()
    
    try:
        if args.algorithms:
            # 只测试指定的算法
            results = runner.run_selected_benchmarks(args.algorithms)
        else:
            # 运行所有配置的测试
            results = runner.run_all_benchmarks()
            
        end_time = time.time()
        logger.info(f"测试完成！总耗时: {end_time - start_time:.2f} 秒")
        logger.info(f"结果已保存到: {output_dir}")
        
        # 显示简要结果摘要
        runner.print_summary(results)
        
    except KeyboardInterrupt:
        logger.info("测试被用户中断")
        sys.exit(1)
    except Exception as e:
        logger.error(f"测试过程中发生错误: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
