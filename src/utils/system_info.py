"""
系统信息获取工具
"""

import platform
import psutil
import cpuinfo
import sys
from typing import Dict, Any


class SystemInfo:
    """系统信息获取类"""
    
    def __init__(self):
        self.cpu_info = None
        self.memory_info = None
        self._collect_static_info()
    
    def _collect_static_info(self):
        """收集静态系统信息"""
        try:
            self.cpu_info = cpuinfo.get_cpu_info()
        except Exception:
            self.cpu_info = {}
    
    def get_cpu_info(self) -> str:
        """获取CPU信息"""
        if self.cpu_info:
            brand = self.cpu_info.get('brand_raw', 'Unknown CPU')
            arch = self.cpu_info.get('arch', 'Unknown')
            cores = psutil.cpu_count(logical=False)
            threads = psutil.cpu_count(logical=True)
            return f"{brand} ({arch}, {cores}核/{threads}线程)"
        else:
            cores = psutil.cpu_count(logical=False)
            threads = psutil.cpu_count(logical=True)
            return f"CPU信息获取失败 ({cores}核/{threads}线程)"
    
    def get_memory_info(self) -> str:
        """获取内存信息"""
        memory = psutil.virtual_memory()
        total_gb = memory.total / (1024**3)
        return f"{total_gb:.1f} GB"
    
    def get_python_version(self) -> str:
        """获取Python版本信息"""
        return f"{sys.version.split()[0]} ({sys.platform})"
    
    def get_platform_info(self) -> str:
        """获取平台信息"""
        return f"{platform.system()} {platform.release()}"
    
    def get_current_cpu_usage(self) -> float:
        """获取当前CPU使用率"""
        return psutil.cpu_percent(interval=1.0)
    
    def get_current_memory_usage(self) -> Dict[str, float]:
        """获取当前内存使用情况"""
        memory = psutil.virtual_memory()
        return {
            'percent': memory.percent,
            'available_gb': memory.available / (1024**3),
            'used_gb': memory.used / (1024**3)
        }
    
    def get_disk_usage(self, path: str = '.') -> Dict[str, float]:
        """获取磁盘使用情况"""
        disk = psutil.disk_usage(path)
        return {
            'total_gb': disk.total / (1024**3),
            'used_gb': disk.used / (1024**3),
            'free_gb': disk.free / (1024**3),
            'percent': (disk.used / disk.total) * 100
        }
    
    def get_all_info(self) -> Dict[str, Any]:
        """获取所有系统信息"""
        return {
            'cpu': self.get_cpu_info(),
            'memory': self.get_memory_info(),
            'python': self.get_python_version(),
            'platform': self.get_platform_info(),
            'current_cpu_usage': self.get_current_cpu_usage(),
            'current_memory_usage': self.get_current_memory_usage(),
            'disk_usage': self.get_disk_usage()
        }
    
    def print_system_info(self):
        """打印系统信息"""
        info = self.get_all_info()
        print("=" * 50)
        print("系统信息")
        print("=" * 50)
        print(f"CPU: {info['cpu']}")
        print(f"内存: {info['memory']}")
        print(f"Python: {info['python']}")
        print(f"操作系统: {info['platform']}")
        print(f"当前CPU使用率: {info['current_cpu_usage']:.1f}%")
        
        mem_usage = info['current_memory_usage']
        print(f"当前内存使用: {mem_usage['percent']:.1f}% "
              f"({mem_usage['used_gb']:.1f}GB/{mem_usage['used_gb'] + mem_usage['available_gb']:.1f}GB)")
        
        disk_usage = info['disk_usage']
        print(f"磁盘使用: {disk_usage['percent']:.1f}% "
              f"({disk_usage['used_gb']:.1f}GB/{disk_usage['total_gb']:.1f}GB)")
        print("=" * 50)


if __name__ == "__main__":
    # 测试代码
    system_info = SystemInfo()
    system_info.print_system_info()
