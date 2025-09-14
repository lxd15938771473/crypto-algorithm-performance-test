# 密码算法性能测试工具

这个仓库提供了用于测试各种密码算法性能和效率的工具集。支持多种加密算法的基准测试，包括对称加密、非对称加密、哈希函数等。

## 功能特性

- 🔐 **对称加密算法测试**：AES、DES、3DES、ChaCha20等
- 🗝️ **非对称加密算法测试**：RSA、ECC、ECDSA等  
- 🔍 **哈希函数测试**：SHA-256、SHA-512、MD5、Blake2等
- 📊 **性能基准测试**：吞吐量、延迟、内存使用等指标
- 📈 **结果可视化**：生成性能图表和报告
- ⚡ **多线程测试**：支持并发性能测试

## 项目结构

```
├── src/                    # 源代码目录
│   ├── algorithms/         # 算法实现
│   ├── benchmarks/         # 基准测试代码
│   └── utils/             # 工具函数
├── tests/                 # 测试用例
├── results/               # 测试结果存储
├── docs/                  # 文档
└── requirements.txt       # Python依赖
```

## 快速开始

1. 克隆仓库
```bash
git clone https://github.com/lxd15938771473/crypto-algorithm-performance-test.git
cd crypto-algorithm-performance-test
```

2. 安装依赖
```bash
pip install -r requirements.txt
```

3. 运行基准测试
```bash
python src/main.py
```

## 贡献指南

欢迎提交Issue和Pull Request来改进这个项目！

## 许可证

MIT License
