# 密码算法性能测试工具

这个仓库提供了用于测试各种密码算法性能和效率的完整工具集，支持命令行和现代化Web界面两种使用方式。支持多种加密算法的基准测试，包括对称加密、非对称加密、哈希函数等。

## ✨ 功能特性

- 🔐 **对称加密算法测试**：AES、DES、3DES、ChaCha20等
- 🗝️ **非对称加密算法测试**：RSA、ECC、ECDSA等  
- 🔍 **哈希函数测试**：SHA-256、SHA-512、MD5、Blake2等
- 📊 **性能基准测试**：吞吐量、延迟、内存使用等指标
- 📈 **结果可视化**：生成性能图表和报告
- ⚡ **多线程测试**：支持并发性能测试
- 🌐 **现代化Web界面**：直观的图形化操作界面
- 🚀 **实时监控**：实时显示测试进度和系统状态
- 📱 **响应式设计**：支持桌面和移动设备

## 🎯 使用方式

### 方式一：Web界面（推荐）

1. **启动Web服务器**
```bash
# 安装依赖
pip install -r requirements.txt

# 启动Web服务器
python web_server.py
```

2. **打开浏览器**
```
访问: http://127.0.0.1:5000
```

3. **使用Web界面**
   - ✅ 选择要测试的算法
   - ⚙️ 配置测试参数（迭代次数、数据大小等）
   - ▶️ 点击"开始测试"按钮
   - 📊 实时查看测试结果和性能图表
   - 💾 导出结果为JSON格式

### 方式二：命令行界面

1. **克隆仓库**
```bash
git clone https://github.com/lxd15938771473/crypto-algorithm-performance-test.git
cd crypto-algorithm-performance-test
```

2. **安装依赖**
```bash
pip install -r requirements.txt
```

3. **运行基准测试**
```bash
# 运行所有配置的测试
python main.py

# 使用自定义配置文件
python main.py -c config/default.yaml

# 只测试特定算法
python main.py -a aes sha256 rsa

# 指定输出格式和目录
python main.py -o results -f json

# 启用详细输出
python main.py -v
```

4. **快速演示**
```bash
# 运行演示脚本
python demo.py
```

## 📁 项目结构

```
crypto-algorithm-performance-test/
├── 📄 README.md                    # 项目说明文档
├── 📦 requirements.txt             # Python依赖包
├── 🚀 main.py                     # 命令行主程序入口
├── 🌐 web_server.py               # Web服务器
├── 🎯 demo.py                     # 快速演示脚本
├── 📝 .gitignore                  # Git忽略文件配置
├── 📁 web/                        # Web前端文件
│   ├── 🌐 index.html              # Web界面主页
│   └── 📁 js/
│       └── ⚙️ main.js             # 前端JavaScript代码
├── 📁 config/
│   └── ⚙️ default.yaml            # 默认配置文件
├── 📁 src/                        # 源代码目录
│   ├── 🧩 __init__.py
│   ├── 📁 algorithms/             # 算法实现
│   │   ├── 🔒 symmetric.py        # 对称加密算法
│   │   ├── 🔑 asymmetric.py       # 非对称加密算法
│   │   ├── #️⃣ hash_functions.py   # 哈希函数
│   │   └── 🧩 __init__.py
│   ├── 📁 benchmarks/             # 基准测试
│   │   ├── ⚡ benchmark_runner.py  # 基准测试运行器
│   │   └── 🧩 __init__.py
│   └── 📁 utils/                  # 工具函数
│       ├── 📋 logger.py           # 日志工具
│       ├── ⚙️ config.py           # 配置加载器
│       ├── 🖥️ system_info.py       # 系统信息
│       └── 🧩 __init__.py
└── 📁 tests/                      # 测试用例
    └── 🧪 test_basic_functionality.py
```

## 🚀 快速开始

### Web界面快速开始

```bash
# 1. 安装依赖
pip install Flask Flask-CORS cryptography pycryptodome psutil

# 2. 启动Web服务器
python web_server.py

# 3. 打开浏览器访问
# http://127.0.0.1:5000
```

### 命令行快速开始

```bash
# 快速测试AES和SHA256算法
python main.py -a aes sha256 -o quick_test

# 查看结果
ls quick_test/
```

## 📊 Web界面功能说明

### 🎛️ 控制面板
- **系统信息**：显示CPU、内存、Python版本等信息
- **算法选择**：通过复选框选择要测试的算法
- **测试设置**：配置迭代次数、数据大小、线程数等参数
- **控制按钮**：开始测试、停止测试、导出结果、清除结果

### 📈 结果面板
- **实时结果**：显示每个算法的性能指标
- **性能图表**：可视化性能对比
- **测试日志**：实时显示测试进度和状态
- **结果导出**：支持JSON格式导出

### 📱 响应式设计
- 支持桌面和移动设备
- 自适应屏幕大小
- 触摸友好的操作界面

## 🔧 配置说明

### Web服务器配置

Web服务器默认运行在 `http://127.0.0.1:5000`，可以通过修改 `web_server.py` 中的配置来改变：

```python
# 修改主机和端口
host = '0.0.0.0'  # 允许外部访问
port = 8080       # 使用8080端口
```

### 测试配置

可以通过 `config/default.yaml` 文件来配置默认的测试参数：

```yaml
test_settings:
  data_sizes: [1024, 8192, 65536, 1048576]  # 测试数据大小
  iterations: 100                           # 迭代次数
  warmup_rounds: 10                         # 预热轮数
  timeout: 300                              # 超时时间

# 算法配置
symmetric_algorithms:
  aes:
    enabled: true
    key_sizes: [128, 192, 256]
    modes: ['CBC', 'ECB', 'CTR', 'GCM']
```

## 🧪 测试

运行单元测试：

```bash
python tests/test_basic_functionality.py
```

运行演示：

```bash
python demo.py
```

## 📊 性能指标说明

### 对称加密和哈希算法
- **吞吐量 (MB/s)**：每秒处理的数据量
- **延迟 (ms)**：单次操作的平均耗时
- **操作/秒**：每秒完成的操作数量

### 非对称加密算法
- **操作/秒 (ops/sec)**：每秒完成的签名/验证操作数
- **延迟 (ms)**：单次操作的平均耗时

## 🌐 API接口

Web服务器提供RESTful API接口，便于自动化测试：

```bash
# 获取系统信息
curl http://127.0.0.1:5000/api/system-info

# 开始基准测试
curl -X POST http://127.0.0.1:5000/api/benchmark \
  -H "Content-Type: application/json" \
  -d '{"algorithms": ["aes", "sha256"], "iterations": 100, "dataSize": 65536}'

# 获取测试状态
curl http://127.0.0.1:5000/api/benchmark/status

# 获取测试结果
curl http://127.0.0.1:5000/api/benchmark/results

# 停止测试
curl -X POST http://127.0.0.1:5000/api/benchmark/stop
```

### API端点说明

| 端点 | 方法 | 说明 |
|------|------|------|
| `/api/system-info` | GET | 获取系统信息 |
| `/api/benchmark` | POST | 开始基准测试 |
| `/api/benchmark/status` | GET | 获取测试状态和进度 |
| `/api/benchmark/results` | GET | 获取测试结果 |
| `/api/benchmark/stop` | POST | 停止正在运行的测试 |
| `/api/benchmark/clear` | POST | 清除测试结果 |
| `/api/export` | POST | 导出测试结果 |
| `/api/algorithms` | GET | 获取支持的算法列表 |

## 🎨 Web界面特性

### 现代化设计
- 🎨 **渐变背景**：美观的紫色渐变背景
- 🌟 **玻璃态效果**：半透明背景与模糊效果
- ✨ **流畅动画**：按钮悬停和加载动画
- 📱 **响应式布局**：适配各种屏幕尺寸

### 交互体验
- ⚡ **实时更新**：测试进度和结果实时显示
- 🔄 **异步处理**：非阻塞的后台测试执行
- 📊 **动态图表**：使用Chart.js生成性能对比图
- 🚨 **状态提示**：清晰的成功/错误提示信息

### 用户友好
- 🎯 **一键测试**：简单的点击操作
- 📋 **智能验证**：防止无效操作
- 💾 **结果导出**：方便的数据导出功能
- 🔍 **详细日志**：完整的测试过程记录

## 🔍 支持的算法

### 对称加密算法
| 算法 | 密钥长度 | 加密模式 | 说明 |
|------|----------|----------|------|
| AES | 128/192/256位 | CBC/ECB/CTR/GCM | 高级加密标准 |
| DES | 64位 | CBC/ECB | 数据加密标准 |
| 3DES | 192位 | CBC/ECB | 三重DES |
| ChaCha20 | 256位 | 流密码 | 现代流加密算法 |

### 非对称加密算法
| 算法 | 密钥长度 | 用途 | 说明 |
|------|----------|------|------|
| RSA | 1024/2048/3072/4096位 | 加密/签名 | RSA公钥密码学 |
| ECC | P-256/P-384/P-521 | 加密 | 椭圆曲线密码学 |
| ECDSA | P-256/P-384/P-521 | 数字签名 | 椭圆曲线数字签名 |

### 哈希算法
| 算法 | 输出长度 | 安全性 | 说明 |
|------|----------|--------|------|
| SHA-256 | 256位 | 高 | 安全哈希算法 |
| SHA-512 | 512位 | 高 | 安全哈希算法 |
| MD5 | 128位 | 低 | 消息摘要算法 |
| BLAKE2b | 可变 | 高 | 现代哈希函数 |
| BLAKE2s | 可变 | 高 | 现代哈希函数 |

## 🛠️ 开发和扩展

### 添加新算法

1. 在相应的算法模块中实现新算法类
2. 更新算法创建工厂函数
3. 在配置文件中添加算法配置
4. 更新Web界面的算法选择列表

### 自定义测试

```python
from src.algorithms import create_symmetric_cipher

# 创建自定义测试
cipher = create_symmetric_cipher('aes', 256, 'GCM')
test_data = b'your test data here'
result = cipher.benchmark_encrypt(test_data, 1000)
print(f"性能: {result['throughput_mbps']:.2f} MB/s")
```

## ⚠️ 注意事项

1. **安全性**：本工具仅用于性能测试，不应用于生产环境的安全实现
2. **系统资源**：某些测试可能消耗大量CPU和内存资源
3. **网络访问**：Web服务器默认只监听本地地址，如需外部访问请修改配置
4. **兼容性**：推荐使用Python 3.8+版本
5. **依赖项**：确保所有required依赖都已正确安装

## 🤝 贡献指南

欢迎提交Issue和Pull Request来改进这个项目！

1. Fork此项目
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 打开Pull Request

## 📄 许可证

MIT License - 详见 [LICENSE](LICENSE) 文件

## 📞 支持与反馈

如果您在使用过程中遇到问题或有改进建议，请：

- 📝 提交Issue：[GitHub Issues](https://github.com/lxd15938771473/crypto-algorithm-performance-test/issues)
- ⭐ 给项目加星：如果这个工具对您有帮助
- 🔄 分享项目：推荐给其他需要的开发者

---

**🔐 让密码算法性能测试变得简单高效！**