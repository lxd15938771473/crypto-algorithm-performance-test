/**
 * 密码算法性能测试工具 - 前端JavaScript
 * 处理用户界面交互和与后端的通信
 */

class CryptoTestApp {
    constructor() {
        this.isRunning = false;
        this.currentTest = null;
        this.results = [];
        this.charts = {};
        
        this.init();
    }

    init() {
        this.bindEvents();
        this.loadSystemInfo();
        this.updateStatus('就绪');
    }

    bindEvents() {
        // 测试控制按钮
        document.getElementById('startTest').addEventListener('click', () => this.startTest());
        document.getElementById('stopTest').addEventListener('click', () => this.stopTest());
        
        // 结果控制按钮
        document.getElementById('exportResults').addEventListener('click', () => this.exportResults());
        document.getElementById('clearResults').addEventListener('click', () => this.clearResults());
        
        // 算法选择变化时更新UI
        const checkboxes = document.querySelectorAll('input[type="checkbox"]');
        checkboxes.forEach(checkbox => {
            checkbox.addEventListener('change', () => this.updateTestButton());
        });
    }

    async loadSystemInfo() {
        try {
            const response = await fetch('/api/system-info');
            if (response.ok) {
                const systemInfo = await response.json();
                this.displaySystemInfo(systemInfo);
            } else {
                // 模拟系统信息（如果后端不可用）
                this.displaySystemInfo({
                    cpu: 'CPU信息获取中...',
                    memory: '内存信息获取中...',
                    python: 'Python版本获取中...',
                    platform: '系统信息获取中...'
                });
            }
        } catch (error) {
            console.log('无法连接到后端，使用模拟数据');
            this.displaySystemInfo({
                cpu: '模拟CPU (4核/8线程)',
                memory: '16.0 GB',
                python: 'Python 3.9.0 (模拟)',
                platform: '模拟环境'
            });
        }
    }

    displaySystemInfo(info) {
        document.getElementById('cpuInfo').textContent = info.cpu || '未知';
        document.getElementById('memoryInfo').textContent = info.memory || '未知';
        document.getElementById('pythonInfo').textContent = info.python || '未知';
    }

    getSelectedAlgorithms() {
        const algorithms = [];
        
        // 对称加密算法
        const symmetric = ['aes', 'des', 'des3', 'chacha20'];
        symmetric.forEach(alg => {
            if (document.getElementById(alg).checked) {
                algorithms.push(alg);
            }
        });
        
        // 非对称加密算法
        const asymmetric = ['rsa', 'ecc', 'ecdsa'];
        asymmetric.forEach(alg => {
            if (document.getElementById(alg).checked) {
                algorithms.push(alg);
            }
        });
        
        // 哈希算法
        const hash = ['sha256', 'sha512', 'md5', 'blake2b'];
        hash.forEach(alg => {
            if (document.getElementById(alg).checked) {
                algorithms.push(alg);
            }
        });
        
        return algorithms;
    }

    getTestSettings() {
        return {
            algorithms: this.getSelectedAlgorithms(),
            iterations: parseInt(document.getElementById('iterations').value),
            dataSize: parseInt(document.getElementById('dataSize').value),
            outputFormat: document.getElementById('outputFormat').value,
            threadCount: parseInt(document.getElementById('threadCount').value)
        };
    }

    updateTestButton() {
        const selectedAlgorithms = this.getSelectedAlgorithms();
        const startButton = document.getElementById('startTest');
        
        if (selectedAlgorithms.length === 0) {
            startButton.disabled = true;
            startButton.innerHTML = '<i class="fas fa-exclamation-triangle"></i> 请选择至少一个算法';
        } else {
            startButton.disabled = this.isRunning;
            startButton.innerHTML = '<i class="fas fa-play"></i> 开始测试';
        }
    }

    async startTest() {
        const settings = this.getTestSettings();
        
        if (settings.algorithms.length === 0) {
            this.showAlert('请至少选择一个算法进行测试', 'warning');
            return;
        }

        this.isRunning = true;
        this.updateControlButtons();
        this.showProgress();
        this.showLog();
        this.updateStatus('运行中', true);

        this.addLog('开始密码算法性能测试...');
        this.addLog(`选中算法: ${settings.algorithms.join(', ')}`);
        this.addLog(`测试设置: ${settings.iterations}次迭代, ${this.formatDataSize(settings.dataSize)}数据`);

        try {
            // 尝试连接后端API
            const response = await fetch('/api/benchmark', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(settings)
            });

            if (response.ok) {
                const result = await response.json();
                this.handleTestResults(result);
            } else {
                // 如果后端不可用，运行模拟测试
                this.addLog('后端服务不可用，运行模拟测试...');
                await this.runSimulatedTest(settings);
            }
        } catch (error) {
            this.addLog('无法连接到后端服务，运行本地模拟测试...');
            await this.runSimulatedTest(settings);
        }

        this.isRunning = false;
        this.updateControlButtons();
        this.hideProgress();
        this.updateStatus('完成');
        this.addLog('测试完成！');
    }

    async runSimulatedTest(settings) {
        const algorithms = settings.algorithms;
        const totalSteps = algorithms.length;
        let currentStep = 0;

        for (const algorithm of algorithms) {
            if (!this.isRunning) break;

            this.addLog(`测试 ${algorithm.toUpperCase()}...`);
            this.updateProgress((currentStep / totalSteps) * 100);

            // 模拟测试延迟
            await this.delay(1000 + Math.random() * 2000);

            // 生成模拟结果
            const result = this.generateMockResult(algorithm, settings);
            this.results.push(result);
            this.displayResult(result);

            currentStep++;
            this.updateProgress((currentStep / totalSteps) * 100);
        }

        // 显示汇总结果
        this.displaySummary();
        this.createPerformanceChart();
    }

    generateMockResult(algorithm, settings) {
        const basePerformance = {
            // 对称加密算法基准性能 (MB/s)
            'aes': 200 + Math.random() * 100,
            'des': 50 + Math.random() * 20,
            'des3': 30 + Math.random() * 15,
            'chacha20': 180 + Math.random() * 80,
            
            // 哈希算法基准性能 (MB/s)
            'sha256': 150 + Math.random() * 50,
            'sha512': 120 + Math.random() * 40,
            'md5': 300 + Math.random() * 100,
            'blake2b': 250 + Math.random() * 80,
            
            // 非对称算法 (ops/sec)
            'rsa': 100 + Math.random() * 50,
            'ecc': 500 + Math.random() * 200,
            'ecdsa': 800 + Math.random() * 300
        };

        const performance = basePerformance[algorithm] || 100 + Math.random() * 50;
        const isAsymmetric = ['rsa', 'ecc', 'ecdsa'].includes(algorithm);
        
        return {
            algorithm: algorithm,
            category: this.getAlgorithmCategory(algorithm),
            performance: performance,
            unit: isAsymmetric ? 'ops/sec' : 'MB/s',
            latency: (1000 / performance) * (isAsymmetric ? 1 : 100),
            iterations: settings.iterations,
            dataSize: settings.dataSize,
            timestamp: Date.now()
        };
    }

    getAlgorithmCategory(algorithm) {
        if (['aes', 'des', 'des3', 'chacha20'].includes(algorithm)) {
            return '对称加密';
        } else if (['rsa', 'ecc', 'ecdsa'].includes(algorithm)) {
            return '非对称加密';
        } else {
            return '哈希算法';
        }
    }

    displayResult(result) {
        const resultsContent = document.getElementById('resultsContent');
        
        // 如果是第一个结果，清除占位符
        if (this.results.length === 1) {
            resultsContent.innerHTML = '';
        }

        const resultCard = document.createElement('div');
        resultCard.className = 'result-card';
        resultCard.innerHTML = `
            <div class="result-header">
                <div class="result-title">${result.algorithm.toUpperCase()}</div>
                <div class="result-badge">${result.category}</div>
            </div>
            <div class="metrics-grid">
                <div class="metric-item">
                    <div class="metric-value">${result.performance.toFixed(2)}</div>
                    <div class="metric-label">${result.unit}</div>
                </div>
                <div class="metric-item">
                    <div class="metric-value">${result.latency.toFixed(2)}</div>
                    <div class="metric-label">ms 延迟</div>
                </div>
                <div class="metric-item">
                    <div class="metric-value">${result.iterations}</div>
                    <div class="metric-label">迭代次数</div>
                </div>
                <div class="metric-item">
                    <div class="metric-value">${this.formatDataSize(result.dataSize)}</div>
                    <div class="metric-label">数据大小</div>
                </div>
            </div>
        `;

        resultsContent.appendChild(resultCard);
    }

    displaySummary() {
        if (this.results.length === 0) return;

        const summaryCard = document.createElement('div');
        summaryCard.className = 'result-card';
        summaryCard.style.borderLeft = '4px solid #48bb78';
        
        // 找出最佳性能
        const bestResult = this.results.reduce((best, current) => {
            return current.performance > best.performance ? current : best;
        });

        const averagePerformance = this.results.reduce((sum, result) => sum + result.performance, 0) / this.results.length;

        summaryCard.innerHTML = `
            <div class="result-header">
                <div class="result-title"><i class="fas fa-trophy"></i> 测试摘要</div>
                <div class="result-badge" style="background: #48bb78;">汇总</div>
            </div>
            <div class="metrics-grid">
                <div class="metric-item">
                    <div class="metric-value">${this.results.length}</div>
                    <div class="metric-label">测试算法数</div>
                </div>
                <div class="metric-item">
                    <div class="metric-value">${bestResult.algorithm.toUpperCase()}</div>
                    <div class="metric-label">最佳算法</div>
                </div>
                <div class="metric-item">
                    <div class="metric-value">${bestResult.performance.toFixed(2)}</div>
                    <div class="metric-label">最佳性能 (${bestResult.unit})</div>
                </div>
                <div class="metric-item">
                    <div class="metric-value">${averagePerformance.toFixed(2)}</div>
                    <div class="metric-label">平均性能</div>
                </div>
            </div>
        `;

        document.getElementById('resultsContent').appendChild(summaryCard);
    }

    createPerformanceChart() {
        // 创建图表容器
        const chartContainer = document.createElement('div');
        chartContainer.className = 'chart-container';
        chartContainer.innerHTML = '<canvas id="performanceChart" width="400" height="200"></canvas>';
        document.getElementById('resultsContent').appendChild(chartContainer);

        // 按类别分组数据
        const categories = {};
        this.results.forEach(result => {
            if (!categories[result.category]) {
                categories[result.category] = [];
            }
            categories[result.category].push(result);
        });

        // 准备图表数据
        const labels = this.results.map(result => result.algorithm.toUpperCase());
        const data = this.results.map(result => result.performance);
        const colors = this.results.map(result => this.getCategoryColor(result.category));

        // 创建图表
        const ctx = document.getElementById('performanceChart').getContext('2d');
        new Chart(ctx, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [{
                    label: '性能',
                    data: data,
                    backgroundColor: colors,
                    borderColor: colors.map(color => color.replace('0.7', '1')),
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    title: {
                        display: true,
                        text: '算法性能对比'
                    },
                    legend: {
                        display: false
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        title: {
                            display: true,
                            text: '性能值'
                        }
                    },
                    x: {
                        title: {
                            display: true,
                            text: '算法'
                        }
                    }
                }
            }
        });
    }

    getCategoryColor(category) {
        const colors = {
            '对称加密': 'rgba(102, 126, 234, 0.7)',
            '非对称加密': 'rgba(247, 147, 26, 0.7)',
            '哈希算法': 'rgba(72, 187, 120, 0.7)'
        };
        return colors[category] || 'rgba(128, 128, 128, 0.7)';
    }

    stopTest() {
        this.isRunning = false;
        this.addLog('测试被用户停止');
        this.updateStatus('已停止');
        this.updateControlButtons();
        this.hideProgress();
    }

    exportResults() {
        if (this.results.length === 0) {
            this.showAlert('没有可导出的结果', 'warning');
            return;
        }

        const settings = this.getTestSettings();
        const exportData = {
            timestamp: new Date().toISOString(),
            settings: settings,
            results: this.results,
            summary: {
                totalTests: this.results.length,
                bestPerformance: Math.max(...this.results.map(r => r.performance)),
                averagePerformance: this.results.reduce((sum, r) => sum + r.performance, 0) / this.results.length
            }
        };

        const dataStr = JSON.stringify(exportData, null, 2);
        const dataBlob = new Blob([dataStr], { type: 'application/json' });
        
        const link = document.createElement('a');
        link.href = URL.createObjectURL(dataBlob);
        link.download = `crypto-benchmark-${Date.now()}.json`;
        link.click();

        this.addLog('结果已导出到JSON文件');
    }

    clearResults() {
        this.results = [];
        const resultsContent = document.getElementById('resultsContent');
        resultsContent.innerHTML = `
            <div style="text-align: center; margin-top: 100px; color: #718096;">
                <i class="fas fa-chart-line" style="font-size: 4rem; margin-bottom: 20px;"></i>
                <p style="font-size: 1.2rem;">选择算法并点击"开始测试"来查看性能结果</p>
            </div>
        `;
        
        // 清除图表
        Object.values(this.charts).forEach(chart => {
            if (chart) chart.destroy();
        });
        this.charts = {};

        this.addLog('结果已清除');
    }

    updateControlButtons() {
        const startButton = document.getElementById('startTest');
        const stopButton = document.getElementById('stopTest');

        if (this.isRunning) {
            startButton.disabled = true;
            startButton.innerHTML = '<span class="spinner"></span> 测试中...';
            stopButton.disabled = false;
        } else {
            startButton.disabled = false;
            this.updateTestButton();
            stopButton.disabled = true;
        }
    }

    showProgress() {
        document.getElementById('progressContainer').style.display = 'block';
        this.updateProgress(0);
    }

    hideProgress() {
        document.getElementById('progressContainer').style.display = 'none';
    }

    updateProgress(percentage) {
        document.getElementById('progressFill').style.width = percentage + '%';
    }

    showLog() {
        document.getElementById('logContainer').style.display = 'block';
    }

    addLog(message) {
        const logContent = document.getElementById('logContent');
        const logEntry = document.createElement('div');
        logEntry.className = 'log-entry';
        
        const timestamp = new Date().toLocaleTimeString();
        logEntry.textContent = `[${timestamp}] ${message}`;
        
        logContent.appendChild(logEntry);
        logContent.scrollTop = logContent.scrollHeight;
    }

    updateStatus(status, isRunning = false) {
        const statusText = document.getElementById('statusText');
        const statusDot = document.getElementById('statusDot');
        
        statusText.textContent = status;
        
        if (isRunning) {
            statusDot.className = 'status-dot running';
        } else {
            statusDot.className = 'status-dot';
        }
    }

    formatDataSize(bytes) {
        const units = ['B', 'KB', 'MB', 'GB'];
        let size = bytes;
        let unitIndex = 0;
        
        while (size >= 1024 && unitIndex < units.length - 1) {
            size /= 1024;
            unitIndex++;
        }
        
        return `${size.toFixed(unitIndex > 0 ? 1 : 0)} ${units[unitIndex]}`;
    }

    showAlert(message, type = 'info') {
        // 创建简单的提示框
        const alert = document.createElement('div');
        alert.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 15px 20px;
            border-radius: 8px;
            color: white;
            font-weight: 600;
            z-index: 1000;
            background: ${type === 'warning' ? '#f56565' : '#4299e1'};
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        `;
        alert.textContent = message;
        
        document.body.appendChild(alert);
        
        setTimeout(() => {
            document.body.removeChild(alert);
        }, 3000);
    }

    delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    handleTestResults(results) {
        // 处理从后端返回的真实测试结果
        if (results.symmetric) {
            Object.keys(results.symmetric).forEach(algorithm => {
                const result = this.parseBackendResult(algorithm, results.symmetric[algorithm], '对称加密');
                if (result) {
                    this.results.push(result);
                    this.displayResult(result);
                }
            });
        }

        if (results.hash) {
            Object.keys(results.hash).forEach(algorithm => {
                const result = this.parseBackendResult(algorithm, results.hash[algorithm], '哈希算法');
                if (result) {
                    this.results.push(result);
                    this.displayResult(result);
                }
            });
        }

        if (results.asymmetric) {
            Object.keys(results.asymmetric).forEach(algorithm => {
                const result = this.parseBackendResult(algorithm, results.asymmetric[algorithm], '非对称加密');
                if (result) {
                    this.results.push(result);
                    this.displayResult(result);
                }
            });
        }

        this.displaySummary();
        this.createPerformanceChart();
    }

    parseBackendResult(algorithm, data, category) {
        // 解析后端返回的复杂结果结构，提取关键性能指标
        try {
            let performance = 0;
            let latency = 0;
            let iterations = 0;
            let dataSize = 0;

            // 遍历结果数据找到性能指标
            if (typeof data === 'object' && !data.error) {
                for (const key in data) {
                    const subData = data[key];
                    if (typeof subData === 'object') {
                        for (const subKey in subData) {
                            const metrics = subData[subKey];
                            if (metrics && typeof metrics === 'object') {
                                if (metrics.throughput_mbps) {
                                    performance = Math.max(performance, metrics.throughput_mbps);
                                }
                                if (metrics.latency_ms) {
                                    latency = metrics.latency_ms;
                                }
                                if (metrics.operations_per_second) {
                                    performance = Math.max(performance, metrics.operations_per_second);
                                }
                                if (metrics.iterations) {
                                    iterations = metrics.iterations;
                                }
                                if (metrics.data_size) {
                                    dataSize = metrics.data_size;
                                }
                            }
                        }
                    }
                }
            }

            if (performance > 0) {
                return {
                    algorithm: algorithm,
                    category: category,
                    performance: performance,
                    unit: category === '非对称加密' ? 'ops/sec' : 'MB/s',
                    latency: latency || (1000 / performance),
                    iterations: iterations || 100,
                    dataSize: dataSize || 65536,
                    timestamp: Date.now()
                };
            }
        } catch (error) {
            console.error('解析后端结果失败:', error);
        }

        return null;
    }
}

// 初始化应用
document.addEventListener('DOMContentLoaded', () => {
    window.cryptoApp = new CryptoTestApp();
});