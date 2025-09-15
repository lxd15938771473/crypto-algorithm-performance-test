/**
 * 简化版前端测试脚本
 */

// 简单测试函数
function simpleTest() {
    console.log("开始简单测试...");
    
    // 显示进度条
    document.getElementById('progressContainer').style.display = 'block';
    document.getElementById('progressFill').style.width = '0%';
    
    // 模拟测试进度
    let progress = 0;
    const interval = setInterval(() => {
        progress += 10;
        document.getElementById('progressFill').style.width = progress + '%';
        
        if (progress >= 100) {
            clearInterval(interval);
            showSimpleResult();
        }
    }, 300);
}

function showSimpleResult() {
    const resultsContent = document.getElementById('resultsContent');
    resultsContent.innerHTML = `
        <div class="result-card">
            <div class="result-header">
                <div class="result-title">测试成功！</div>
                <div class="result-badge">模拟结果</div>
            </div>
            <div class="metrics-grid">
                <div class="metric-item">
                    <div class="metric-value">150.5</div>
                    <div class="metric-label">MB/s</div>
                </div>
                <div class="metric-item">
                    <div class="metric-value">6.67</div>
                    <div class="metric-label">ms 延迟</div>
                </div>
            </div>
        </div>
    `;
    console.log("测试完成！");
}

// 页面加载完成后执行
document.addEventListener('DOMContentLoaded', function() {
    console.log("页面加载完成，开始初始化...");
    
    // 添加简单测试按钮
    const buttonGroup = document.querySelector('.button-group');
    if (buttonGroup) {
        const simpleTestBtn = document.createElement('button');
        simpleTestBtn.className = 'btn btn-secondary';
        simpleTestBtn.innerHTML = '<i class="fas fa-flask"></i> 简单测试';
        simpleTestBtn.onclick = simpleTest;
        buttonGroup.appendChild(simpleTestBtn);
        console.log("简单测试按钮已添加");
    }
    
    // 检查主要元素是否存在
    const checkElements = [
        'startTest', 'stopTest', 'resultsContent', 
        'progressContainer', 'systemInfo'
    ];
    
    checkElements.forEach(id => {
        const element = document.getElementById(id);
        if (element) {
            console.log(`✅ 元素 ${id} 存在`);
        } else {
            console.error(`❌ 元素 ${id} 不存在`);
        }
    });
    
    // 检查算法选择框
    const algorithms = ['aes', 'sha256', 'rsa'];
    algorithms.forEach(alg => {
        const checkbox = document.getElementById(alg);
        if (checkbox) {
            console.log(`✅ 算法 ${alg} 选择框存在`);
        } else {
            console.error(`❌ 算法 ${alg} 选择框不存在`);
        }
    });
    
    console.log("初始化完成！如果上面有❌错误，说明HTML结构有问题");
});
