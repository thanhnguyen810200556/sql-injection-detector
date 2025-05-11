document.addEventListener('DOMContentLoaded', function() {
    // Xử lý dropdown
    const navbarItems = document.querySelectorAll('.navbar__item');
    navbarItems.forEach(item => {
        item.addEventListener('click', function() {
            const dropdown = this.querySelector('.dropdown');
            if (dropdown) {
                // Chỉ toggle visibility thay vì display vì CSS đã xử lý transition
                if (dropdown.style.visibility === 'visible') {
                    dropdown.style.visibility = 'hidden';
                    dropdown.style.opacity = '0';
                    dropdown.style.transform = 'translateY(-20px)';
                } else {
                    dropdown.style.visibility = 'visible';
                    dropdown.style.opacity = '1';
                    dropdown.style.transform = 'translateY(0)';
                }
            }
        });
    });

    // Xử lý kiểm tra SQLi
    const searchButton = document.querySelector('.search-button');
    const searchInput = document.querySelector('.search-input');
    const resultContainer = document.getElementById('result-container');
    
    // Các phần tử kết quả
    const timestampEl = document.getElementById('timestamp');
    const isSqliEl = document.getElementById('is-sqli');
    const confidenceEl = document.getElementById('confidence');
    const severityEl = document.getElementById('severity');
    const ruleScoreEl = document.getElementById('rule-score');
    const mlScoreEl = document.getElementById('ml-score');
    const execTimeEl = document.getElementById('execution-time');
    const patternsList = document.getElementById('detected-patterns');
    const patternsSection = document.getElementById('patterns-section');

    searchButton.addEventListener('click', checkSQLi);
    searchInput.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') checkSQLi();
    });

    async function checkSQLi() {
        const query = searchInput.value.trim();
        if (!query) return;

        // Hiển thị trạng thái đang kiểm tra
        resultContainer.style.display = 'flex';
        isSqliEl.textContent = 'Đang kiểm tra...';
        isSqliEl.className = 'result-value loading';
        
        // Ẩn các phần tử khác trong khi đang kiểm tra
        confidenceEl.textContent = '';
        severityEl.textContent = '';
        ruleScoreEl.textContent = '';
        mlScoreEl.textContent = '';
        execTimeEl.textContent = '';
        patternsList.innerHTML = '';
        patternsSection.style.display = 'none';

        try {
            const response = await fetch('/api/detect', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ query: query })
            });

            const data = await response.json();

            if (data.success) {
                displayResults(data.result);
            } else {
                showError('Lỗi khi xử lý truy vấn');
            }
        } catch (error) {
            console.error(error);
            showError('Lỗi kết nối đến server');
        }
    }

    function displayResults(result) {
        // Cập nhật thời gian
        const currentTime = new Date().toLocaleString('vi-VN');
        timestampEl.textContent = `Thời gian: ${currentTime}`;
        
        // Hiển thị kết quả chính
        isSqliEl.textContent = result.is_sqli ? 'CÓ SQL INJECTION' : 'KHÔNG CÓ SQL INJECTION';
        isSqliEl.className = `result-value ${result.is_sqli ? 'attack-true' : 'attack-false'}`;
        
        // Hiển thị các thông số
        confidenceEl.textContent = `${(result.confidence * 100).toFixed(2)}%`;
        
        // Hiển thị mức độ và áp dụng class tương ứng
        const severityText = getSeverityText(result.confidence);
        severityEl.textContent = severityText;
        severityEl.className = `result-value severity-${severityText.toLowerCase()}`;
        
        // Hiển thị các điểm số
        ruleScoreEl.textContent = `${(result.rule_score * 100).toFixed(2)}%`;
        mlScoreEl.textContent = `${(result.ml_score * 100).toFixed(2)}%`;
        
        // Hiển thị thời gian xử lý
        execTimeEl.textContent = `${result.execution_time.toFixed(2)} ms`;
        
        // Hiển thị các mẫu đáng ngờ nếu có
        if (result.detected_patterns && result.detected_patterns.length > 0) {
            patternsList.innerHTML = '';
            result.detected_patterns.forEach(pattern => {
                const li = document.createElement('li');
                li.textContent = pattern;
                patternsList.appendChild(li);
            });
            patternsSection.style.display = 'block';
        } else {
            patternsSection.style.display = 'none';
        }
    }

    function getSeverityText(confidence) {
        if (confidence >= 0.8) return 'HIGH';
        if (confidence >= 0.5) return 'MEDIUM';
        return 'LOW';
    }

    function showError(message) {
        isSqliEl.textContent = message;
        isSqliEl.className = 'result-value error';
        
        // Hiển thị thời gian xảy ra lỗi
        const currentTime = new Date().toLocaleString('vi-VN');
        timestampEl.textContent = `Thời gian: ${currentTime}`;
    }
});
