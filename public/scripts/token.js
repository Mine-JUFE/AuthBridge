
    (function() {
        const tokenEl = document.getElementById('jwt-token');
        const copyBtn = document.getElementById('copy-btn');
        const emptyState = document.getElementById('empty-state');
        const token = tokenEl.getAttribute('data-token') || tokenEl.textContent;

        // 空状态处理
        if (!token || token === 'undefined') {
            tokenEl.style.display = 'none';
            copyBtn.style.display = 'none';
            emptyState.classList.remove('hidden');
            return;
        }

        // ========== 核心：可拖动选择复制 ==========
        let isDragging = false;
        let startX = 0;
        let scrollLeft = 0;

        // 鼠标拖动滚动（兼容文本选择）
        tokenEl.addEventListener('mousedown', function(e) {
            // 只有点击空白处才触发拖动，选中文本时不触发
            if (window.getSelection().toString() === '') {
                isDragging = true;
                startX = e.pageX - tokenEl.offsetLeft;
                scrollLeft = tokenEl.scrollLeft;
                tokenEl.style.cursor = 'grabbing';
                e.preventDefault(); // 防止文本选中
            }
        });

        document.addEventListener('mousemove', function(e) {
            if (!isDragging) return;
            const x = e.pageX - tokenEl.offsetLeft;
            const walk = (x - startX) * 1.2; // 拖动速度
            tokenEl.scrollLeft = scrollLeft - walk;
        });

        document.addEventListener('mouseup', function() {
            isDragging = false;
            tokenEl.style.cursor = 'text';
        });

        // 移动端触摸拖动
        tokenEl.addEventListener('touchstart', function(e) {
            isDragging = true;
            startX = e.touches[0].pageX - tokenEl.offsetLeft;
            scrollLeft = tokenEl.scrollLeft;
            e.preventDefault();
        });

        document.addEventListener('touchmove', function(e) {
            if (!isDragging) return;
            const x = e.touches[0].pageX - tokenEl.offsetLeft;
            const walk = (x - startX) * 1.2;
            tokenEl.scrollLeft = scrollLeft - walk;
        });

        document.addEventListener('touchend', function() {
            isDragging = false;
        });

        // ========== 高对比度复制按钮 ==========
        copyBtn.addEventListener('click', async function() {
            try {
                await navigator.clipboard.writeText(token);
                // 复制成功：仅改文字为「已复制」，移除对勾，保持按钮宽度不变
                copyBtn.textContent = '已复制';
                copyBtn.classList.add('success');

                setTimeout(() => {
                    copyBtn.textContent = '复制令牌';
                    copyBtn.classList.remove('success');
                }, 2000);
            } catch (err) {
                // 复制失败：仅改文字为「手动复制」，保持按钮宽度不变
                copyBtn.textContent = '手动复制';
                copyBtn.classList.add('error');

                // 自动选中全部文本
                const range = document.createRange();
                range.selectNodeContents(tokenEl);
                const selection = window.getSelection();
                selection.removeAllRanges();
                selection.addRange(range);

                setTimeout(() => {
                    copyBtn.textContent = '复制令牌';
                    copyBtn.classList.remove('error');
                }, 2000);
            }
        });

        // 双击全选
        tokenEl.addEventListener('dblclick', function() {
            const range = document.createRange();
            range.selectNodeContents(tokenEl);
            const selection = window.getSelection();
            selection.removeAllRanges();
            selection.addRange(range);
        });
    })();
