
let charts = {};
let lastData = null; // 缓存上次数据，避免不必要的更新
let isLoading = false;
let isOnline = true;
let isFirstLoad = true; // 标记是否首次加载
let consecutiveErrors = 0; // 连续错误计数

document.addEventListener('DOMContentLoaded', () => {
    setupNavigation();
    initCharts();
    loadStats();
    setInterval(loadStats, 3000);

    // 网络状态监听
    window.addEventListener('online', () => {
        isOnline = true;
        consecutiveErrors = 0;
        updateOnlineStatus(true);
    });
    window.addEventListener('offline', () => {
        isOnline = false;
        updateOnlineStatus(false);
    });
});

function setupNavigation() {
    document.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', () => {
            // UI Toggle
            document.querySelectorAll('.nav-item').forEach(i => i.classList.remove('active'));
            item.classList.add('active');

            const target = item.dataset.target;
            document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
            document.getElementById(target).classList.add('active');

            if (target === 'settings') {
                loadConfig();
            }
        });
    });

    document.getElementById('save-config-btn')?.addEventListener('click', saveConfig);
}

// ==================== DASHBOARD ====================

async function loadStats() {
    // 防止重复请求
    if (isLoading) return;
    isLoading = true;

    // 显示加载状态（可选：添加小图标旋转）
    const refreshBtn = document.querySelector('[onclick="refreshData()"]');
    if (refreshBtn) {
        refreshBtn.style.opacity = '0.5';
    }

    try {
        const res = await fetch('/api/stats');
        if (!res.ok) {
            throw new Error(`HTTP ${res.status}`);
        }

        const data = await res.json();

        // 检查数据是否真的变化了
        const dataChanged = !lastData || JSON.stringify(data) !== JSON.stringify(lastData);

        if (dataChanged) {
            // 1. Cards
            updateText('total-queries', (data.total_queries || 0).toLocaleString());
            updateText('avg-latency', (data.avg_latency_ms || 0).toFixed(2) + ' ms');
            updateText('cache-hit-rate', (data.cache_hit_rate || 0).toFixed(1) + ' %');
            updateText('blocked-count', (data.blocked_count || 0).toLocaleString());

            // 2. Charts
            updateDoughnut('chart-qtype', data.qtype_stats);
            updateDoughnut('chart-rcode', data.rcode_stats);
            updateDoughnut('chart-strategy', data.strategy_breakdown);

            // 3. Tables
            updateTable('top-domains-list', data.top_domains);
            updateTable('top-clients-list', data.top_clients);

            // 缓存数据
            lastData = data;
        }

        // 成功获取数据，重置错误计数
        consecutiveErrors = 0;
        isFirstLoad = false;

        // 只有在非首次加载时才更新在线状态
        if (!isFirstLoad) {
            updateOnlineStatus(true);
        }

    } catch (e) {
        console.error("Stats Error:", e);
        consecutiveErrors++;

        // 只有在连续失败 3 次以上且非首次加载时，才显示离线状态
        // 这样可以避免首次加载慢或临时网络波动导致的误报
        if (!isFirstLoad && consecutiveErrors >= 3) {
            updateOnlineStatus(false);
        }
    } finally {
        isLoading = false;

        // 恢复按钮状态
        const refreshBtn = document.querySelector('[onclick="refreshData()"]');
        if (refreshBtn) {
            refreshBtn.style.opacity = '1';
        }
    }
}

// 更新网络状态指示器
function updateOnlineStatus(online) {
    const statusEl = document.getElementById('connection-status');
    if (statusEl) {
        statusEl.className = online ? 'status-indicator online' : 'status-indicator offline';
        statusEl.title = online ? '连接正常' : '连接中断';
    }
}

function updateText(id, text) {
    const el = document.getElementById(id);
    if (el) el.innerText = text;
}

function updateTable(id, list) {
    const container = document.getElementById(id);
    if (!container || !list) return;

    // Safety check
    if (!Array.isArray(list)) return;

    const html = list.slice(0, 8).map(([key, val]) => `
        <div class="data-row">
            <span style="overflow:hidden; text-overflow:ellipsis; white-space:nowrap; max-width: 70%;" title="${key}">${key}</span>
            <span style="font-family:monospace; color:var(--accent-blue);">${val}</span>
        </div>
    `).join('');
    container.innerHTML = html;
}

// Chart.js Wrapper
function initCharts() {
    const commonOptions = {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: { position: 'right', labels: { color: '#94a3b8', boxWidth: 10 } }
        },
        cutout: '70%',
        borderWidth: 0
    };

    ['chart-qtype', 'chart-rcode', 'chart-strategy'].forEach(id => {
        const ctx = document.getElementById(id)?.getContext('2d');
        if (!ctx) return;

        charts[id] = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: [],
                datasets: [{
                    data: [],
                    backgroundColor: [
                        '#3b82f6', '#8b5cf6', '#10b981', '#f59e0b', '#ef4444', '#64748b'
                    ]
                }]
            },
            options: commonOptions
        });
    });
}

function updateDoughnut(id, statsObj) {
    const chart = charts[id];
    if (!chart || !statsObj) return;

    // Convert Obj to Sorted Array
    const sorted = Object.entries(statsObj)
        .sort((a, b) => b[1] - a[1]) // Descending
        .slice(0, 6); // Top 6

    chart.data.labels = sorted.map(i => i[0]);
    chart.data.datasets[0].data = sorted.map(i => i[1]);
    chart.update('none'); // No animation for perf
}

// ==================== SETTINGS ====================

async function loadConfig() {
    const textarea = document.getElementById('config-editor');
    textarea.value = "Loading configuration...";
    try {
        const res = await fetch('/api/config');
        const json = await res.json();
        textarea.value = JSON.stringify(json, null, 4);
    } catch (e) {
        textarea.value = "// Error loading config:\n" + e;
    }
}

async function saveConfig() {
    const textarea = document.getElementById('config-editor');
    const btn = document.getElementById('save-config-btn');
    const originalText = btn.innerText;

    try {
        const config = JSON.parse(textarea.value);
        btn.innerText = "Applying...";
        btn.disabled = true;

        const res = await fetch('/api/config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(config)
        });

        if (res.ok) {
            alert("✅ Configuration Saved & Hot Reload Triggered!");
        } else {
            throw new Error(await res.text());
        }
    } catch (e) {
        alert("❌ Save Failed: " + e.message);
    } finally {
        btn.innerText = originalText;
        btn.disabled = false;
    }
}

// ==================== 手动刷新 ====================

function refreshData() {
    // 立即加载一次数据
    loadStats();

    // 给用户反馈
    const btn = document.querySelector('[onclick="refreshData()"]');
    if (btn) {
        const originalTransform = btn.style.transform;
        btn.style.transform = 'rotate(360deg)';
        btn.style.transition = 'transform 0.5s ease';

        setTimeout(() => {
            btn.style.transform = originalTransform;
        }, 500);
    }
}
