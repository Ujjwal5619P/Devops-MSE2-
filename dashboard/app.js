const scheme = window.location.protocol === 'https:' ? 'https' : 'http';
const wsScheme = window.location.protocol === 'https:' ? 'wss' : 'ws';
const API_URL = `${scheme}://${window.location.hostname}:8000`;
const WS_URL = `${wsScheme}://${window.location.hostname}:8000/ws/alerts`;

let severityChart;
let timelineChart;

async function initDashboard() {
    await fetchStats();
    await fetchHistory();
    setupWebSocket();
}

async function fetchHistory() {
    try {
        const response = await fetch(`${API_URL}/api/alerts`);
        const alerts = await response.json();
        const feed = document.getElementById('live-feed');
        feed.innerHTML = '';
        alerts.slice(-15).forEach(alert => appendAlert(alert, feed, false));
    } catch (error) {
        console.error('Error fetching history:', error);
    }
}

async function fetchStats() {
    try {
        const response = await fetch(`${API_URL}/api/stats`);
        const data = await response.json();
        updateAllStats(data);
    } catch (error) {
        console.error('Error fetching stats:', error);
    }
}

function updateAllStats(data) {
    document.getElementById('total-alerts').textContent = data.total_alerts || 0;

    const critical = data.severity_counts?.CRITICAL || 0;
    const blocked = data.blocked_ips?.length || 0;
    document.getElementById('critical-alerts').innerHTML =
    `${critical}<span class="metric-sub"> Crit</span><br>${blocked}<span class="metric-sub"> Block</span>`;

    updateSeverityChart(data.severity_counts || {});
    updateTimelineChart(data.timeline || []);
    updateBlockedTable(data.blocked_ips || []);
}

function updateSeverityChart(counts) {
    const ctx = document.getElementById('severityChart').getContext('2d');
    const values = [counts.LOW || 0, counts.MEDIUM || 0, counts.HIGH || 0, counts.CRITICAL || 0];

    if (severityChart) {
        severityChart.data.datasets[0].data = values;
        severityChart.update();
        return;
    }

    severityChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Low', 'Medium', 'High', 'Critical'],
            datasets: [{
                data: values,
                backgroundColor: ['#3b82f6', '#f59e0b', '#ef4444', '#b91c1c'],
                borderWidth: 0,
                hoverOffset: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { position: 'bottom', labels: { color: '#e2e8f0' } }
            }
        }
    });
}

function updateTimelineChart(timeline) {
    const ctx = document.getElementById('timelineChart').getContext('2d');
    const labels = timeline.map(item => item.time);
    const values = timeline.map(item => item.count);

    if (timelineChart) {
        timelineChart.data.labels = labels;
        timelineChart.data.datasets[0].data = values;
        timelineChart.update();
        return;
    }

    timelineChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels,
            datasets: [{
                label: 'Events/Min',
                data: values,
                borderColor: '#ef4444',
                backgroundColor: 'rgba(239, 68, 68, 0.1)',
                borderWidth: 2,
                fill: true,
                tension: 0.3
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                y: { beginAtZero: true, grid: { color: '#1e293b' }, ticks: { color: '#94a3b8', stepSize: 1 } },
                x: { grid: { color: '#1e293b' }, ticks: { color: '#94a3b8' } }
            }
        }
    });
}

function updateBlockedTable(ips) {
    const tbody = document.getElementById('blocked-table').getElementsByTagName('tbody')[0];
    tbody.innerHTML = '';

    if (ips.length === 0) {
        tbody.innerHTML = '<tr><td style="color: #94a3b8; border:none;">No IPs blocked currently.</td></tr>';
        return;
    }

    ips.forEach(ip => {
        const row = document.createElement('tr');
        row.innerHTML = `<td style="color: #ef4444; font-weight: bold; border-bottom: 1px solid #1e293b;">🚫 ${ip}</td>`;
        tbody.appendChild(row);
    });
}

function setupWebSocket() {
    const ws = new WebSocket(WS_URL);
    const feed = document.getElementById('live-feed');

    ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        if (data.type === 'update') {
            if (data.alert) appendAlert(data.alert, feed, true);
            if (data.stats) updateAllStats(data.stats);
        }
    };

    ws.onclose = () => {
        console.log('WebSocket closed. Reconnecting...');
        setTimeout(setupWebSocket, 3000);
    };
}

function appendAlert(alert, feed, prepend = true) {
    const severity = (alert.severity || 'LOW').toLowerCase();
    const entry = document.createElement('div');
    entry.className = `log-entry ${severity}`;

    const time = alert.timestamp ? new Date(alert.timestamp).toLocaleTimeString() : 'Unknown';
    const attackType = alert.attack_type || 'Unknown';

    let typeClass = '';
    if (attackType === 'Port Scan') typeClass = 'scan';
    else if (attackType === 'Brute Force / DoS') typeClass = 'brute';
    else if (attackType === 'Malicious IP') typeClass = 'alert';
    else if (attackType === 'SSH Brute Force') typeClass = 'ssh';
    else if (attackType === 'HTTP Flood') typeClass = 'http';
    else if (attackType === 'Suspicious Port') typeClass = 'sus';

    entry.innerHTML = `
        <span class="log-timestamp">[${time}]</span>
        <span class="badge ${typeClass}">${attackType}</span>
        <strong>[${alert.severity || 'LOW'}]</strong> ${alert.message || 'Threat Detected'}
        <span class="geo">(${alert.geo || 'Unknown'})</span>
        <br/>
        <span style="color:#94a3b8; font-size: 0.8rem; padding-left: 5px;">
            SRC: ${alert.src_ip || 'N/A'}:${alert.src_port ?? 'N/A'} -> DST: ${alert.dst_ip || 'N/A'}:${alert.dst_port ?? 'N/A'} |
            Reason: ${alert.details?.reason || 'N/A'}
        </span>
    `;

    if (prepend) {
        feed.prepend(entry);
    } else {
        feed.appendChild(entry);
    }

    while (feed.children.length > 50) {
        feed.removeChild(feed.lastChild);
    }
}

document.addEventListener('DOMContentLoaded', initDashboard);
