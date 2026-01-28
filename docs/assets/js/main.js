async function fetchJSON(path) {
    try {
        const response = await fetch(path);
        if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
        return await response.json();
    } catch (e) {
        console.error("Could not load " + path, e);
        return null;
    }
}

// Simple utils
function displayStats(indicators, coverage) {
    const totalEl = document.getElementById('total-indicators');
    if (totalEl) totalEl.innerText = indicators.length;

    const coveredEl = document.getElementById('covered-techniques');
    if (coveredEl && coverage) coveredEl.innerText = Object.keys(coverage).length;

    // Render Charts if elements exist
    if (document.getElementById('chart-types') && typeof Chart !== 'undefined') {
        renderCharts(indicators);
    }
}

function renderCharts(indicators) {
    // Process Data
    const types = {};
    const sources = {};

    indicators.forEach(i => {
        types[i.indicator_type] = (types[i.indicator_type] || 0) + 1;
        sources[i.source] = (sources[i.source] || 0) + 1;
    });

    const commonOptions = {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: { labels: { color: '#8b949e', font: { family: 'Inter' } } }
        },
        scales: {
            y: { ticks: { color: '#8b949e' }, grid: { color: 'rgba(255,255,255,0.05)' } },
            x: { ticks: { color: '#8b949e' }, grid: { color: 'rgba(255,255,255,0.05)' } }
        }
    };

    // Chart 1: Types (Doughnut)
    new Chart(document.getElementById('chart-types'), {
        type: 'doughnut',
        data: {
            labels: Object.keys(types),
            datasets: [{
                data: Object.values(types),
                backgroundColor: ['#2f81f7', '#3fb950', '#d29922', '#f85149', '#a371f7'],
                borderColor: '#0d1117',
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { position: 'right', labels: { color: '#c9d1d9', font: { family: 'Inter' } } }
            }
        }
    });

    // Chart 2: Sources (Bar)
    // Sort sources by count
    const sortedSources = Object.entries(sources).sort((a, b) => b[1] - a[1]).slice(0, 10);

    new Chart(document.getElementById('chart-sources'), {
        type: 'bar',
        data: {
            labels: sortedSources.map(s => s[0]),
            datasets: [{
                label: 'Count',
                data: sortedSources.map(s => s[1]),
                backgroundColor: 'rgba(56, 139, 253, 0.5)',
                borderColor: '#2f81f7',
                borderWidth: 1
            }]
        },
        options: commonOptions
    });
}

function downloadCSV(data, filename) {
    if (!data.length) return;
    const headers = Object.keys(data[0]).join(',');
    const rows = data.map(row => Object.values(row).map(v =>
        typeof v === 'string' && v.includes(',') ? `"${v}"` : JSON.stringify(v)
    ).join(','));

    const csvContent = "data:text/csv;charset=utf-8," + [headers, ...rows].join('\n');
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", filename);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}
