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
}
