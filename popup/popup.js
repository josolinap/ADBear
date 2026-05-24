let dnsFilteringEnabled = false;

const statusDot = document.getElementById("status-dot");
const statusText = document.getElementById("status-text");
const openSidebar = document.getElementById("open-sidebar");
const refreshBtn = document.getElementById("refresh-btn");
const dnsFilterToggle = document.getElementById("dns-filter-toggle");
const dnsFilterStatus = document.getElementById("dns-filter-status");
const dnsTotal = document.getElementById("dns-total");
const dnsBlocked = document.getElementById("dns-blocked");
const dnsDomains = document.getElementById("dns-domains");
const dnsBlockedPct = document.getElementById("dns-blocked-pct");
const dnsBarPct = document.getElementById("dns-bar-pct");
const dnsBarFill = document.getElementById("dns-bar-fill");

async function fetchDNSStats() {
    try {
        const stats = await browser.runtime.sendMessage({ action: "get_stats" });
        if (stats) {
            dnsTotal.textContent = stats.totalQueries.toLocaleString();
            dnsBlocked.textContent = stats.blockedCount.toLocaleString();
            dnsDomains.textContent = stats.uniqueDomains.toLocaleString();
            dnsBlockedPct.textContent = stats.blockedPct + "%";
            dnsBarPct.textContent = stats.blockedPct + "%";
            dnsBarFill.style.width = stats.blockedPct + "%";
            dnsFilteringEnabled = stats.filteringEnabled;
            dnsFilterToggle.checked = dnsFilteringEnabled;
            dnsFilterStatus.textContent = dnsFilteringEnabled ? "On" : "Off";
            dnsFilterStatus.className = dnsFilteringEnabled ? "toggle-status active" : "toggle-status";
        }
    } catch (e) {
        dnsTotal.textContent = "-";
        dnsBlocked.textContent = "-";
        dnsDomains.textContent = "-";
        dnsBlockedPct.textContent = "-";
    }
}

async function ping() {
    try {
        const data = await browser.runtime.sendMessage({ action: "get_connections" });
        if (data && data.type === "connections") {
            statusDot.className = "dot-online";
            statusText.textContent = "Connected";
        } else {
            statusDot.className = "dot-offline";
            statusText.textContent = "Disconnected";
        }
    } catch (e) {
        statusDot.className = "dot-offline";
        statusText.textContent = "Disconnected";
    }
}

dnsFilterToggle.addEventListener("change", async () => {
    const enabled = dnsFilterToggle.checked;
    try {
        await browser.runtime.sendMessage({ action: "set_filtering", enabled });
        dnsFilterStatus.textContent = enabled ? "On" : "Off";
        dnsFilterStatus.className = enabled ? "toggle-status active" : "toggle-status";
    } catch (e) {
        dnsFilterToggle.checked = !enabled;
    }
});

refreshBtn.addEventListener("click", () => {
    refreshBtn.style.transform = "rotate(360deg)";
    setTimeout(() => { refreshBtn.style.transform = ""; }, 500);
    ping();
    fetchDNSStats();
});

openSidebar.addEventListener("click", () => {
    browser.sidebarAction.open();
    window.close();
});

ping();
fetchDNSStats();

setInterval(fetchDNSStats, 5000);
