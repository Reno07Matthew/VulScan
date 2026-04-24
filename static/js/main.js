document.addEventListener('DOMContentLoaded', () => {
    const scanBtn = document.getElementById('scan-btn');
    const targetInput = document.getElementById('target');
    const portsInput = document.getElementById('ports');
    const threadsInput = document.getElementById('threads');
    const statusArea = document.getElementById('status-area');
    const progressBar = document.getElementById('progress-bar');
    const statusText = document.getElementById('status-text');
    const resultsArea = document.getElementById('results-area');
    const displayTarget = document.getElementById('display-target');
    const targetIpBadge = document.getElementById('target-ip');

    let scanData = null;

    // Tab logic
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
            btn.classList.add('active');
            document.getElementById('panel-' + btn.dataset.tab).classList.add('active');
        });
    });

    // Progress animation
    function animateProgress(phases) {
        let i = 0;
        const interval = setInterval(() => {
            if (i < phases.length) {
                progressBar.style.width = phases[i].pct + '%';
                statusText.textContent = phases[i].text;
                i++;
            } else { clearInterval(interval); }
        }, 800);
        return interval;
    }

    scanBtn.addEventListener('click', async () => {
        const target = targetInput.value.trim();
        if (!target) { alert('Please enter a target host.'); return; }

        scanBtn.disabled = true;
        scanBtn.innerHTML = '<span class="btn-icon">⏳</span> Scanning...';
        statusArea.classList.remove('hidden');
        resultsArea.classList.add('hidden');
        progressBar.style.width = '0%';

        const phases = [
            {pct: 10, text: 'Resolving hostname...'},
            {pct: 25, text: 'Scanning ports...'},
            {pct: 50, text: 'Grabbing banners...'},
            {pct: 65, text: 'Looking up CVEs...'},
            {pct: 80, text: 'Computing risk scores...'},
        ];
        const progInterval = animateProgress(phases);

        try {
            const resp = await fetch('/api/scan', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    target, ports: portsInput.value.trim() || null,
                    threads: threadsInput.value, timeout: 1.0
                })
            });
            const data = await resp.json();
            clearInterval(progInterval);

            if (data.error) {
                progressBar.style.width = '100%';
                statusText.textContent = 'Error: ' + data.error;
                return;
            }

            scanData = data;
            progressBar.style.width = '95%';
            statusText.textContent = 'Rendering results...';
            displayResults(data);
            progressBar.style.width = '100%';

            // Fire geo request in background
            fetchGeo(data.target_ip);

        } catch (err) {
            clearInterval(progInterval);
            console.error(err);
            statusText.textContent = 'Scan failed. Check console.';
        } finally {
            scanBtn.disabled = false;
            scanBtn.innerHTML = '<span class="btn-icon">⚡</span> Start Scan';
            setTimeout(() => statusArea.classList.add('hidden'), 1200);
        }
    });

    function displayResults(data) {
        displayTarget.textContent = data.target;
        targetIpBadge.textContent = data.target_ip;
        renderPorts(data);
        renderRisk(data);
        renderCVEs(data);
        resultsArea.classList.remove('hidden');
        resultsArea.scrollIntoView({behavior:'smooth'});
    }

    // ── Ports Panel ──
    function renderPorts(data) {
        const c = document.getElementById('ports-container');
        c.innerHTML = '';
        const ports = Object.entries(data.open_ports);
        if (!ports.length) {
            c.innerHTML = '<div class="empty-state"><div class="icon">✅</div><p>No open ports found.</p></div>';
            return;
        }
        ports.forEach(([port, d]) => {
            const div = document.createElement('div');
            div.className = 'result-card';
            let sw = '';
            if (d.identified_software) {
                sw = `<p style="margin-bottom:8px;font-size:0.88rem;font-weight:600;">Detected: <span style="color:var(--success)">${d.identified_software} v${d.identified_version}</span></p>`;
            }
            div.innerHTML = `
                <div class="result-main">
                    <div class="port-info">
                        <span class="port-number">Port ${port}</span>
                        <span class="service-badge">${d.mapped_service}</span>
                    </div>
                </div>
                ${d.weakness_warning ? `<div class="weakness-alert">⚠️ ${d.weakness_warning}</div>` : ''}
                ${d.banner ? `<div class="banner-text">${escapeHtml(d.banner)}</div>` : ''}
                ${sw}
            `;
            c.appendChild(div);
        });
    }

    // ── Risk Panel ──
    function renderRisk(data) {
        const risk = data.risk;
        if (!risk) return;

        // Gauge animation
        const score = risk.overall_score;
        const arc = document.getElementById('gauge-arc');
        const scoreEl = document.getElementById('gauge-score');
        const labelEl = document.getElementById('gauge-label');
        const maxDash = 251.2;
        const targetDash = (score / 10) * maxDash;
        setTimeout(() => {
            arc.style.transition = 'stroke-dasharray 1.2s ease';
            arc.setAttribute('stroke-dasharray', targetDash + ' ' + maxDash);
            scoreEl.textContent = score.toFixed(1);
            labelEl.textContent = risk.overall_severity;
        }, 200);

        // Summary
        const summary = document.getElementById('risk-summary-text');
        const portCount = Object.keys(risk.port_risks).length;
        const critCount = Object.values(risk.port_risks).filter(r => r.severity === 'CRITICAL' || r.severity === 'HIGH').length;
        summary.innerHTML = `
            <h3><span class="severity-badge severity-${risk.overall_severity}">${risk.overall_severity}</span> Overall Risk</h3>
            <p>${portCount} open port(s) assessed. ${critCount} high/critical risk port(s) found.</p>
        `;

        // Per-port risk cards
        const c = document.getElementById('risk-details-container');
        c.innerHTML = '';
        Object.entries(risk.port_risks).forEach(([port, r]) => {
            const div = document.createElement('div');
            div.className = 'result-card risk-card';
            const barClass = r.severity === 'CRITICAL' ? 'risk-bar-critical' : r.severity === 'HIGH' ? 'risk-bar-high' : r.severity === 'MEDIUM' ? 'risk-bar-medium' : 'risk-bar-low';
            const portData = data.open_ports[port];
            let remediationHtml = '';
            if (r.remediation) {
                const steps = r.remediation.steps.map(s => `<li>${s}</li>`).join('');
                const cmds = r.remediation.commands.join('\n');
                remediationHtml = `
                    <div class="remediation-section">
                        <div class="remediation-title">🔧 Remediation — ${r.remediation.service}</div>
                        <p style="font-size:0.82rem;color:var(--text-secondary);margin-bottom:8px;">${r.remediation.risk_summary}</p>
                        <ul class="remediation-steps">${steps}</ul>
                        <div class="command-block"><button class="copy-btn" onclick="copyCmd(this)">Copy</button>${escapeHtml(cmds)}</div>
                    </div>
                `;
            }
            div.innerHTML = `
                <div class="result-main">
                    <div class="port-info">
                        <span class="port-number">Port ${port}</span>
                        <span class="service-badge">${portData ? portData.mapped_service : ''}</span>
                        <span class="severity-badge severity-${r.severity}">${r.severity}</span>
                    </div>
                    <span style="font-family:'JetBrains Mono';font-weight:700;color:var(--accent-color)">${r.risk_score}/10</span>
                </div>
                <div class="risk-bar-container"><div class="risk-bar ${barClass}" style="width:${r.risk_score * 10}%"></div></div>
                ${remediationHtml}
            `;
            c.appendChild(div);
        });
    }

    // ── CVEs Panel ──
    function renderCVEs(data) {
        const c = document.getElementById('cves-container');
        c.innerHTML = '';
        let allCves = [];
        Object.entries(data.open_ports).forEach(([port, d]) => {
            if (d.vulnerabilities && d.vulnerabilities.length) {
                d.vulnerabilities.forEach(v => allCves.push({...v, port, service: d.mapped_service, software: d.identified_software, version: d.identified_version}));
            }
        });
        if (!allCves.length) {
            c.innerHTML = '<div class="empty-state"><div class="icon">🎉</div><p>No CVEs discovered for the detected services.</p></div>';
            return;
        }
        allCves.sort((a,b) => (typeof b.score==='number'?b.score:0) - (typeof a.score==='number'?a.score:0));
        allCves.forEach(v => {
            const div = document.createElement('div');
            div.className = 'cve-card';
            const scoreClass = getScoreClass(v.score);
            div.innerHTML = `
                <div class="cve-header">
                    <span class="cve-id">${v.id}</span>
                    <div style="display:flex;gap:6px;align-items:center;">
                        <span class="service-badge">${v.service}:${v.port}</span>
                        <span class="cve-score ${scoreClass}">${v.score}</span>
                    </div>
                </div>
                ${v.software ? `<p style="font-size:0.78rem;color:var(--warning);margin-bottom:4px;">${v.software} v${v.version}</p>` : ''}
                <p class="cve-desc">${v.description}</p>
            `;
            c.appendChild(div);
        });
    }

    // ── Geo Panel ──
    async function fetchGeo(targetIp) {
        const loading = document.getElementById('geo-loading');
        const container = document.getElementById('geo-container');
        loading.classList.remove('hidden');
        container.classList.add('hidden');
        try {
            const resp = await fetch('/api/geo', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({target_ip: targetIp})
            });
            const geo = await resp.json();
            renderGeo(geo);
        } catch (e) {
            container.innerHTML = '<div class="empty-state"><div class="icon">❌</div><p>Geo-IP lookup failed.</p></div>';
            container.classList.remove('hidden');
        } finally {
            loading.classList.add('hidden');
        }
    }

    function renderGeo(geo) {
        const container = document.getElementById('geo-container');
        const tg = geo.target_geo || {};
        let infoHtml = `
            <div class="geo-info-grid">
                <div class="geo-info-card"><div class="geo-label">Country</div><div class="geo-value">${tg.country || 'N/A'} ${tg.country_code ? '('+tg.country_code+')' : ''}</div></div>
                <div class="geo-info-card"><div class="geo-label">City / Region</div><div class="geo-value">${tg.city || 'N/A'}, ${tg.region || ''}</div></div>
                <div class="geo-info-card"><div class="geo-label">ISP</div><div class="geo-value">${tg.isp || 'N/A'}</div></div>
                <div class="geo-info-card"><div class="geo-label">Coordinates</div><div class="geo-value">${tg.latitude || '?'}, ${tg.longitude || '?'}</div></div>
            </div>
        `;
        let topoHtml = '';
        if (geo.hops && geo.hops.length) {
            let lines = geo.hops.map(h => {
                const geoStr = h.geo && h.geo.country ? `${h.geo.city||''}, ${h.geo.country}` : '';
                const rtt = h.rtt_ms !== null ? h.rtt_ms + ' ms' : '* * *';
                return `<div class="hop-line">
                    <span class="hop-num">${h.hop}</span>
                    <span class="hop-connector">├──</span>
                    <span class="hop-ip">${h.ip}</span>
                    <span class="hop-rtt">${rtt}</span>
                    <span class="hop-geo">${geoStr}</span>
                </div>`;
            }).join('');
            topoHtml = `<div class="topology-section"><h3>🗺️ Network Topology (${geo.total_hops} hops)</h3><div class="topology-tree">${lines}</div></div>`;
        } else {
            topoHtml = '<div class="empty-state" style="margin-top:20px"><div class="icon">🔒</div><p>Traceroute unavailable (may require elevated permissions).</p></div>';
        }
        container.innerHTML = infoHtml + topoHtml;
        container.classList.remove('hidden');
    }

    // ── Helpers ──
    function escapeHtml(str) {
        const d = document.createElement('div');
        d.textContent = str;
        return d.innerHTML;
    }
    function getScoreClass(score) {
        if (typeof score !== 'number') return 'cve-score-medium';
        if (score >= 9) return 'cve-score-critical';
        if (score >= 7) return 'cve-score-high';
        if (score >= 4) return 'cve-score-medium';
        return 'cve-score-low';
    }
});

// Global copy function
function copyCmd(btn) {
    const block = btn.parentElement;
    const text = block.textContent.replace('Copy','').trim();
    navigator.clipboard.writeText(text).then(() => {
        btn.textContent = 'Copied!';
        setTimeout(() => btn.textContent = 'Copy', 1500);
    });
}
