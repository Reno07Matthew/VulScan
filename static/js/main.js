document.addEventListener('DOMContentLoaded', () => {
    const scanBtn = document.getElementById('scan-btn');
    const targetInput = document.getElementById('target');
    const portsInput = document.getElementById('ports');
    const threadsInput = document.getElementById('threads');
    
    const statusArea = document.getElementById('status-area');
    const resultsArea = document.getElementById('results-area');
    const resultsContainer = document.getElementById('results-container');
    const displayTarget = document.getElementById('display-target');
    const targetIpBadge = document.getElementById('target-ip');

    scanBtn.addEventListener('click', async () => {
        const target = targetInput.value.trim();
        if (!target) {
            alert('Please enter a target host.');
            return;
        }

        // UI Reset
        scanBtn.disabled = true;
        scanBtn.textContent = 'Scanning...';
        statusArea.classList.remove('hidden');
        resultsArea.classList.add('hidden');
        resultsContainer.innerHTML = '';

        try {
            const response = await fetch('/api/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    target: target,
                    ports: portsInput.value.trim() || null,
                    threads: threadsInput.value,
                    timeout: 1.0
                })
            });

            const data = await response.json();

            if (data.error) {
                alert(`Error: ${data.error}`);
            } else {
                displayResults(data);
            }
        } catch (err) {
            console.error(err);
            alert('An error occurred during the scan.');
        } finally {
            scanBtn.disabled = false;
            scanBtn.textContent = 'Start Scan';
            statusArea.classList.add('hidden');
        }
    });

    function displayResults(data) {
        displayTarget.textContent = data.target;
        targetIpBadge.textContent = data.target_ip;
        
        const ports = Object.entries(data.open_ports);
        
        if (ports.length === 0) {
            resultsContainer.innerHTML = '<div class="card"><p>No open ports found.</p></div>';
        } else {
            ports.forEach(([port, details]) => {
                const card = createResultCard(port, details);
                resultsContainer.appendChild(card);
            });
        }
        
        resultsArea.classList.remove('hidden');
        resultsArea.scrollIntoView({ behavior: 'smooth' });
    }

    function createResultCard(port, details) {
        const div = document.createElement('div');
        div.className = 'result-card';
        
        let vulnerabilitiesHtml = '';
        if (details.vulnerabilities && details.vulnerabilities.length > 0) {
            vulnerabilitiesHtml = `
                <div class="vulnerabilities">
                    ${details.vulnerabilities.map(v => `
                        <div class="cve-card">
                            <div class="cve-header">
                                <span class="cve-id">${v.id}</span>
                                <span class="cve-score">${v.score}</span>
                            </div>
                            <p class="cve-desc">${v.description}</p>
                        </div>
                    `).join('')}
                </div>
            `;
        }

        let softwareHtml = '';
        if (details.identified_software) {
            softwareHtml = `<p style="margin-bottom: 10px; font-size: 0.9rem; font-weight: 600;">
                Detected: <span style="color: var(--success)">${details.identified_software} v${details.identified_version}</span>
            </p>`;
        }

        div.innerHTML = `
            <div class="result-main">
                <div class="port-info">
                    <span class="port-number">Port ${port}</span>
                    <span class="service-badge">${details.mapped_service}</span>
                </div>
            </div>
            ${details.weakness_warning ? `<div class="weakness-alert">⚠️ ${details.weakness_warning}</div>` : ''}
            ${details.banner ? `<div class="banner-text">${details.banner}</div>` : ''}
            ${softwareHtml}
            ${vulnerabilitiesHtml}
        `;
        
        return div;
    }
});
