const form = document.getElementById('scanForm');
const btn = document.getElementById('btnScan');
const resultsDiv = document.getElementById('results');
const resultsUrl = document.getElementById('resultsUrl');
const resultsList = document.getElementById('resultsList');
const resultsTotal = document.getElementById('resultsTotal');
const resultsActions = document.getElementById('resultsActions');
const btnExport = document.getElementById('btnExport');
const formError = document.getElementById('formError');
let lastReport = null;

document.querySelectorAll('.preset-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('input[name="checks"]').forEach(c => c.checked = false);
        if (btn.dataset.preset === 'fast') {
            ['misconfig', 'sql', 'xss'].forEach(v => {
                const el = document.getElementById(v);
                if (el) el.checked = true;
            });
        } else {
            document.querySelectorAll('input[name="checks"]').forEach(c => c.checked = true);
        }
    });
});

window.toggleRemediation = (i) => {
    const el = document.getElementById('rem-' + i);
    if (el) el.classList.toggle('show');
};

btnExport.addEventListener('click', () => {
    if (!lastReport) return;
    const blob = new Blob([JSON.stringify(lastReport, null, 2)], {type: 'application/json'});
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'scan-report-' + new Date().toISOString().slice(0,10) + '.json';
    a.click();
});

form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const url = document.getElementById('url').value.trim();
    const checks = [...form.querySelectorAll('input[name="checks"]:checked')].map(c => c.value);

    // Limpa erro antigo
    if (formError) {
        formError.style.display = 'none';
        formError.textContent = '';
    }

    if (!url) {
        if (formError) {
            formError.textContent = 'Informe uma URL para escanear.';
            formError.style.display = 'block';
        }
        return;
    }

    if (checks.length === 0) {
        if (formError) {
            formError.textContent = 'Selecione pelo menos um tipo de verificação.';
            formError.style.display = 'block';
        }
        return;
    }

    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> Escaneando...';
    resultsDiv.style.display = 'none';

    try {
        const res = await fetch('/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url, checks })
        });
        const data = await res.json();

        resultsDiv.style.display = 'block';
        resultsUrl.textContent = data.url || url;

        if (!res.ok) {
            let msg = data.error || 'Erro ao escanear.';
            resultsList.innerHTML = `<div class="error-msg">${escapeHtml(msg)}</div>`;
            resultsTotal.textContent = '';
        } else {
            resultsTotal.textContent = `${data.total} vulnerabilidade(s)`;
            resultsActions.style.display = data.findings.length ? 'flex' : 'none';
            lastReport = data;
            if (data.findings.length === 0) {
                resultsList.innerHTML = `
                    <div class="empty-state">
                        <p>✓ Nenhuma vulnerabilidade aparente encontrada.</p>
                        <p>Este não é um certificado de segurança — faça pentest profissional.</p>
                    </div>`;
            } else {
                resultsList.innerHTML = data.findings.map((f, i) => {
                    const cls = f.type.toLowerCase().replace(/\s+/g, '-');
                    const sev = (f.severity || 'medium').toLowerCase();
                    const rem = f.remediation || '';
                    return `
                    <div class="result-item ${cls}">
                        <div class="result-header">
                            <div class="result-title">
                                <span class="result-badge ${cls}">${f.type}</span>
                                <span class="result-badge ${sev}">${sev}</span>
                            </div>
                        </div>
                        <div class="result-body">
                            <div class="result-desc">${escapeHtml(f.desc)}</div>
                            ${rem ? `<button class="remediation-btn" onclick="toggleRemediation(${i})">Ver solução</button>` : ''}
                        </div>
                        ${rem ? `<div class="remediation-tip" id="rem-${i}">${escapeHtml(rem)}</div>` : ''}
                    </div>
                `}).join('');
                resultsActions.style.display = 'flex';
                lastReport = data;
            }
        }
    } catch (err) {
        resultsDiv.style.display = 'block';
        resultsList.innerHTML = `<div class="error-msg">Erro: ${err.message}</div>`;
        resultsTotal.textContent = '';
    }

    btn.disabled = false;
    btn.textContent = 'Escanear';
});

function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}