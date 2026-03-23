const form = document.getElementById('scanForm');
const btn = document.getElementById('btnScan');
const resultsDiv = document.getElementById('results');
const resultsUrl = document.getElementById('resultsUrl');
const resultsList = document.getElementById('resultsList');
const resultsTotal = document.getElementById('resultsTotal');
const resultsActions = document.getElementById('resultsActions');
const resultsToolbar = document.getElementById('resultsToolbar');
const aiInsightsBox = document.getElementById('aiInsights');
const aiHeadline = document.getElementById('aiHeadline');
const aiSummary = document.getElementById('aiSummary');
const aiActions = document.getElementById('aiActions');
const btnGeneratePlan = document.getElementById('btnGeneratePlan');
const btnCopyPlan = document.getElementById('btnCopyPlan');
const aiPlanOutput = document.getElementById('aiPlanOutput');
const filterSeverity = document.getElementById('filterSeverity');
const sortBy = document.getElementById('sortBy');
let lastReport = null;

const STORAGE_URL = 'scanner_last_url';
const STORAGE_CHECKS = 'scanner_last_checks';
const STORAGE_THEME = 'scanner_theme';
const STORAGE_AMBIENT = 'scanner_ambient';

// Ambient (Mr. Robot style) via Web Audio API
let ambientCtx = null;
let ambientMasterGain = null;
let ambientOscillators = [];
let ambientPlaying = false;

function initAmbient() {
    if (ambientCtx) return ambientCtx;
    const Ctx = window.AudioContext || window.webkitAudioContext;
    if (!Ctx) return null;
    ambientCtx = new Ctx();
    const mixGain = ambientCtx.createGain();
    mixGain.gain.value = 0.12;
    ambientMasterGain = ambientCtx.createGain();
    ambientMasterGain.gain.value = 1;
    mixGain.connect(ambientMasterGain);
    ambientMasterGain.connect(ambientCtx.destination);

    const freqs = [55, 82.5, 110, 165, 220];
    const gains = [0.5, 0.2, 0.15, 0.1, 0.05];
    const types = ['sine', 'sine', 'triangle', 'sine', 'sine'];

    for (let i = 0; i < freqs.length; i++) {
        const osc = ambientCtx.createOscillator();
        const g = ambientCtx.createGain();
        osc.type = types[i];
        osc.frequency.value = freqs[i];
        osc.detune.value = (i - 2) * 3;
        g.gain.value = gains[i];
        osc.connect(g);
        g.connect(mixGain);
        osc.start(0);
        ambientOscillators.push(osc);
    }
    return ambientCtx;
}

function createAmbientAudioFallback() {
    const sr = 44100, len = sr * 4;
    const buf = new ArrayBuffer(44 + len * 2);
    const view = new DataView(buf);
    const writeStr = (o, s) => { for (let i = 0; i < s.length; i++) view.setUint8(o + i, s.charCodeAt(i)); };
    writeStr(0, 'RIFF');
    view.setUint32(4, 36 + len * 2, true);
    writeStr(8, 'WAVE');
    writeStr(12, 'fmt ');
    view.setUint32(16, 16, true);
    view.setUint16(20, 1, true);
    view.setUint16(22, 1, true);
    view.setUint32(24, sr, true);
    view.setUint32(28, sr * 2, true);
    view.setUint16(32, 2, true);
    view.setUint16(34, 16, true);
    writeStr(36, 'data');
    view.setUint32(40, len * 2, true);
    for (let i = 0; i < len; i++) {
        const t = i / sr;
        const sample = Math.sin(2 * Math.PI * 55 * t) * 0.3 +
            Math.sin(2 * Math.PI * 110 * t) * 0.15 +
            Math.sin(2 * Math.PI * 165 * t) * 0.08;
        const v = Math.max(-1, Math.min(1, sample)) * 8192;
        view.setInt16(44 + i * 2, v, true);
    }
    return new Blob([buf], { type: 'audio/wav' });
}

let ambientAudioEl = null;

async function toggleAmbient() {
    const btn = document.getElementById('ambientToggle');
    if (!ambientCtx) initAmbient();

    if (ambientCtx) {
        try {
            if (ambientCtx.state === 'suspended') await ambientCtx.resume();
        } catch (e) {
            ambientCtx = null;
        }
    }

    if (!ambientCtx && !ambientAudioEl) {
        ambientAudioEl = new Audio(URL.createObjectURL(createAmbientAudioFallback()));
        ambientAudioEl.loop = true;
        ambientAudioEl.volume = 0.15;
    }

    if (ambientPlaying) {
        if (ambientCtx && ambientMasterGain) {
            ambientMasterGain.gain.setTargetAtTime(0, ambientCtx.currentTime, 0.3);
        } else if (ambientAudioEl) {
            ambientAudioEl.pause();
        }
        ambientPlaying = false;
        btn?.classList.remove('playing');
        toast('Música ambiente desligada');
    } else {
        if (ambientCtx && ambientMasterGain) {
            ambientMasterGain.gain.setTargetAtTime(1, ambientCtx.currentTime, 0.2);
        } else if (ambientAudioEl) {
            ambientAudioEl.currentTime = 0;
            ambientAudioEl.play().catch(() => toast('Clique novamente para ativar o áudio'));
        }
        ambientPlaying = true;
        btn?.classList.add('playing');
        toast('Música ambiente ligada');
    }
    try { localStorage.setItem(STORAGE_AMBIENT, ambientPlaying ? '1' : '0'); } catch (e) {}
}

document.getElementById('ambientToggle')?.addEventListener('click', () => {
    toggleAmbient();
});

function toast(msg) {
    const el = document.getElementById('toast');
    if (!el) return;
    el.textContent = msg;
    el.classList.add('show');
    setTimeout(() => el.classList.remove('show'), 2500);
}

function saveState() {
    try {
        const url = document.getElementById('url')?.value?.trim();
        if (url) localStorage.setItem(STORAGE_URL, url);
        const checks = [...form.querySelectorAll('input[name="checks"]:checked')].map(c => c.value);
        localStorage.setItem(STORAGE_CHECKS, JSON.stringify(checks));
    } catch (e) {}
}

function loadState() {
    try {
        const url = localStorage.getItem(STORAGE_URL);
        if (url && document.getElementById('url')) document.getElementById('url').value = url;
        const raw = localStorage.getItem(STORAGE_CHECKS);
        if (raw) {
            const checks = JSON.parse(raw);
            form.querySelectorAll('input[name="checks"]').forEach(c => { c.checked = checks.includes(c.value); });
        }
        const theme = localStorage.getItem(STORAGE_THEME);
        if (theme === 'light') document.body.classList.add('theme-light');
        const ambient = localStorage.getItem(STORAGE_AMBIENT);
        if (ambient === '1') document.getElementById('ambientToggle')?.classList.add('ambient-wanted');
    } catch (e) {}
}

// Auto-inicia ambiente no primeiro clique (se usuário tinha ligado antes)
let ambientAutoStartAttempted = false;
function tryAutoStartAmbient() {
    if (ambientAutoStartAttempted || !document.getElementById('ambientToggle')?.classList.contains('ambient-wanted')) return;
    ambientAutoStartAttempted = true;
    document.getElementById('ambientToggle')?.classList.remove('ambient-wanted');
    if (!ambientPlaying) toggleAmbient();
}
document.body.addEventListener('click', tryAutoStartAmbient);
document.body.addEventListener('keydown', tryAutoStartAmbient);

document.getElementById('themeToggle')?.addEventListener('click', () => {
    document.body.classList.toggle('theme-light');
    try { localStorage.setItem(STORAGE_THEME, document.body.classList.contains('theme-light') ? 'light' : 'dark'); } catch (e) {}
    toast(document.body.classList.contains('theme-light') ? 'Tema claro' : 'Tema escuro');
});

loadState();

document.querySelectorAll('.preset-btn').forEach(b => {
    b.addEventListener('click', () => {
        document.querySelectorAll('input[name="checks"]').forEach(c => c.checked = false);
        const preset = b.dataset.preset;
        if (preset === 'fast') {
            ['misconfig', 'sql', 'xss'].forEach(v => { const el = document.getElementById(v); if (el) el.checked = true; });
        } else if (preset === 'full') {
            form.querySelectorAll('input[name="checks"]').forEach(c => c.checked = true);
        } else if (preset === 'headers') {
            ['misconfig', 'https'].forEach(v => { const el = document.getElementById(v); if (el) el.checked = true; });
        } else if (preset === 'injection') {
            ['sql', 'xss'].forEach(v => { const el = document.getElementById(v); if (el) el.checked = true; });
        } else {
            form.querySelectorAll('input[name="checks"]').forEach(c => c.checked = true);
        }
    });
});

window.toggleRemediation = (i) => {
    const el = document.getElementById('rem-' + i);
    if (el) el.classList.toggle('show');
};

function getFilteredSortedFindings() {
    if (!lastReport || !lastReport.findings) return [];
    let list = lastReport.findings.slice();
    const sev = filterSeverity?.value;
    if (sev) list = list.filter(f => (f.severity || '').toLowerCase() === sev);
    const sort = sortBy?.value || 'severity';
    const order = { critical: 0, high: 1, medium: 2, low: 3 };
    if (sort === 'severity') list.sort((a, b) => (order[a.severity] ?? 4) - (order[b.severity] ?? 4));
    else if (sort === 'type') list.sort((a, b) => (a.type || '').localeCompare(b.type || ''));
    return list;
}

function renderFindings(findings) {
    if (!findings || findings.length === 0) {
        resultsList.innerHTML = `
            <div class="empty-state">
                <p>✓ Nenhuma vulnerabilidade aparente encontrada.</p>
                <p>Este não é um certificado de segurança — faça pentest profissional.</p>
            </div>`;
        return;
    }
    resultsList.innerHTML = findings.map((f, i) => {
        const cls = (f.type || '').toLowerCase().replace(/\s+/g, '-');
        const sev = (f.severity || 'medium').toLowerCase();
        const rem = f.remediation || '';
        return `
        <div class="result-item ${cls}">
            <div class="result-header">
                <div class="result-title">
                    <span class="result-badge ${cls}">${escapeHtml(f.type)}</span>
                    <span class="result-badge ${sev}">${sev}</span>
                </div>
            </div>
            <div class="result-body">
                <div class="result-desc">${escapeHtml(f.desc)}</div>
                ${rem ? `<button class="remediation-btn" onclick="toggleRemediation(${i})">Ver solução</button>` : ''}
            </div>
            ${rem ? `<div class="remediation-tip" id="rem-${i}">${escapeHtml(rem)}</div>` : ''}
        </div>`;
    }).join('');
}

function renderAIInsights(insights) {
    if (!aiInsightsBox || !aiHeadline || !aiSummary || !aiActions) return;
    if (!insights) {
        aiInsightsBox.style.display = 'none';
        if (aiPlanOutput) aiPlanOutput.style.display = 'none';
        if (btnCopyPlan) btnCopyPlan.style.display = 'none';
        return;
    }

    aiHeadline.textContent = insights.headline || 'Análise automática indisponível.';
    aiSummary.textContent = insights.summary || '';
    const actions = Array.isArray(insights.top_actions) ? insights.top_actions : [];
    aiActions.innerHTML = actions.map(a => `<li>${escapeHtml(a)}</li>`).join('');
    aiInsightsBox.style.display = 'block';
    if (aiPlanOutput) aiPlanOutput.style.display = 'none';
    if (btnCopyPlan) btnCopyPlan.style.display = 'none';
}

function createActionByType(findings) {
    const actions = [];
    const hasType = (snippet) => findings.some(f => (f.type || '').toUpperCase().includes(snippet));

    if (hasType('SQL')) actions.push('Dev: migrar consultas sensíveis para prepared statements e validar inputs numéricos.');
    if (hasType('XSS')) actions.push('Dev: aplicar escape de saída por contexto e sanitização estrita em campos ricos.');
    if (hasType('LFI') || hasType('PATH')) actions.push('Dev: bloquear path traversal com whitelist de caminhos permitidos.');
    if (hasType('MISCONFIG') || hasType('HTTPS')) actions.push('DevOps: padronizar headers de segurança e redirect HTTP->HTTPS.');
    if (hasType('COOKIE')) actions.push('DevOps: forçar Set-Cookie com HttpOnly, Secure e SameSite=Lax/Strict.');
    if (hasType('HTTP METHODS')) actions.push('DevOps: restringir métodos HTTP perigosos (PUT/DELETE/TRACE/PATCH).');
    if (hasType('CORS')) actions.push('DevOps: limitar Access-Control-Allow-Origin para domínios confiáveis.');

    return actions;
}

function generateSevenDayPlan(report) {
    const findings = Array.isArray(report?.findings) ? report.findings : [];
    const insights = report?.ai_insights || {};
    const score = insights.risk_score ?? 'n/a';
    const level = (insights.risk_level || 'desconhecido').toString().toUpperCase();
    const now = new Date().toLocaleString('pt-BR');

    const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
    findings.forEach(f => {
        const sev = (f.severity || 'medium').toLowerCase();
        bySeverity[sev] = (bySeverity[sev] || 0) + 1;
    });

    const criticalOrHigh = findings.filter(f => {
        const sev = (f.severity || '').toLowerCase();
        return sev === 'critical' || sev === 'high';
    });

    const topImmediate = criticalOrHigh.slice(0, 5).map((f, i) =>
        `${i + 1}. ${f.type || 'VULN'} - ${f.desc || 'Sem descrição'}`.slice(0, 220)
    );

    const typedActions = createActionByType(findings);
    const genericActions = [
        'Dev: criar testes de regressão para os vetores corrigidos.',
        'DevOps: adicionar verificação de headers e TLS no pipeline.',
        'Segurança: agendar re-scan ao final da semana e comparar tendência.',
    ];
    const actions = [...typedActions, ...genericActions].slice(0, 7);

    const lines = [
        `PLANO DE CORRECAO - 7 DIAS`,
        `Gerado em: ${now}`,
        `Alvo: ${report?.url || 'N/D'}`,
        `Risco atual: ${level} (score ${score}/100)`,
        `Achados: total=${findings.length} | C=${bySeverity.critical || 0} H=${bySeverity.high || 0} M=${bySeverity.medium || 0} L=${bySeverity.low || 0}`,
        ``,
        `Dia 1 - Triage e Contencao`,
        `- Validar escopo e congelar alteracoes de risco no app.`,
        `- Priorizar imediatamente critical/high.`,
        ...(topImmediate.length ? topImmediate.map(t => `- ${t}`) : ['- Sem achados critical/high nesta rodada.']),
        ``,
        `Dia 2 - Correcao backend (injecao e validacao)`,
        `- Corrigir SQLi/XSS/LFI com validacao e sanitizacao por contexto.`,
        `- Revisar endpoints mais expostos.`,
        ``,
        `Dia 3 - Hardening de plataforma`,
        `- Ajustar headers, CORS, cookies e metodos HTTP.`,
        `- Garantir redirect e postura HTTPS consistente.`,
        ``,
        `Dia 4 - Testes e QA de seguranca`,
        `- Rodar testes funcionais e de regressao com foco em seguranca.`,
        `- Validar que nao houve quebra de fluxo critico.`,
        ``,
        `Dia 5 - Observabilidade e protecao operacional`,
        `- Criar alertas para padroes suspeitos.`,
        `- Instrumentar logs para trilha de auditoria.`,
        ``,
        `Dia 6 - Re-scan dirigido`,
        `- Rodar novo scan com checks completos e comparar com baseline.`,
        `- Corrigir pendencias medias remanescentes.`,
        ``,
        `Dia 7 - Fechamento e prevencao`,
        `- Publicar checklist de seguranca no pipeline.`,
        `- Definir rotina de scan semanal e ownership por time.`,
        ``,
        `Acoes recomendadas desta rodada:`,
        ...actions.map(a => `- ${a}`),
    ];

    return lines.join('\n');
}

btnGeneratePlan?.addEventListener('click', () => {
    if (!lastReport || !aiPlanOutput) {
        toast('Faça um scan antes de gerar o plano');
        return;
    }
    const plan = generateSevenDayPlan(lastReport);
    aiPlanOutput.textContent = plan;
    aiPlanOutput.style.display = 'block';
    if (btnCopyPlan) btnCopyPlan.style.display = 'inline-block';
    toast('Plano de correção (7 dias) gerado');
});

btnCopyPlan?.addEventListener('click', async () => {
    if (!aiPlanOutput || !aiPlanOutput.textContent) return;
    try {
        await navigator.clipboard.writeText(aiPlanOutput.textContent);
        toast('Plano copiado');
    } catch (e) {
        toast('Falha ao copiar plano');
    }
});

filterSeverity?.addEventListener('change', () => { if (lastReport) { renderFindings(getFilteredSortedFindings()); } });
sortBy?.addEventListener('change', () => { if (lastReport) { renderFindings(getFilteredSortedFindings()); } });

function escapeHtml(str) {
    if (str == null) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

document.getElementById('btnExportJson')?.addEventListener('click', () => {
    if (!lastReport) return;
    const blob = new Blob([JSON.stringify(lastReport, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'scan-report-' + new Date().toISOString().slice(0, 10) + '.json';
    a.click();
    toast('JSON exportado');
});

document.getElementById('btnExportCsv')?.addEventListener('click', () => {
    if (!lastReport?.findings?.length) return;
    try {
        window.open('/api/export?format=csv', '_blank');
        toast('CSV exportado');
    } catch (e) { toast('Erro ao exportar CSV'); }
});

document.getElementById('btnExportHtml')?.addEventListener('click', () => {
    if (!lastReport?.findings?.length) return;
    try {
        window.open('/api/export?format=html', '_blank');
        toast('HTML exportado');
    } catch (e) { toast('Erro ao exportar HTML'); }
});

document.getElementById('btnCopy')?.addEventListener('click', async () => {
    if (!lastReport) return;
    const text = JSON.stringify(lastReport, null, 2);
    try {
        await navigator.clipboard.writeText(text);
        toast('Relatório copiado');
    } catch (e) { toast('Falha ao copiar'); }
});

form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const url = document.getElementById('url').value.trim();
    const checks = [...form.querySelectorAll('input[name="checks"]:checked')].map(c => c.value);
    const e2eHuman = document.getElementById('e2e_human')?.checked || false;
    const e2eAdvanced = document.getElementById('e2e_advanced')?.checked || false;
    const e2eProfile = document.getElementById('e2e_profile')?.value?.trim() || '';
    const cloudflareTimeout = document.getElementById('cloudflare_timeout')?.value || '60000';

    const payload = { url, checks, e2e_human: e2eHuman };
    if (e2eAdvanced) {
        payload.e2e_advanced = true;
        if (e2eProfile) payload.e2e_profile = e2eProfile;
        payload.cloudflare_timeout = cloudflareTimeout;
    }

    saveState();
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> Escaneando...';
    resultsDiv.style.display = 'none';
    const e2eStatusDiv = document.getElementById('e2eStatus');
    if (e2eStatusDiv) e2eStatusDiv.style.display = 'none';
    renderAIInsights(null);

    try {
        const res = await fetch('/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const data = await res.json();

        resultsDiv.style.display = 'block';
        resultsUrl.textContent = data.url || url;

        if (!res.ok) {
            resultsList.innerHTML = `<div class="error-msg">${escapeHtml(data.error || 'Erro ao escanear')}</div>`;
            resultsTotal.textContent = '';
            resultsActions.style.display = 'none';
            resultsToolbar.style.display = 'none';
            renderAIInsights(null);
        } else {
            lastReport = data;
            resultsTotal.textContent = `${data.total} vulnerabilidade(s)`;
            const hasFindings = data.findings && data.findings.length > 0;
            resultsActions.style.display = hasFindings ? 'flex' : 'none';
            resultsToolbar.style.display = hasFindings ? 'flex' : 'none';
            renderFindings(getFilteredSortedFindings());
            renderAIInsights(data.ai_insights);
            if (data.e2e_advanced_started && document.getElementById('e2eStatus')) startE2EStatusPolling();
        }
    } catch (err) {
        resultsDiv.style.display = 'block';
        resultsList.innerHTML = `<div class="error-msg">Erro: ${escapeHtml(err.message)}</div>`;
        resultsTotal.textContent = '';
        resultsActions.style.display = 'none';
        resultsToolbar.style.display = 'none';
        renderAIInsights(null);
    }

    btn.disabled = false;
    btn.textContent = 'Escanear';
});

document.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
        e.preventDefault();
        form.requestSubmit();
    }
});

function startE2EStatusPolling() {
    const e2eStatusDiv = document.getElementById('e2eStatus');
    const e2eStatusText = document.getElementById('e2eStatusText');
    const e2eTokenPre = document.getElementById('e2eToken');
    if (!e2eStatusDiv || !e2eStatusText) return;
    e2eStatusDiv.style.display = 'block';
    e2eTokenPre.style.display = 'none';

    const poll = async () => {
        try {
            const res = await fetch('/e2e-status');
            const data = await res.json();
            if (data.status === 'running') {
                e2eStatusText.textContent = 'em execução...';
                setTimeout(poll, 2000);
                return;
            }
            if (data.status === 'done') {
                if (data.error) e2eStatusText.textContent = 'Erro: ' + data.error;
                else if (data.token) {
                    e2eStatusText.textContent = 'Token Turnstile capturado:';
                    e2eTokenPre.textContent = data.token;
                    e2eTokenPre.style.display = 'block';
                } else e2eStatusText.textContent = 'concluído (sem token exibido).';
                return;
            }
            e2eStatusText.textContent = data.status || '—';
            setTimeout(poll, 2000);
        } catch (e) {
            e2eStatusText.textContent = 'Falha ao consultar status: ' + e.message;
        }
    };
    poll();
}
