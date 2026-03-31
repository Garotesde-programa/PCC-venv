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
const execSummary = document.getElementById('execSummary');
const execRiskLabel = document.getElementById('execRiskLabel');
const execRiskScore = document.getElementById('execRiskScore');
const execConfidence = document.getElementById('execConfidence');
const riskBarWrap = document.getElementById('riskBarWrap');
const riskBarFill = document.getElementById('riskBarFill');
const trendBox = document.getElementById('trendBox');
const btnExecutiveMode = document.getElementById('btnExecutiveMode');
const directorMode = document.getElementById('directorMode');
const directorSummary = document.getElementById('directorSummary');
const btnHistory = document.getElementById('btnHistory');
const historyPanel = document.getElementById('historyPanel');
const scanProgressWrap = document.getElementById('scanProgressWrap');
const scanProgressFill = document.getElementById('scanProgressFill');
const scanProgressText = document.getElementById('scanProgressText');
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
        const abuse = getAbuseNarrative(f);
        const evidence = f.evidence || {};
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
            <details class="attack-flow">
                <summary>Como um atacante exploraria isso (visão empresa)</summary>
                <div class="attack-content">
                    <div><strong>Exploração provável:</strong> ${escapeHtml(abuse.exploit)}</div>
                    <div><strong>Impacto para a empresa:</strong> ${escapeHtml(abuse.impact)}</div>
                    <div><strong>Probabilidade:</strong> ${escapeHtml(abuse.likelihood)}</div>
                    <div><strong>Pré-requisitos:</strong> ${escapeHtml(abuse.prereqs)}</div>
                    ${evidence.response_signal ? `<div><strong>Evidência:</strong> ${escapeHtml(evidence.response_signal)}</div>` : ''}
                </div>
            </details>
        </div>`;
    }).join('');
}

function renderExecutiveSummary(insights) {
    if (!execSummary || !riskBarWrap || !riskBarFill) return;
    if (!insights) {
        execSummary.style.display = 'none';
        riskBarWrap.style.display = 'none';
        return;
    }

    const riskLevel = (insights.risk_level || 'desconhecido').toUpperCase();
    const score = Number.isFinite(insights.risk_score) ? insights.risk_score : 0;
    execRiskLabel.textContent = riskLevel;
    execRiskScore.textContent = `${score}/100`;
    execConfidence.textContent = (insights.confidence || 'média').toUpperCase();
    execSummary.style.display = 'grid';
    riskBarWrap.style.display = 'block';
    riskBarFill.style.width = `${Math.max(0, Math.min(100, score))}%`;
}

function getAbuseNarrative(finding) {
    const t = (finding?.type || '').toUpperCase();
    const map = [
        {
            k: 'SQL',
            exploit: 'Injetar payload em parâmetros para extrair base de clientes, credenciais e dados financeiros.',
            impact: 'Vazamento de dados, multa LGPD, incidente de imagem e possível paralisação operacional.',
            likelihood: 'Alta em endpoints sem validação e consultas dinâmicas.',
            prereqs: 'Entrada controlada pelo atacante e erro de validação no backend.'
        },
        {
            k: 'XSS',
            exploit: 'Inserir script malicioso para roubar sessão de usuários/admin e executar ações em nome deles.',
            impact: 'Tomada de conta, fraude interna, suporte sobrecarregado e perda de confiança do cliente.',
            likelihood: 'Alta em campos refletidos/armazenados sem escaping.',
            prereqs: 'Usuário-alvo acessa conteúdo contaminado.'
        },
        {
            k: 'LFI',
            exploit: 'Forçar leitura de arquivos sensíveis (config, chaves, logs) para escalar ataque ao servidor.',
            impact: 'Exposição de segredos, invasão lateral de ambiente e risco de ransomware.',
            likelihood: 'Média/Alta quando paths são derivados de input do usuário.',
            prereqs: 'Parâmetro de arquivo sem whitelist e sanitização.'
        },
        {
            k: 'PATH',
            exploit: 'Manipular caminhos para acessar arquivos internos fora da área permitida da aplicação.',
            impact: 'Comprometimento de integridade, vazamento de informações estratégicas e downtime.',
            likelihood: 'Média com validação fraca de caminhos.',
            prereqs: 'Entrada de path acessível externamente.'
        },
        {
            k: 'OPEN REDIRECT',
            exploit: 'Usar domínio legítimo da empresa para redirecionar vítima para phishing sem levantar suspeita.',
            impact: 'Roubo de credenciais de clientes, dano reputacional e aumento de chargeback/fraudes.',
            likelihood: 'Média com parâmetros de redirect sem whitelist.',
            prereqs: 'Link malicioso enviado para vítimas.'
        },
        {
            k: 'HTTP METHODS',
            exploit: 'Abusar métodos perigosos para alterar/deletar recursos sem autorização adequada.',
            impact: 'Indisponibilidade de serviço, perda de dados e quebra de SLA.',
            likelihood: 'Média dependendo de autenticação/ACL.',
            prereqs: 'Endpoint aceita métodos sensíveis em produção.'
        },
        {
            k: 'COOKIE',
            exploit: 'Capturar cookie de sessão sem HttpOnly/Secure e reutilizar sessão de usuário privilegiado.',
            impact: 'Acesso indevido, risco regulatório e investigação de incidente complexa.',
            likelihood: 'Média/Alta se combinado com XSS ou tráfego não criptografado.',
            prereqs: 'Cookie inseguro e canal de captura.'
        },
        {
            k: 'CORS',
            exploit: 'Fazer site malicioso chamar API da empresa com sessão autenticada da vítima.',
            impact: 'Exfiltração de dados de conta, abertura de chamados legais e prejuízo de marca.',
            likelihood: 'Média em APIs com CORS amplo.',
            prereqs: 'Vítima autenticada acessa página controlada pelo atacante.'
        },
        {
            k: 'HTTPS',
            exploit: 'Interceptar tráfego HTTP em rede pública para ler ou modificar requisições.',
            impact: 'Roubo de credenciais, manipulação de pagamentos e quebra de confiança.',
            likelihood: 'Média em cenários de Wi-Fi público/proxy comprometido.',
            prereqs: 'Conexão sem TLS obrigatório.'
        },
        {
            k: 'MISCONFIG',
            exploit: 'Enumerar arquivos/painéis expostos para preparar invasão em cadeia mais profunda.',
            impact: 'Aumento da superfície de ataque, incidente em produção e custos de remediação.',
            likelihood: 'Alta para alvos expostos publicamente.',
            prereqs: 'Serviço acessível e sem hardening básico.'
        },
        {
            k: 'INFO',
            exploit: 'Usar versões/tecnologias expostas para aplicar exploits conhecidos com maior precisão.',
            impact: 'Aceleração do ataque, menor tempo de detecção e maior chance de comprometimento.',
            likelihood: 'Média como etapa de reconhecimento.',
            prereqs: 'Headers/banner com tecnologia e versão.'
        },
    ];
    const hit = map.find(item => t.includes(item.k));
    if (hit) return { exploit: hit.exploit, impact: hit.impact };
    return {
        exploit: 'Combinar esse achado com outras falhas para escalar privilégio e manter persistência.',
        impact: 'Risco de incidente de segurança com impacto financeiro, jurídico e reputacional.',
        likelihood: 'Média',
        prereqs: 'Encadeamento com outras fragilidades do ambiente.'
    };
}

function renderTrend(comparison) {
    if (!trendBox) return;
    if (!comparison || !comparison.has_previous) {
        trendBox.style.display = 'none';
        return;
    }
    const delta = Number(comparison.delta_total || 0);
    const sign = delta > 0 ? '+' : '';
    const byType = comparison.by_type_delta || {};
    const highlights = Object.entries(byType)
        .filter(([, v]) => Number(v) !== 0)
        .slice(0, 4)
        .map(([k, v]) => `${k}: ${v > 0 ? '+' : ''}${v}`)
        .join(' | ');
    trendBox.innerHTML = `<strong>Tendência:</strong> ${escapeHtml(comparison.trend_label || '')} (${sign}${delta})`
        + (highlights ? `<br><span>${escapeHtml(highlights)}</span>` : '');
    trendBox.style.display = 'block';
}

function buildDirectorSummary(report) {
    const ai = report?.ai_insights || {};
    const comp = report?.comparison || {};
    const risk = (ai.risk_level || 'desconhecido').toUpperCase();
    const score = ai.risk_score ?? 'n/a';
    const trend = comp.has_previous ? (comp.trend_label || 'estável') : 'sem baseline anterior';
    const top = Array.isArray(ai.top_actions) ? ai.top_actions.slice(0, 3) : [];
    const bullets = top.map(t => `- ${t}`).join('<br>');
    return `Risco atual <strong>${escapeHtml(risk)}</strong> (score ${escapeHtml(String(score))}/100), com tendência <strong>${escapeHtml(trend)}</strong>.<br>`
        + `Prioridades de negócio imediatas:<br>${bullets || '- Manter monitoramento contínuo e plano preventivo.'}`;
}

async function loadHistory() {
    if (!historyPanel) return;
    if (historyPanel.style.display === 'block') {
        historyPanel.style.display = 'none';
        return;
    }
    historyPanel.style.display = 'block';
    historyPanel.innerHTML = '<div class="history-row">Carregando histórico...</div>';
    try {
        const res = await fetch('/api/history', { headers: { 'Accept': 'application/json' } });
        const data = await res.json();
        const history = Array.isArray(data.history) ? data.history : [];
        if (!history.length) {
            historyPanel.innerHTML = '<div class="history-row">Sem histórico ainda.</div>';
            return;
        }
        historyPanel.innerHTML = history.map(h => {
            const dt = new Date((h.ts || 0) * 1000).toLocaleString('pt-BR');
            const delta = h.delta_from_previous;
            const deltaTxt = delta == null ? 'n/a' : (delta > 0 ? `+${delta}` : `${delta}`);
            return `<div class="history-row"><strong>${escapeHtml(h.url || '-')}</strong><br>Total: ${h.total || 0} | Delta: ${deltaTxt} | ${dt}</div>`;
        }).join('');
    } catch (e) {
        historyPanel.innerHTML = `<div class="history-row">Erro ao carregar histórico: ${escapeHtml(e.message)}</div>`;
    }
}

function renderAIInsights(insights) {
    if (!aiInsightsBox || !aiHeadline || !aiSummary || !aiActions) return;
    if (!insights) {
        aiInsightsBox.style.display = 'none';
        if (aiPlanOutput) aiPlanOutput.style.display = 'none';
        if (btnCopyPlan) btnCopyPlan.style.display = 'none';
        if (btnGeneratePlan) btnGeneratePlan.textContent = 'Gerar plano de correção (7 dias)';
        if (trendBox) trendBox.style.display = 'none';
        return;
    }

    aiHeadline.textContent = insights.headline || 'Análise automática indisponível.';
    aiSummary.textContent = insights.summary || '';
    const actions = Array.isArray(insights.top_actions) ? insights.top_actions : [];
    const blockers = Array.isArray(insights.immediate_blockers) ? insights.immediate_blockers : [];
    const next24h = Array.isArray(insights.next_24h) ? insights.next_24h : [];
    const confidence = insights.confidence ? `Confiança da análise: ${insights.confidence}` : '';
    aiActions.innerHTML = [
        ...actions.map(a => `<li>${escapeHtml(a)}</li>`),
        ...blockers.map(b => `<li><strong>Crítico agora:</strong> ${escapeHtml(b)}</li>`),
        ...next24h.map(n => `<li><strong>Próx. 24h:</strong> ${escapeHtml(n)}</li>`),
        ...(confidence ? [`<li>${escapeHtml(confidence)}</li>`] : []),
    ].join('');
    aiInsightsBox.style.display = 'block';
    renderExecutiveSummary(insights);
    if (aiPlanOutput) aiPlanOutput.style.display = 'none';
    if (btnCopyPlan) btnCopyPlan.style.display = 'none';
    if (btnGeneratePlan) btnGeneratePlan.textContent = 'Gerar plano de correção (7 dias)';
}

function setScanProgress(percent, label) {
    if (!scanProgressWrap || !scanProgressFill || !scanProgressText) return;
    scanProgressWrap.style.display = 'block';
    const safe = Math.max(0, Math.min(100, Number(percent) || 0));
    scanProgressFill.style.width = `${safe}%`;
    scanProgressText.textContent = label || 'Processando...';
}

function clearScanProgress() {
    if (!scanProgressWrap || !scanProgressFill || !scanProgressText) return;
    scanProgressWrap.style.display = 'none';
    scanProgressFill.style.width = '0%';
    scanProgressText.textContent = 'Iniciando...';
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
    if (aiPlanOutput.style.display === 'block') {
        aiPlanOutput.style.display = 'none';
        if (btnCopyPlan) btnCopyPlan.style.display = 'none';
        if (btnGeneratePlan) btnGeneratePlan.textContent = 'Gerar plano de correção (7 dias)';
        toast('Plano ocultado');
        return;
    }
    const plan = generateSevenDayPlan(lastReport);
    aiPlanOutput.textContent = plan;
    aiPlanOutput.style.display = 'block';
    if (btnCopyPlan) btnCopyPlan.style.display = 'inline-block';
    if (btnGeneratePlan) btnGeneratePlan.textContent = 'Ocultar plano de correção';
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
    if (historyPanel) historyPanel.style.display = 'none';
    if (directorMode) directorMode.style.display = 'none';
    setScanProgress(3, 'Enviando job de varredura...');

    try {
        const res = await fetch('/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'X-Requested-With': 'XMLHttpRequest',
            },
            body: JSON.stringify(payload)
        });
        const contentType = (res.headers.get('content-type') || '').toLowerCase();
        let data;
        if (contentType.includes('application/json')) {
            data = await res.json();
        } else {
            const raw = await res.text();
            throw new Error(`Resposta inesperada do servidor (MIME: ${contentType || 'desconhecido'}). ${raw.slice(0, 180)}`);
        }

        if (!res.ok) {
            throw new Error(data.error || 'Erro ao iniciar o scan');
        }
        if (!data.job_id) {
            throw new Error('Servidor não retornou job_id para acompanhamento');
        }

        let pollDone = false;
        while (!pollDone) {
            await new Promise(r => setTimeout(r, 900));
            const pRes = await fetch(`/api/scan/${encodeURIComponent(data.job_id)}`, {
                headers: { 'Accept': 'application/json' },
            });
            const pData = await pRes.json();
            if (!pRes.ok) {
                throw new Error(pData.error || 'Falha ao consultar status do scan');
            }
            const p = pData.progress || {};
            setScanProgress(p.percent || 0, p.stage || 'Processando...');

            if (pData.status === 'error') {
                throw new Error(pData.error || 'Scan falhou');
            }
            if (pData.status !== 'done') {
                continue;
            }
            const result = pData.result || {};
            resultsDiv.style.display = 'block';
            resultsUrl.textContent = result.url || url;
            lastReport = result;
            resultsTotal.textContent = `${result.total || 0} vulnerabilidade(s)`;
            const hasFindings = result.findings && result.findings.length > 0;
            resultsActions.style.display = hasFindings ? 'flex' : 'none';
            resultsToolbar.style.display = hasFindings ? 'flex' : 'none';
            renderFindings(getFilteredSortedFindings());
            renderAIInsights(result.ai_insights);
            renderTrend(result.comparison);
            if (result.e2e_advanced_started && document.getElementById('e2eStatus')) startE2EStatusPolling();
            setScanProgress(100, 'Scan concluído');
            pollDone = true;
        }
    } catch (err) {
        resultsDiv.style.display = 'block';
        resultsList.innerHTML = `<div class="error-msg">Erro: ${escapeHtml(err.message)}</div>`;
        resultsTotal.textContent = '';
        resultsActions.style.display = 'none';
        resultsToolbar.style.display = 'none';
        renderAIInsights(null);
    }

    setTimeout(clearScanProgress, 900);
    btn.disabled = false;
    btn.textContent = 'Escanear';
});

btnExecutiveMode?.addEventListener('click', () => {
    if (!directorMode || !directorSummary) return;
    if (directorMode.style.display === 'block') {
        directorMode.style.display = 'none';
        return;
    }
    if (!lastReport) {
        toast('Faça um scan antes de abrir o modo diretoria');
        return;
    }
    directorSummary.innerHTML = buildDirectorSummary(lastReport);
    directorMode.style.display = 'block';
});

btnHistory?.addEventListener('click', () => {
    loadHistory();
});

document.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && (e.key === 'Enter' || e.code === 'NumpadEnter')) {
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
