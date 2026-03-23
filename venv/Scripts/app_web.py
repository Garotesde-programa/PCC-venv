#!/usr/bin/env python3
"""
Interface Web do Scanner de Vulnerabilidades
"""

import sys
import os
from urllib.parse import urlparse
from time import time
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, render_template, request, jsonify, redirect
from scanner_site import scan, run_e2e_human
from werkzeug.middleware.proxy_fix import ProxyFix

try:
    from e2e_playwright import run_e2e as run_e2e_advanced
    E2E_ADVANCED_AVAILABLE = True
except ImportError:
    run_e2e_advanced = None
    E2E_ADVANCED_AVAILABLE = False

app = Flask(__name__)

# Estado do último E2E avançado (Turnstile, profile, Bézier) para polling
_last_e2e_result = {"status": "idle", "token": None, "error": None}
# Último relatório completo (para histórico e export)
_last_scan_report = None
_MAX_HISTORY = 50
_scan_history = []

ALLOWED_DOMAINS = os.getenv('SCANNER_ALLOWED_DOMAINS', '').strip()
INTERNAL_HEADER_NAME = os.getenv('SCANNER_INTERNAL_HEADER_NAME', 'X-Internal-Scan')
INTERNAL_HEADER_VALUE = os.getenv('SCANNER_INTERNAL_HEADER_VALUE', '').strip()
RATE_LIMIT_WINDOW = int(os.getenv('SCANNER_RATE_LIMIT_WINDOW', '60'))  # segundos
RATE_LIMIT_MAX = int(os.getenv('SCANNER_RATE_LIMIT_MAX', '10'))        # req/Janela/IP
FORCE_HTTPS_REDIRECT = os.getenv('SCANNER_FORCE_HTTPS_REDIRECT', '').lower() in ('1', 'true', 'yes')
HTTPS_REDIRECT_PORT = int(os.getenv('SCANNER_HTTPS_PORT', os.getenv('SCANNER_PORT', '5000')))
SSL_MODE = os.getenv('SCANNER_SSL_MODE', '').strip().lower()  # '', 'adhoc', 'cert'
SSL_CERT_PATH = os.getenv('SCANNER_SSL_CERT', '').strip()
SSL_KEY_PATH = os.getenv('SCANNER_SSL_KEY', '').strip()
TRUST_PROXY = os.getenv('SCANNER_TRUST_PROXY', '').lower() in ('1', 'true', 'yes')
PROXY_FIX_X_FOR = int(os.getenv('SCANNER_PROXY_FIX_X_FOR', '1'))
PROXY_FIX_X_PROTO = int(os.getenv('SCANNER_PROXY_FIX_X_PROTO', '1'))
PROXY_FIX_X_HOST = int(os.getenv('SCANNER_PROXY_FIX_X_HOST', '1'))

_RATE_LIMIT_BUCKETS = {}

# Cookies de sessao mais seguros (defesa em profundidade).
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = os.getenv('SCANNER_SESSION_SAMESITE', 'Lax')
app.config['SESSION_COOKIE_SECURE'] = os.getenv('SCANNER_SESSION_SECURE', '').lower() in ('1', 'true', 'yes')

if TRUST_PROXY:
    app.wsgi_app = ProxyFix(
        app.wsgi_app,
        x_for=PROXY_FIX_X_FOR,
        x_proto=PROXY_FIX_X_PROTO,
        x_host=PROXY_FIX_X_HOST,
    )


@app.after_request
def _security_headers(response):
    """Anti-clickjacking, MIME sniffing, CSP e HTTPS (evita achados do scanner)."""
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['X-Permitted-Cross-Domain-Policies'] = 'none'
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=(), payment=(), usb=()'
    response.headers['Cross-Origin-Resource-Policy'] = 'same-origin'

    # CSP reforcada: reduz XSS, clickjacking e mixed content.
    csp = (
        "default-src 'self'; "
        "base-uri 'self'; frame-ancestors 'none'; object-src 'none'; form-action 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-src 'none'"
    )
    if request.is_secure:
        csp += '; upgrade-insecure-requests; block-all-mixed-content'
    response.headers['Content-Security-Policy'] = csp
    # HSTS: em produção (HTTPS) ativa; em localhost não é enviado
    if request.is_secure:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    return response


@app.before_request
def _redirect_https_if_configured():
    """Redireciona HTTP -> HTTPS quando SCANNER_FORCE_HTTPS_REDIRECT=1."""
    if not FORCE_HTTPS_REDIRECT or request.is_secure:
        return None

    # So redireciona quando HTTPS estiver habilitado no app.
    https_enabled = (SSL_MODE == 'adhoc') or (SSL_MODE == 'cert' and SSL_CERT_PATH and SSL_KEY_PATH)
    if not https_enabled:
        return None

    if request.url.startswith('http://'):
        https_url = request.url.replace('http://', 'https://', 1)
        if HTTPS_REDIRECT_PORT and HTTPS_REDIRECT_PORT != 443:
            parsed = urlparse(https_url)
            clean_host = (parsed.netloc or '').split(':')[0]
            https_url = f'https://{clean_host}:{HTTPS_REDIRECT_PORT}{parsed.path}'
            if parsed.query:
                https_url += f'?{parsed.query}'
        return redirect(https_url, code=307)
    return None


def _is_allowed_domain(url: str) -> bool:
    """
    Restringe o scanner a domínios permitidos via variável de ambiente
    SCANNER_ALLOWED_DOMAINS, ex.: "meusite.com, api.meusite.com".
    Se não houver configuração, não restringe.
    """
    if not ALLOWED_DOMAINS:
        return True

    parsed = urlparse(url)
    host = (parsed.netloc or '').split(':')[0].lower()
    if not host:
        return False

    allowed = [d.strip().lower() for d in ALLOWED_DOMAINS.split(',') if d.strip()]
    if not allowed:
        return True

    return any(host == d or host.endswith('.' + d) for d in allowed)


def _check_internal_header():
    """
    Opcionalmente exige um cabeçalho interno (por ex. para integrar com Cloudflare).
    Se SCANNER_INTERNAL_HEADER_VALUE estiver vazio, não é exigido.
    """
    if not INTERNAL_HEADER_VALUE:
        return True
    incoming = request.headers.get(INTERNAL_HEADER_NAME, '').strip()
    return incoming == INTERNAL_HEADER_VALUE


def _rate_limit() -> bool:
    """
    Rate limit simples por IP em memória, para evitar abuso da interface web.
    Retorna True se a requisição está dentro do limite.
    """
    if RATE_LIMIT_MAX <= 0 or RATE_LIMIT_WINDOW <= 0:
        return True

    now = time()
    ip = request.remote_addr or 'unknown'
    bucket = _RATE_LIMIT_BUCKETS.get(ip, [])
    # limpa entradas antigas
    bucket = [t for t in bucket if now - t < RATE_LIMIT_WINDOW]
    if len(bucket) >= RATE_LIMIT_MAX:
        _RATE_LIMIT_BUCKETS[ip] = bucket
        return False
    bucket.append(now)
    _RATE_LIMIT_BUCKETS[ip] = bucket
    return True


def _set_e2e_token(token: str) -> None:
    global _last_e2e_result
    _last_e2e_result["token"] = token
    _last_e2e_result["status"] = "done"


def _run_e2e_advanced_thread(url: str, profile: str | None, cloudflare_timeout_ms: int) -> None:
    global _last_e2e_result
    _last_e2e_result = {"status": "running", "token": None, "error": None}
    try:
        run_e2e_advanced(
            url,
            user_data_dir=profile or None,
            cloudflare_timeout_ms=cloudflare_timeout_ms,
            turnstile_callback=_set_e2e_token,
            headless=True,
        )
        if _last_e2e_result["status"] == "running":
            _last_e2e_result["status"] = "done"
    except Exception as e:
        _last_e2e_result["status"] = "done"
        _last_e2e_result["error"] = str(e)


@app.route('/')
def index():
    return render_template('index.html', e2e_advanced_available=E2E_ADVANCED_AVAILABLE)


@app.route('/e2e-status')
def e2e_status():
    """Estado do E2E avançado (polling): status, token, error."""
    return jsonify(_last_e2e_result)


@app.route('/api/checks')
def api_checks():
    """Lista verificações disponíveis (id, label)."""
    from scanner_site import CHECK_FUNCS
    opts = []
    for k, labels in CHECK_FUNCS.items():
        for label, _ in labels:
            opts.append({'id': k, 'label': label})
    return jsonify({'checks': opts})


@app.route('/api/history')
def api_history():
    """Últimos scans (url, timestamp, total)."""
    return jsonify({'history': _scan_history[:20]})


def _store_scan(url: str, total: int, findings: list):
    global _last_scan_report, _scan_history
    from time import time
    _last_scan_report = {'url': url, 'findings': findings, 'total': total, 'ts': time()}
    _scan_history.insert(0, {'url': url, 'total': total, 'ts': time()})
    _scan_history[:] = _scan_history[:_MAX_HISTORY]


def _build_ai_insights(url: str, findings: list[dict]) -> dict:
    """
    Gera insights automáticos para priorizar correções.
    É uma camada heurística local para dar contexto prático ao relatório.
    """
    sev_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    for f in findings:
        sev = (f.get('severity') or 'medium').lower()
        if sev not in sev_counts:
            sev = 'medium'
        sev_counts[sev] += 1

    risk_score = 100 - (
        sev_counts['critical'] * 22
        + sev_counts['high'] * 14
        + sev_counts['medium'] * 8
        + sev_counts['low'] * 4
    )
    risk_score = max(0, min(100, risk_score))

    if risk_score >= 80:
        risk_level = 'baixo'
    elif risk_score >= 55:
        risk_level = 'moderado'
    elif risk_score >= 30:
        risk_level = 'alto'
    else:
        risk_level = 'crítico'

    priority = []
    by_type = {}
    for item in findings:
        t = (item.get('type') or '').upper()
        by_type[t] = by_type.get(t, 0) + 1

    top_types = sorted(by_type.items(), key=lambda x: x[1], reverse=True)[:3]
    for vuln_type, count in top_types:
        if 'SQL' in vuln_type:
            priority.append(f"Revisar consultas SQL e migrar para prepared statements ({count} achados).")
        elif 'XSS' in vuln_type:
            priority.append(f"Aplicar escape/sanitização consistente de saída e reforçar CSP ({count} achados).")
        elif 'LFI' in vuln_type or 'PATH' in vuln_type:
            priority.append(f"Bloquear path traversal com whitelist de arquivos e validação estrita ({count} achados).")
        elif 'HTTP METHODS' in vuln_type:
            priority.append(f"Restringir métodos HTTP perigosos no servidor e WAF ({count} achados).")
        elif 'MISCONFIG' in vuln_type:
            priority.append(f"Fechar misconfigurações e padronizar headers de segurança ({count} achados).")
        elif 'COOKIE' in vuln_type:
            priority.append(f"Corrigir cookies de sessão com HttpOnly, Secure e SameSite ({count} achados).")
        else:
            priority.append(f"Tratar vulnerabilidades {vuln_type} com prioridade operacional ({count} achados).")

    if not priority:
        priority.append("Nenhum achado crítico/prioritário; mantenha monitoramento e re-scan periódico.")

    previous_same_url = next((h for h in _scan_history if h.get('url') == url), None)
    trend = None
    if previous_same_url:
        prev_total = int(previous_same_url.get('total', 0))
        delta = len(findings) - prev_total
        if delta < 0:
            trend = f"Melhora em relação ao último scan: {abs(delta)} achado(s) a menos."
        elif delta > 0:
            trend = f"Piora em relação ao último scan: {delta} achado(s) a mais."
        else:
            trend = "Mesma quantidade de achados em relação ao último scan."

    headline = (
        f"Risco {risk_level.upper()} - score {risk_score}/100 "
        f"(C:{sev_counts['critical']} H:{sev_counts['high']} M:{sev_counts['medium']} L:{sev_counts['low']})"
    )
    summary = (
        "A IA local priorizou os pontos com maior impacto explorável para acelerar sua correção."
        if findings
        else "Sem vulnerabilidades aparentes nesta execução; mantenha validação contínua e pentest periódico."
    )
    if trend:
        summary += f" {trend}"

    return {
        'risk_score': risk_score,
        'risk_level': risk_level,
        'headline': headline,
        'summary': summary,
        'top_actions': priority,
        'severity_breakdown': sev_counts,
    }


@app.route('/api/export')
def api_export():
    """Exporta último relatório: ?format=json|html|csv"""
    global _last_scan_report
    fmt = request.args.get('format', 'json').lower()
    if not _last_scan_report:
        from flask import abort
        abort(404, 'Nenhum relatório para exportar')
    url = _last_scan_report['url']
    findings = _last_scan_report['findings']
    if fmt == 'csv':
        import csv
        import io
        out = io.StringIO()
        w = csv.writer(out)
        w.writerow(['Tipo', 'Descrição', 'Severidade', 'Remediação'])
        for f in findings:
            w.writerow([
                f.get('type', ''),
                f.get('desc', ''),
                f.get('severity', ''),
                (f.get('remediation') or '').replace('\n', ' '),
            ])
        from flask import Response
        return Response(out.getvalue(), mimetype='text/csv', headers={
            'Content-Disposition': f'attachment; filename=scan-{urlparse(url).netloc or "report"}.csv'
        })
    if fmt == 'html':
        rows = ''.join(
            f'<tr><td>{f.get("type")}</td><td>{f.get("desc")}</td><td>{f.get("severity")}</td><td>{f.get("remediation") or ""}</td></tr>'
            for f in findings
        )
        html = f'''<!DOCTYPE html><html><head><meta charset="utf-8"><title>Relatório - {url}</title>
<style>table{{border-collapse:collapse}} th,td{{border:1px solid #333;padding:6px}} th{{background:#222;color:#fff}}</style></head>
<body><h1>Scanner - {url}</h1><p>Total: {len(findings)}</p>
<table><tr><th>Tipo</th><th>Descrição</th><th>Severidade</th><th>Remediação</th></tr>{rows}</table></body></html>'''
        from flask import Response
        return Response(html, mimetype='text/html', headers={
            'Content-Disposition': f'inline; filename=scan-{urlparse(url).netloc or "report"}.html'
        })
    return jsonify(_last_scan_report)


@app.route('/scan', methods=['POST'])
def run_scan():
    # Tenta ler JSON; se falhar, cai para form sem estourar exceção
    if not _rate_limit():
        return jsonify({'error': 'Muitas requisições, tente novamente mais tarde'}), 429

    if not _check_internal_header():
        return jsonify({'error': 'Cabeçalho interno inválido ou ausente'}), 403

    data = request.get_json(silent=True) or request.form
    url = (data.get('url') or '').strip()
    checks = data.get('checks', ['misconfig', 'sql', 'xss'])
    e2e_human = bool(data.get('e2e_human'))
    e2e_advanced = bool(data.get('e2e_advanced')) and E2E_ADVANCED_AVAILABLE
    e2e_profile = (data.get('e2e_profile') or '').strip() or None
    cloudflare_timeout = data.get('cloudflare_timeout')
    cloudflare_timeout_ms = int(cloudflare_timeout) if cloudflare_timeout not in (None, '') else 60_000
    
    if not url:
        return jsonify({'error': 'URL é obrigatória'}), 400
    
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    if isinstance(checks, str):
        checks = [c.strip() for c in checks.split(',') if c.strip()]

    if len(url) > 2048:
        return jsonify({'error': 'URL muito longa'}), 400

    if not _is_allowed_domain(url):
        return jsonify({'error': 'Domínio não autorizado para varredura'}), 400
    
    valid_opts = ('misconfig', 'sql', 'xss', 'redirect', 'http_methods', 'cors', 'info', 'lfi', 'cookie', 'https')
    valid = [c for c in checks if c in valid_opts]
    if not valid:
        valid = ['misconfig', 'sql', 'xss']
    
    try:
        findings = scan(url, valid)

        # E2E humanizado (browser visível, scroll/mouse simples)
        if e2e_human and not e2e_advanced:
            threading.Thread(
                target=run_e2e_human,
                args=(url,),
                daemon=True,
            ).start()

        # E2E avançado (Turnstile, profile, Bézier, token callback)
        if e2e_advanced and run_e2e_advanced:
            threading.Thread(
                target=_run_e2e_advanced_thread,
                args=(url, e2e_profile, cloudflare_timeout_ms),
                daemon=True,
            ).start()

        items = []
        for item in findings:
            t, d = item[0], item[1]
            sev = item[2] if len(item) > 2 else 'medium'
            rem = item[3] if len(item) > 3 else ''
            items.append({'type': t, 'desc': d, 'severity': sev, 'remediation': rem})
        ai_insights = _build_ai_insights(url, items)
        _store_scan(url, len(findings), items)
        return jsonify({
            'url': url,
            'findings': items,
            'total': len(findings),
            'ai_insights': ai_insights,
            'e2e_human_started': bool(e2e_human),
            'e2e_advanced_started': bool(e2e_advanced),
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    host = os.getenv('SCANNER_HOST', '127.0.0.1')
    port = int(os.getenv('SCANNER_PORT', '5000'))
    debug = os.getenv('SCANNER_DEBUG', '1').lower() not in ('0', 'false', 'no')
    ssl_context = None
    if SSL_MODE == 'adhoc':
        ssl_context = 'adhoc'
    elif SSL_MODE == 'cert' and SSL_CERT_PATH and SSL_KEY_PATH:
        ssl_context = (SSL_CERT_PATH, SSL_KEY_PATH)

    if ssl_context:
        app.config['SESSION_COOKIE_SECURE'] = True

    scheme = 'https' if ssl_context else 'http'
    print(f'\n  Interface: {scheme}://{host}:{port}\n')
    if FORCE_HTTPS_REDIRECT and not ssl_context:
        print('  Aviso: SCANNER_FORCE_HTTPS_REDIRECT=1 ignorado sem SSL habilitado.')

    app.run(host=host, port=port, debug=debug, ssl_context=ssl_context)
