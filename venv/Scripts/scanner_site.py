#!/usr/bin/env python3
"""
Scanner de Vulnerabilidades Web
Detecta: Misconfiguration, SQLi, XSS, Open Redirect, HTTP Methods, Info Disclosure
Otimizado com requisições paralelas
"""

import urllib.request
import urllib.parse
import urllib.error
import ssl
import re
import argparse
import sys
import os
import time
import random
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor

# Configuração (ajustáveis por variáveis de ambiente)
TIMEOUT = int(os.getenv('SCANNER_TIMEOUT', '5'))
MAX_WORKERS = int(os.getenv('SCANNER_MAX_WORKERS', '12'))
SCAN_USER_AGENT = os.getenv(
    'SCANNER_USER_AGENT',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Scanner/1.0',
)

SSL_CONTEXT = ssl.create_default_context()
SSL_CONTEXT.check_hostname = False
SSL_CONTEXT.verify_mode = ssl.CERT_NONE


class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


def make_request(url, data=None, method='GET', headers=None):
    """Faz requisição HTTP"""
    req_headers = {
        'User-Agent': SCAN_USER_AGENT,
        'Accept': 'text/html,application/xhtml+xml,*/*;q=0.9',
    }
    if headers:
        req_headers.update(headers)
    try:
        if data and method == 'POST':
            data = urllib.parse.urlencode(data).encode()
            req = urllib.request.Request(url, data=data, headers=req_headers, method='POST')
        else:
            req = urllib.request.Request(url, headers=req_headers, method=method)
        resp = urllib.request.urlopen(req, timeout=TIMEOUT, context=SSL_CONTEXT)
        return resp.read().decode('utf-8', errors='ignore'), resp.headers, resp.getcode()
    except urllib.error.HTTPError as e:
        h = e.headers if hasattr(e, 'headers') else {}
        return (e.read().decode('utf-8', errors='ignore') if e.fp else None), h, e.code
    except Exception:
        return None, {}, None


# ============ MISCONFIGURATION (paralelo) ============

def _check_path(args):
    base_url, path, desc = args
    try:
        full_url = urljoin(base_url, path)
        content, _, code = make_request(full_url)
        if content and code == 200 and len(content) > 10:
            return f"Possível exposição: {path} - {desc}"
    except Exception:
        pass
    return None


def check_sensitive_paths(base_url):
    sensitive = [
        ('/.git/config', 'Repositório Git exposto'),
        ('/.git/HEAD', 'Repositório Git exposto'),
        ('/.env', 'Arquivo de ambiente exposto'),
        ('/.env.local', 'Arquivo de ambiente exposto'),
        ('/.env.production', 'Arquivo de ambiente exposto'),
        ('/phpinfo.php', 'phpinfo exposto'),
        ('/phpinfo', 'phpinfo exposto'),
        ('/server-status', 'Status do servidor Apache'),
        ('/server-info', 'Info do servidor Apache'),
        ('/admin', 'Painel admin'),
        ('/administrator', 'Painel admin'),
        ('/wp-admin', 'WordPress admin'),
        ('/wp-config.php', 'Config WordPress'),
        ('/backup.sql', 'Backup de banco de dados'),
        ('/dump.sql', 'Dump de banco'),
        ('/.htaccess', 'Configuração Apache'),
        ('/web.config', 'Configuração IIS'),
        ('/config.php', 'Config PHP'),
        ('/config.json', 'Config JSON'),
        ('/.aws/credentials', 'Credenciais AWS'),
        ('/debug', 'Debug exposto'),
        ('/trace.axd', 'Trace ASP.NET'),
        ('/.svn/entries', 'Repositório SVN'),
        ('/crossdomain.xml', 'Flash crossdomain'),
        ('/clientaccesspolicy.xml', 'Silverlight policy'),
    ]
    findings = []
    tasks = [(base_url, p, d) for p, d in sensitive]
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        for r in ex.map(_check_path, tasks):
            if r:
                findings.append(r)
    return findings


def _is_localhost(parsed_or_url):
    """True se o host for 127.0.0.1 ou localhost (scanner apontando para a própria UI)."""
    if hasattr(parsed_or_url, 'netloc'):
        host = (parsed_or_url.netloc or '').split(':')[0].lower()
    else:
        parsed = urlparse(parsed_or_url)
        host = (parsed.netloc or '').split(':')[0].lower()
    return host in ('127.0.0.1', 'localhost', '')


def check_security_headers(url):
    findings = []
    try:
        parsed = urlparse(url)
        if _is_localhost(parsed):
            return findings  # Não acusar a própria interface local
        req = urllib.request.Request(url, headers={'User-Agent': SCAN_USER_AGENT}, method='HEAD')
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=SSL_CONTEXT) as resp:
            required = {
                'X-Frame-Options': 'Proteção contra clickjacking',
                'X-Content-Type-Options': 'Proteção contra MIME sniffing',
                'Content-Security-Policy': 'Política de segurança de conteúdo',
                'Strict-Transport-Security': 'Forçar HTTPS',
            }
            recommended = {
                'Referrer-Policy': 'Controle de vazamento de referrer',
                'Permissions-Policy': 'Controle de features do browser',
            }
            for header, desc in required.items():
                if header not in resp.headers or not resp.headers[header]:
                    findings.append(f"Header ausente: {header} ({desc})")
            for header, desc in recommended.items():
                if header not in resp.headers or not resp.headers[header]:
                    findings.append(f"Header recomendado ausente: {header} ({desc})")
    except Exception as e:
        findings.append(f"Erro ao verificar headers: {e}")
    return findings


def check_directory_listing(url):
    content, _, code = make_request(url)
    if content and code == 200:
        if any(x in content.lower() for x in ['index of', '[dir]', 'parent directory']):
            return [f"Listagem de diretório habilitada"]
    return []


# ============ SQL INJECTION (paralelo) ============

SQL_ERRORS = (
    "sql syntax", "mysql_fetch", "mysqli", "postgresql", "sqlite", "ora-01",
    "sqlstate", "unclosed quotation", "warning: mysql", "pg_query", "mssql",
    "syntax error", "mysql_num_rows", "mysql_error", "odbc_", "driver",
    "sqlexception", "sqlite3", "sql_exec", "mysql_query", "pg_exec",
    "ora-00933", "ora-01756", "pl/sql", "oci_", "unexpected end of sql",
)

SQL_PAYLOADS = [
    "'", "' OR '1'='1", "' OR 1=1--", "1' OR '1'='1' /*", "admin'--",
    "1; DROP TABLE users--", "1 UNION SELECT NULL--", "' OR ''='",
    "1' AND '1'='1", "' UNION SELECT 1,2,3--", "1' ORDER BY 1--",
    "' WAITFOR DELAY '0:0:5'--", "1; SELECT pg_sleep(5)--",
    "1' AND SLEEP(5)--", "1' AND 1=2 UNION SELECT * FROM users--",
    "' OR EXISTS(SELECT * FROM users)--", "1' RLIKE (SELECT",
]


def _test_sql(args):
    base_url, param_name, payload, all_params = args
    test_params = {k: (payload if k == param_name else v[0]) for k, v in all_params.items()}
    test_url = base_url + '?' + urllib.parse.urlencode(test_params)
    content, _, _ = make_request(test_url)
    if content:
        for err in SQL_ERRORS:
            if err in content.lower():
                return (param_name, f"Possível SQLi em ?{param_name}= - Erro: {err[:25]}...")
    return None


def check_sql_injection(url):
    parsed = urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)
    if not params:
        params = {'id': ['1'], 'q': ['test']}
    base_url = url.split('?')[0]

    tasks = []
    for pname, vals in params.items():
        for payload in SQL_PAYLOADS:
            tasks.append((base_url, pname, payload, {k: v for k, v in params.items()}))

    findings = []
    seen = set()
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        for r in ex.map(_test_sql, tasks):
            if r and r[0] not in seen:
                seen.add(r[0])
                findings.append(r[1])
    return findings[:8]


# ============ XSS (paralelo) ============

XSS_PAYLOADS = [
    '<script>alert(1)</script>', '"><img src=x onerror=alert(1)>', '<svg onload=alert(1)>',
    "javascript:alert(1)", "'-alert(1)-'", '<body onload=alert(1)>', '"><script>alert(1)</script>',
    '<img src=x onerror=alert(1)>', "'\"-->", '<iframe src="javascript:alert(1)">',
    '<input onfocus=alert(1) autofocus>', '<marquee onstart=alert(1)>',
    '"><svg/onload=alert(1)>', "';alert(1);//", '{{constructor.constructor("alert(1)")()}}',
]


def _test_xss(args):
    base_url, param_name, payload, all_params = args
    test_params = {k: (payload if k == param_name else v[0]) for k, v in all_params.items()}
    test_url = base_url + '?' + urllib.parse.urlencode(test_params)
    content, _, _ = make_request(test_url)
    if content:
        sanitized = payload.replace('<', '&lt;').replace('>', '&gt;')
        if payload in content and sanitized not in content:
            return (param_name, f"Possível XSS em ?{param_name}= - Payload refletido sem escape")
        if re.search(r'<script|onerror|onload', content, re.I):
            return (param_name, f"Possível XSS em ?{param_name}= - Tag/evento na resposta")
    return None


def check_xss(url):
    parsed = urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)
    if not params:
        params = {'q': ['test'], 'search': ['a']}
    base_url = url.split('?')[0] if '?' in url else url

    tasks = [(base_url, p, payload, params) for p in params for payload in XSS_PAYLOADS]
    findings = []
    seen = set()
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        for r in ex.map(_test_xss, tasks):
            if r and r[0] not in seen:
                seen.add(r[0])
                findings.append(r[1])
    return findings[:8]


# ============ OPEN REDIRECT ============

REDIRECT_PARAMS = [
    'redirect', 'url', 'next', 'return', 'returnUrl', 'dest', 'redir',
    'goto', 'target', 'link', 'ref', 'continue', 'out', 'view', 'to',
    'redirect_uri', 'redirect_url', 'callback', 'return_url', 'return_to',
]
REDIRECT_PAYLOAD = 'https://evil.com'


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _test_redirect(args):
    base_url, param = args
    sep = '&' if '?' in base_url else '?'
    test_url = base_url + sep + param + '=' + urllib.parse.quote(REDIRECT_PAYLOAD)
    opener = urllib.request.build_opener(NoRedirectHandler)
    try:
        req = urllib.request.Request(test_url, headers={'User-Agent': 'Mozilla/5.0 Scanner/1.0'})
        resp = opener.open(req, timeout=TIMEOUT, context=SSL_CONTEXT)
        return None
    except urllib.error.HTTPError as e:
        if e.code in (301, 302, 303, 307, 308):
            loc = e.headers.get('Location', '') or ''
            if REDIRECT_PAYLOAD in loc or 'evil.com' in loc:
                return f"Open Redirect em ?{param}= - Redireciona para URL externa"
    except Exception:
        pass
    return None


def check_open_redirect(url):
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}" + ('?' + parsed.query if parsed.query else '')
    tasks = [(base, p) for p in REDIRECT_PARAMS]
    findings = []
    with ThreadPoolExecutor(max_workers=8) as ex:
        for r in ex.map(_test_redirect, tasks):
                if r:
                    findings.append(r)
    return findings[:6]


# ============ HTTP METHODS ============

def check_http_methods(url):
    dangerous = ['PUT', 'DELETE', 'TRACE', 'PATCH', 'CONNECT']
    findings = []
    for method in dangerous:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': SCAN_USER_AGENT}, method=method)
            resp = urllib.request.urlopen(req, timeout=TIMEOUT, context=SSL_CONTEXT)
            if resp.getcode() in (200, 201, 204):
                findings.append(f"Método {method} permitido - risco de alteração/deleção")
        except urllib.error.HTTPError as e:
            if e.code not in (405, 501, 403, 404):
                findings.append(f"Método {method} retornou {e.code}")
        except Exception:
            pass
    return findings[:6]


# ============ PATH TRAVERSAL / LFI ============

LFI_PARAMS = ['file', 'path', 'page', 'include', 'doc', 'document', 'template', 'view', 'folder', 'dir', 'load', 'q']
LFI_PAYLOADS = [
    '../../../etc/passwd', '..%2F..%2F..%2Fetc/passwd', '....//....//....//etc/passwd',
    '..../..../..../etc/passwd', '%2e%2e%2f%2e%2e%2fetc/passwd', '..%252f..%252f..%252fetc/passwd',
]
LFI_INDICATORS = ['root:x:0:0', '[boot loader]', '/bin/bash', 'root:', '[extensions]']

def _test_lfi(args):
    base_url, param, payload = args
    test_url = base_url + ('&' if '?' in base_url else '?') + param + '=' + urllib.parse.quote(payload)
    content, _, code = make_request(test_url)
    if content and code == 200:
        for ind in LFI_INDICATORS:
            if ind in content:
                return (param, f"Possível LFI/Path Traversal em ?{param}= - Conteúdo sensível exposto")
    return None


def check_lfi(url):
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}" + ('?' + parsed.query if parsed.query else '')
    tasks = [(base, p, payload) for p in LFI_PARAMS for payload in LFI_PAYLOADS]
    findings = []
    seen = set()
    with ThreadPoolExecutor(max_workers=8) as ex:
        for r in ex.map(_test_lfi, tasks):
            if r and r[0] not in seen:
                seen.add(r[0])
                findings.append(r[1])
    return findings[:6]


# ============ COOKIE SECURITY ============

def check_cookie_security(url):
    findings = []
    try:
        req = urllib.request.Request(url, headers={'User-Agent': SCAN_USER_AGENT})
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=SSL_CONTEXT) as resp:
            set_cookie = resp.headers.get('Set-Cookie') or resp.headers.get('set-cookie') or ''
            if set_cookie:
                if 'HttpOnly' not in set_cookie and 'httponly' not in set_cookie.lower():
                    findings.append("Cookies sem flag HttpOnly - vulnerável a XSS roubando sessão")
                if 'Secure' not in set_cookie and 'secure' not in set_cookie.lower():
                    findings.append("Cookies sem flag Secure - podem ser enviados via HTTP")
            else:
                return []  # Sem cookies = nada a reportar
    except Exception:
        pass
    return findings


# ============ HTTPS REDIRECT ============

def check_https_redirect(url):
    parsed = urlparse(url)
    if _is_localhost(parsed):
        return []  # Em localhost não exige redirect HTTP→HTTPS
    host = parsed.netloc or parsed.path.split('/')[0]
    http_url = f"http://{host}/"
    try:
        req = urllib.request.Request(http_url, headers={'User-Agent': SCAN_USER_AGENT})
        resp = urllib.request.urlopen(req, timeout=TIMEOUT, context=SSL_CONTEXT)
        final = resp.geturl() or ''
        if 'https' not in final:
            return ["Site HTTP não redireciona para HTTPS - tráfego pode ser interceptado"]
    except Exception:
        pass
    return []


# ============ CORS ============

def check_cors(url):
    """CORS permissivo (Access-Control-Allow-Origin: * ou credenciais com origem ampla)."""
    findings = []
    if _is_localhost(urlparse(url)):
        return findings
    try:
        req = urllib.request.Request(url, headers={
            'User-Agent': SCAN_USER_AGENT,
            'Origin': 'https://evil.com',
        })
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=SSL_CONTEXT) as resp:
            acao = resp.headers.get('Access-Control-Allow-Origin', '').strip()
            if acao == '*' or (acao and 'evil.com' in acao):
                findings.append(f"CORS permissivo: Access-Control-Allow-Origin = {acao[:50]}")
    except Exception:
        pass
    return findings[:2]


# ============ INFO DISCLOSURE ============

def check_info_disclosure(url):
    findings = []
    try:
        req = urllib.request.Request(url, headers={'User-Agent': SCAN_USER_AGENT})
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=SSL_CONTEXT) as resp:
            h = resp.headers
            if 'Server' in h and h['Server']:
                findings.append(f"Header Server expõe tecnologia: {h['Server'][:60]}")
            if 'X-Powered-By' in h and h['X-Powered-By']:
                findings.append(f"X-Powered-By expõe: {h['X-Powered-By'][:60]}")
            if 'X-AspNet-Version' in h:
                findings.append("X-AspNet-Version expõe versão do ASP.NET")
            if 'X-Version' in h:
                findings.append(f"X-Version expõe: {h['X-Version'][:40]}")
            if 'X-Debug' in h or 'X-Debug-Token' in h:
                findings.append("Header de debug exposto")
    except Exception:
        pass
    return findings


# ============ SECURITY.TXT ============

def check_security_txt(url):
    findings = []
    try:
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        for path in ['/.well-known/security.txt', '/security.txt']:
            full = urljoin(base, path)
            content, _, code = make_request(full)
            if content and code == 200 and len(content) > 20:
                if 'Contact:' not in content and 'contact' not in content.lower():
                    findings.append(f"security.txt encontrado em {path} mas sem campo Contact")
                return findings
    except Exception:
        pass
    return findings


# ============ SEVERIDADE E REMEDIAÇÃO ============

SEVERITY = {
    'sql': 'critical', 'xss': 'critical', 'lfi': 'critical',
    'http_methods': 'high', 'redirect': 'medium', 'cors': 'medium',
    'misconfig': 'medium', 'info': 'low', 'cookie': 'medium',
    'https': 'high',
}

REMEDIATION = {
    'sql': 'Use prepared statements (parameterized queries). Nunca concatene input em SQL.',
    'xss': 'Escape output (HTML entities), use CSP, valide e sanitize todo input.',
    'misconfig': 'Configure headers de segurança no servidor (X-Frame-Options, CSP, etc). Adicione security.txt em /.well-known/security.txt.',
    'redirect': 'Valide URLs de redirect contra whitelist. Não redirecione para URLs externas.',
    'http_methods': 'Desabilite métodos perigosos (PUT, DELETE, TRACE) se não forem necessários.',
    'info': 'Remova ou ofusque headers Server, X-Powered-By no servidor.',
    'lfi': 'Evite incluir arquivos baseado em input. Use whitelist de arquivos permitidos.',
    'cookie': 'Configure Set-Cookie com HttpOnly e Secure para cookies de sessão.',
    'https': 'Configure redirect 301/302 de HTTP para HTTPS no servidor.',
    'cors': 'Use Access-Control-Allow-Origin com origens específicas, nunca * com credenciais.',
}


# ============ MAIN ============

CHECK_FUNCS = {
    'misconfig': [
        ('Headers', check_security_headers),
        ('Paths', check_sensitive_paths),
        ('Dir Listing', check_directory_listing),
        ('Security.txt', check_security_txt),
    ],
    'sql': [('SQLi', check_sql_injection)],
    'xss': [('XSS', check_xss)],
    'redirect': [('Open Redirect', check_open_redirect)],
    'http_methods': [('HTTP Methods', check_http_methods)],
    'cors': [('CORS', check_cors)],
    'info': [('Info Disclosure', check_info_disclosure)],
    'lfi': [('Path Traversal', check_lfi)],
    'cookie': [('Cookies', check_cookie_security)],
    'https': [('HTTPS Redirect', check_https_redirect)],
}


def scan(url, checks=None, progress_cb=None):
    if checks is None:
        checks = ['misconfig', 'sql', 'xss', 'redirect', 'http_methods', 'info']

    all_findings = []
    print(f"\n{Colors.BOLD}{Colors.BLUE}[*] Scan: {url}{Colors.RESET}\n")

    for check_name in checks:
        if check_name not in CHECK_FUNCS:
            continue
        for label, func in CHECK_FUNCS[check_name]:
            if progress_cb:
                progress_cb(check_name, label, 'running')
            print(f"{Colors.YELLOW}[+] {label}...{Colors.RESET}", end=' ', flush=True)
            try:
                results = func(url)
                items = results if isinstance(results, list) else ([results] if results else [])
                sev = SEVERITY.get(check_name, 'medium')
                rem = REMEDIATION.get(check_name, 'Consulte documentação de segurança.')
                for r in items:
                    all_findings.append((
                        check_name.upper().replace('_', ' '),
                        r,
                        sev,
                        rem,
                    ))
                if progress_cb:
                    progress_cb(check_name, label, 'done')
                print(f"{Colors.GREEN}OK{Colors.RESET}")
            except Exception as e:
                if progress_cb:
                    progress_cb(check_name, label, 'error')
                print(f"{Colors.RED}Erro{Colors.RESET}")
                all_findings.append((check_name.upper(), f"Erro: {e}", 'low', 'Verifique logs.'))

    return all_findings


def main():
    parser = argparse.ArgumentParser(description='Scanner de vulnerabilidades web')
    parser.add_argument('url', help='URL alvo')
    parser.add_argument('-c', '--checks', nargs='+',
                        choices=list(CHECK_FUNCS.keys()),
                        default=['misconfig', 'sql', 'xss', 'redirect', 'info'],
                        help='Tipos de verificação')
    parser.add_argument(
        '--e2e-human',
        action='store_true',
        help='Executa um fluxo E2E com Playwright simulando comportamento humano (QA)',
    )
    args = parser.parse_args()
    url = args.url
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    findings = scan(url, args.checks)

    if args.e2e_human:
        try:
            run_e2e_human(url)
        except Exception as e:
            print(f"{Colors.RED}[E2E] Erro ao executar fluxo humanizado: {e}{Colors.RESET}")

    print(f"\n{Colors.BOLD}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}  RELATÓRIO{Colors.RESET}\n")

    if not findings:
        print(f"{Colors.GREEN}[OK] Nenhuma vulnerabilidade aparente.{Colors.RESET}")
        return 0

    for item in findings:
        vuln_type = item[0]
        desc = item[1]
        c = Colors.RED if 'SQL' in vuln_type or 'XSS' in vuln_type or 'LFI' in vuln_type else Colors.YELLOW
        print(f"{c}[{vuln_type}]{Colors.RESET} {desc}")
    print(f"\n{Colors.YELLOW}Total: {len(findings)}{Colors.RESET}")
    return 1


if __name__ == '__main__':
    sys.exit(main() or 0)


# ============ E2E HUMANIZADO COM PLAYWRIGHT (QA) ============

def _import_playwright():
    """
    Importa Playwright de forma preguiçosa para não quebrar o scanner
    caso a lib não esteja instalada no ambiente.
    """
    try:
        from playwright.sync_api import sync_playwright  # type: ignore
    except ImportError as exc:
        raise RuntimeError(
            "Playwright não está instalado. "
            "Instale com: pip install playwright && playwright install chromium"
        ) from exc
    return sync_playwright


def human_sleep(min_s: float = 0.3, max_s: float = 1.2) -> None:
    time.sleep(random.uniform(min_s, max_s))


def human_type(locator, text: str, min_delay: float = 0.05, max_delay: float = 0.18) -> None:
    for ch in text:
        locator.type(ch)
        time.sleep(random.uniform(min_delay, max_delay))


def human_mouse_move(page, x: float, y: float, steps: int = 20) -> None:
    try:
        current = page.mouse.position
    except Exception:
        current = {"x": 0, "y": 0}
    x0, y0 = current["x"], current["y"]
    for i in range(1, steps + 1):
        nx = x0 + (x - x0) * i / steps + random.uniform(-1, 1)
        ny = y0 + (y - y0) * i / steps + random.uniform(-1, 1)
        page.mouse.move(nx, ny)
        human_sleep(0.01, 0.05)


def human_scroll(page, total: int = 2000, step: int = 200) -> None:
    current = 0
    while current < total:
        page.mouse.wheel(0, step + random.randint(-30, 30))
        current += step
        human_sleep(0.3, 1.0)


def launch_human_browser():
    sync_playwright = _import_playwright()
    p = sync_playwright().start()

    browser = p.chromium.launch(
        headless=False,
        args=[
            "--start-maximized",
            "--disable-blink-features=AutomationControlled",
        ],
    )

    context = browser.new_context(
        viewport={"width": 1366, "height": 768},
        user_agent=(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/122.0.0.0 Safari/537.36"
        ),
        locale="pt-BR",
        timezone_id="America/Sao_Paulo",
    )

    context.add_init_script(
        "Object.defineProperty(navigator, 'languages', "
        "{get: () => ['pt-BR', 'pt', 'en-US', 'en']});"
    )

    page = context.new_page()
    return p, browser, context, page


def run_e2e_human(url: str) -> None:
    """
    Fluxo E2E genérico, simulando um usuário navegando na URL informada.
    Adapte este fluxo para o seu cenário real (login, cliques específicos, etc).
    """
    print(f"{Colors.BLUE}[E2E] Iniciando fluxo humanizado com Playwright em: {url}{Colors.RESET}")
    p, browser, context, page = launch_human_browser()
    try:
        page.goto(url, wait_until="domcontentloaded")
        human_sleep(1.5, 3.0)

        human_scroll(page, total=1200, step=200)

        # Exemplo: aguarda alguns segundos como se o usuário estivesse lendo
        human_sleep(2.0, 4.0)

        print(f"{Colors.GREEN}[E2E] Fluxo humanizado básico concluído. "
              f"Adapte a função run_e2e_human() para o seu caso.{Colors.RESET}")
    finally:
        browser.close()
        p.stop()
