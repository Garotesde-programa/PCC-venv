# Scanner de Vulnerabilidades Web

Ferramenta de varredura de segurança com interface web, E2E humanizado e E2E avançado (Cloudflare Turnstile, profile, Bézier).

## Funcionalidades

- **Scanner**: Headers de segurança, paths sensíveis, listagem de diretório, SQLi, XSS, Open Redirect, HTTP Methods, **CORS**, Info Disclosure, LFI/Path Traversal, Cookies, HTTPS Redirect.
- **Interface web**: Presets (rápido, completo, só headers, injeção), filtro por severidade, ordenação, export JSON/CSV/HTML, copiar relatório, tema claro/escuro, atalho Ctrl+Enter.
- **E2E humanizado**: Playwright com scroll e mouse simulados (browser visível).
- **E2E avançado**: Turnstile, profile “quentado”, mouse Bézier, captura de token, headless; opcional em Docker com xvfb.

## Uso rápido

1. **Interface (atalho)**  
   Execute `iniciar_scanner_ia.bat` — abre o navegador em http://127.0.0.1:5000.

2. **Linha de comando**  
   ```bash
   cd Scripts
   python scanner_site.py https://exemplo.com -c misconfig sql xss
   python scanner_site.py https://exemplo.com --e2e-human
   ```

3. **E2E avançado (CLI)**  
   ```bash
   rodar_e2e_avancado.bat https://seu-site.com
   ```

## Requisitos

- Python 3.9+
- `pip install -r requirements.txt`
- Para E2E: `pip install playwright` e `python -m playwright install chromium`

## Configuração

Veja `.env.example`. Variáveis opcionais: `SCANNER_ALLOWED_DOMAINS`, `SCANNER_INTERNAL_HEADER_VALUE`, `SCANNER_RATE_LIMIT_*`, `SCANNER_TIMEOUT`, `SCANNER_FORCE_HTTPS_REDIRECT`.

## APIs

- `POST /scan` — executa scan (JSON: url, checks, e2e_human, e2e_advanced, …).
- `GET /e2e-status` — estado do E2E avançado (polling).
- `GET /api/checks` — lista de verificações disponíveis.
- `GET /api/history` — últimos scans.
- `GET /api/export?format=json|csv|html` — exporta último relatório.

## E2E em Docker

Ver `Scripts/README.e2e.md` e `Scripts/Dockerfile.e2e`.
