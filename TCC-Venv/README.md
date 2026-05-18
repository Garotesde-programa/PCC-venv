# Scanner de Vulnerabilidades Web

Ferramenta de varredura de segurança com interface web, relatórios executivos, histórico em SQLite e E2E com Playwright.

> **Aviso legal:** use apenas em sistemas que você possui ou tem autorização explícita para testar. Varreduras não autorizadas podem ser ilegais.

## Funcionalidades

- **Scanner:** headers de segurança, paths sensíveis, listagem de diretório, SQLi, XSS, open redirect, HTTP methods, CORS, info disclosure, LFI, cookies, HTTPS redirect
- **Interface web:** presets, filtro por severidade, insights de risco, modo diretoria, histórico, cancelamento de scan
- **Export:** JSON, CSV, HTML, SARIF (CI/CD)
- **Achados:** CWE, severidade, confiança, remediação e evidências
- **E2E:** humanizado (browser visível) e avançado (Turnstile, profile, Bézier)

## Início rápido (Windows)

1. Clone o repositório
2. Dê duplo clique em `iniciar_scanner_ia.bat`
3. Na primeira execução o script cria `.venv` e instala dependências
4. Marque a confirmação de autorização e escaneie a URL

Requisito: **Python 3.9+** instalado (`py -3` ou `python` no PATH).

## Linha de comando

```bash
cd Scripts
python scanner_site.py https://exemplo.com -c misconfig sql xss
python scanner_site.py https://exemplo.com --e2e-human
```

E2E avançado (opcional):

```bash
rodar_e2e_avancado.bat https://seu-site.com
```

Requer `pip install playwright` e `python -m playwright install chromium`.

## Configuração

Copie `.env.example` para `.env` e ajuste:

| Variável | Descrição |
|----------|-----------|
| `SCANNER_ALLOWED_DOMAINS` | Restringe domínios permitidos |
| `SCANNER_ALLOW_PRIVATE` | `1` para permitir IPs privados (lab) |
| `SCANNER_WEB_TOKEN` | Token opcional para API |
| `SCANNER_DB_PATH` | Caminho do SQLite (padrão: `data/scanner.db`) |

## API

| Endpoint | Método | Descrição |
|----------|--------|-----------|
| `/api/health` | GET | Status e versão |
| `/scan` | POST | Inicia scan (`authorized: true` obrigatório) |
| `/api/scan/<id>` | GET | Status do job |
| `/api/scan/<id>` | DELETE | Cancela scan |
| `/api/history` | GET | Histórico |
| `/api/export?format=` | GET | `json`, `csv`, `html`, `sarif` |

## Estrutura

```
├── iniciar_scanner_ia.bat   # Launcher principal
├── _env.bat                 # Bootstrap do venv
├── Scripts/                 # Código Python + UI
├── data/                    # Banco SQLite (gerado localmente)
└── requirements.txt
```

## Scripts úteis

- `verificar_venv.bat` — testa Python e Flask
- `recriar_venv.bat` — recria `.venv` do zero

## E2E em Docker

Ver `Scripts/README.e2e.md` e `Scripts/Dockerfile.e2e`.

## Licença

MIT — veja [LICENSE](LICENSE).
