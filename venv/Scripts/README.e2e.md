
Script e imagem Docker para testes E2E em site com:

- **Cloudflare Turnstile**
- Headers anti-clickjacking / X-Content-Type-Options
- Redirecionamento HTTP → 307 HTTPS
- Profile de navegador “quentado” (cookies Google, Facebook, etc.)
- Mouse com curvas Bézier e scroll com velocidade variável
- Captura do token Turnstile via callback

## Uso local

```bash
cd Scripts
pip install -r requirements-e2e.txt
python -m playwright install chromium
```

```bash
# Sem profile (contexto limpo)
python e2e_playwright.py https://seu-site.com

# Com profile persistente (pasta com cookies/sessões)
python e2e_playwright.py https://seu-site.com --profile /caminho/para/profile

# Timeout do Cloudflare (ms) e browser visível
python e2e_playwright.py https://seu-site.com --cloudflare-timeout 90000 --no-headless
```

## Uso no código

```python
from e2e_playwright import run_e2e, launch_context, wait_cloudflare_gone, mouse_move_bezier, get_turnstile_token

def meu_callback(token: str) -> None:
    print("Token Turnstile:", token[:80])

token = run_e2e(
    "https://seu-site.com",
    user_data_dir="/var/e2e-profile",
    cloudflare_timeout_ms=60_000,
    turnstile_callback=meu_callback,
    headless=True,
)
```

## Docker (Debian 12 + xvfb)

Build e execução:

```bash
# Na raiz do repo (onde está Scripts/)
docker build -f Scripts/Dockerfile.e2e -t e2e-playwright Scripts/
docker run --rm e2e-playwright https://seu-site.com
```

Com profile montado e timeout customizado:

```bash
docker run --rm \
  -v /caminho/local/profile:/profile \
  e2e-playwright https://seu-site.com --profile /profile --cloudflare-timeout 90000
```

A imagem inicia o Xvfb (display :99) e executa o script em modo headless no framebuffer virtual.

## Profile “quentado”

Para reduzir desconfiança, use um diretório de perfil já usado em um Chrome real (com login em Google/Facebook etc.):

1. Copie a pasta de user data do Chrome (em Windows algo como `%LOCALAPPDATA%\Google\Chrome\User Data`) para um diretório, ou
2. Rode uma vez o script com `--profile /caminho` e faça login manual nos serviços; nas próximas execuções o mesmo `--profile` reutiliza cookies.

Não use o mesmo diretório simultaneamente com o Chrome aberto.
