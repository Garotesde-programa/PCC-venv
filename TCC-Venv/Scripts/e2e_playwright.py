#!/usr/bin/env python3
"""
E2E Playwright para infra proprietária: Cloudflare Turnstile, headers Chrome 120,
profile aquecido, mouse Bézier, captura de token Turnstile, HTTPS 307, xvfb.

- Headers: Accept-Language, sec-ch-ua, DNT, Referer (enviado pelo Chromium em
  navegações subsequentes). TLS 1.3 e cipher-suites são as do Chromium (desktop).
- Redirect 307 HTTP→HTTPS: seguido automaticamente pelo Playwright.
- MIME (X-Content-Type-Options): o cliente aceita o content-type declarado;
  não é necessário alterar o parser.
- Container: use o Dockerfile.e2e com xvfb (Debian 12). Ex.:
  docker build -f Scripts/Dockerfile.e2e -t e2e-playwright Scripts/
  docker run -e URL=https://seu-site.com e2e-playwright
"""

from __future__ import annotations

import random
import time
from typing import Callable, Optional

# Headers de um Chrome 120 real (desktop)
CHROME_120_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
    "Accept-Language": "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7",
    "Accept-Encoding": "gzip, deflate, br",
    "Cache-Control": "max-age=0",
    "Sec-Ch-Ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Ch-Ua-Platform": '"Windows"',
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Upgrade-Insecure-Requests": "1",
    "DNT": "1",
    "Priority": "u=0, i",
}

USER_AGENT_CHROME_120 = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)

# Seletores comuns do Cloudflare / Turnstile (um deles sumir = desafio resolvido)
DEFAULT_CLOUDFLARE_SELECTORS = [
    "iframe[src*='challenges.cloudflare.com']",
    "iframe[src*='turnstile']",
    "#challenge-running",
    ".cf-turnstile",
    "[data-sitekey]",  # container Turnstile com data-sitekey
]


def _import_playwright():
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise RuntimeError(
            "Playwright não instalado. pip install playwright && python -m playwright install chromium"
        ) from exc
    return sync_playwright


def _human_sleep(min_s: float = 0.15, max_s: float = 0.4) -> None:
    time.sleep(random.uniform(min_s, max_s))


# --- Curva de Bézier cúbica para movimento de mouse realista ---

def _bezier_point(t: float, p0: tuple[float, float], p1: tuple[float, float],
                  p2: tuple[float, float], p3: tuple[float, float]) -> tuple[float, float]:
    """Ponto na curva Bézier cúbica em t in [0,1]."""
    u = 1.0 - t
    x = u * u * u * p0[0] + 3 * u * u * t * p1[0] + 3 * u * t * t * p2[0] + t * t * t * p3[0]
    y = u * u * u * p0[1] + 3 * u * u * t * p1[1] + 3 * u * t * t * p2[1] + t * t * t * p3[1]
    return (x, y)


def _ease_in_out(t: float) -> float:
    """Suaviza início e fim do movimento."""
    if t <= 0:
        return 0.0
    if t >= 1:
        return 1.0
    if t < 0.5:
        return 2 * t * t
    return 1 - pow(-2 * t + 2, 2) / 2


def mouse_move_bezier(page, x_end: float, y_end: float, steps: int = 40,
                      speed_variance: float = 0.3) -> None:
    """
    Move o mouse até (x_end, y_end) por uma curva de Bézier com velocidade variável.
    Reduz desconfiança de automação.
    """
    try:
        pos = page.mouse.position
    except Exception:
        pos = {"x": 0, "y": 0}
    x0, y0 = float(pos.get("x", 0)), float(pos.get("y", 0))

    # Controles aleatórios entre início e fim com desvio
    dx = x_end - x0
    dy = y_end - y0
    jitter = max(abs(dx), abs(dy)) * 0.2
    p1 = (x0 + dx * 0.25 + random.uniform(-jitter, jitter),
          y0 + dy * 0.25 + random.uniform(-jitter, jitter))
    p2 = (x0 + dx * 0.75 + random.uniform(-jitter, jitter),
          y0 + dy * 0.75 + random.uniform(-jitter, jitter))
    p0, p3 = (x0, y0), (x_end, y_end)

    for i in range(1, steps + 1):
        t_raw = i / steps
        # Pequena variação de velocidade por passo
        t_raw += random.uniform(-speed_variance / steps, speed_variance / steps)
        t_raw = max(0, min(1, t_raw))
        t = _ease_in_out(t_raw)
        x, y = _bezier_point(t, p0, p1, p2, p3)
        page.mouse.move(x, y)
        _human_sleep(0.008, 0.025)


def scroll_realistic(page, delta_y: int = 400, steps: int = 8) -> None:
    """Scroll com passos e velocidade variáveis (simula roda do mouse)."""
    step = delta_y // steps
    for _ in range(steps):
        page.mouse.wheel(0, step + random.randint(-20, 20))
        _human_sleep(0.05, 0.2)


def wait_cloudflare_gone(page, timeout_ms: int = 60_000,
                         selectors: Optional[list[str]] = None) -> None:
    """
    Aguarda qualquer um dos elementos Cloudflare/Turnstile desaparecer
    (desafio resolvido). Timeout em ms.
    """
    sel = selectors or DEFAULT_CLOUDFLARE_SELECTORS
    deadline = time.monotonic() + (timeout_ms / 1000.0)
    while time.monotonic() < deadline:
        visible = False
        for selector in sel:
            try:
                el = page.locator(selector).first
                if el.count() > 0 and el.is_visible():
                    visible = True
                    break
            except Exception:
                pass
        if not visible:
            return
        _human_sleep(0.5, 1.2)
    raise TimeoutError(f"Cloudflare/Turnstile ainda visível após {timeout_ms}ms")


def get_turnstile_token(page, widget_id: str = "cf-turnstile") -> Optional[str]:
    """
    Obtém o token do Turnstile após o widget estar pronto.
    widget_id: id do container do Turnstile (ex.: cf-turnstile).
    Retorna None se turnstile não existir ou ainda não tiver resposta.
    """
    script = """
    (widgetId) => {
        if (typeof window.turnstile !== 'undefined') {
            try {
                if (typeof window.turnstile.getResponse === 'function') {
                    return window.turnstile.getResponse(widgetId) || null;
                }
                var el = document.querySelector('[data-sitekey]');
                if (el && el.getAttribute && el.getAttribute('data-callback')) return null;
                return null;
            } catch (e) { return null; }
        }
        var container = document.getElementById(widgetId) || document.querySelector('.cf-turnstile');
        if (container && container.getAttribute('data-turnstile-response')) {
            return container.getAttribute('data-turnstile-response');
        }
        return null;
    }
    """
    try:
        return page.evaluate(script, widget_id)
    except Exception:
        return None


def wait_turnstile_ready_and_get_token(page, timeout_ms: int = 30_000,
                                       poll_interval_ms: int = 500,
                                       callback: Optional[Callable[[str], None]] = None) -> Optional[str]:
    """
    Espera turnstile.ready() (ou equivalente) e o token estar disponível;
    chama callback(token) se fornecido e devolve o token.
    """
    script_ready = """
    () => {
        if (typeof window.turnstile !== 'undefined' && typeof window.turnstile.getResponse === 'function')
            return true;
        var el = document.querySelector('.cf-turnstile, [data-sitekey]');
        if (el && el.getAttribute('data-turnstile-response')) return true;
        return false;
    }
    """
    deadline = time.monotonic() + (timeout_ms / 1000.0)
    token = None
    while time.monotonic() < deadline:
        try:
            if page.evaluate(script_ready):
                token = get_turnstile_token(page)
                if token:
                    if callback:
                        callback(token)
                    return token
        except Exception:
            pass
        time.sleep(poll_interval_ms / 1000.0)
    return token


def launch_context(
    user_data_dir: Optional[str] = None,
    headless: bool = True,
    viewport: Optional[dict] = None,
    locale: str = "pt-BR",
    timezone_id: str = "America/Sao_Paulo",
    ignore_https_errors: bool = True,
):
    """
    Abre contexto de navegador com profile opcional (quente), headers Chrome 120
    e TLS/navegação que segue 307 HTTPS sem reclamar.
    """
    sync_playwright = _import_playwright()
    p = sync_playwright().start()

    viewport = viewport or {"width": 1920, "height": 1080}
    launch_options = {
        "headless": headless,
        "args": [
            "--disable-blink-features=AutomationControlled",
            "--no-sandbox",
            "--disable-setuid-sandbox",
            "--disable-dev-shm-usage",
            "--disable-accelerated-2d-canvas",
            "--disable-gpu",
            "--window-size=1920,1080",
        ],
    }

    if user_data_dir:
        context = p.chromium.launch_persistent_context(
            user_data_dir,
            **launch_options,
            viewport=viewport,
            user_agent=USER_AGENT_CHROME_120,
            locale=locale,
            timezone_id=timezone_id,
            ignore_https_errors=ignore_https_errors,
            extra_http_headers=CHROME_120_HEADERS,
            accept_downloads=True,
        )
        return p, None, context, context.new_page()
    else:
        browser = p.chromium.launch(**launch_options)
        context = browser.new_context(
            viewport=viewport,
            user_agent=USER_AGENT_CHROME_120,
            locale=locale,
            timezone_id=timezone_id,
            ignore_https_errors=ignore_https_errors,
            extra_http_headers=CHROME_120_HEADERS,
        )
        context.add_init_script(
            "Object.defineProperty(navigator, 'webdriver', {get: () => undefined});"
        )
        context.add_init_script(
            "Object.defineProperty(navigator, 'languages', {get: () => ['pt-BR','pt','en-US','en']});"
        )
        page = context.new_page()
        return p, browser, context, page


def run_e2e(
    url: str,
    *,
    user_data_dir: Optional[str] = None,
    cloudflare_timeout_ms: int = 60_000,
    cloudflare_selectors: Optional[list[str]] = None,
    turnstile_callback: Optional[Callable[[str], None]] = None,
    turnstile_timeout_ms: int = 30_000,
    headless: bool = True,
    do_scroll_before_continue: bool = True,
    do_bezier_click: bool = True,
) -> Optional[str]:
    """
    Fluxo E2E completo:
    - Navega para url (segue 307 HTTP→HTTPS).
    - Aguarda Cloudflare/Turnstile desaparecer (timeout ajustável).
    - Opcional: scroll e movimento Bézier antes de continuar.
    - Captura token Turnstile e chama turnstile_callback(token) se fornecido.
    - Retorna o token Turnstile se obtido.

    user_data_dir: pasta de profile persistente (cookies Google/Facebook etc.).
    """
    p, browser, context, page = launch_context(
        user_data_dir=user_data_dir,
        headless=headless,
        ignore_https_errors=True,
    )
    token = None
    try:
        # Navegação segue redirect 307 por padrão no Playwright.
        # Não usamos networkidle: muitos sites nunca param (analytics, websockets) e dão timeout.
        page.goto(url, wait_until="domcontentloaded", timeout=60000)
        page.wait_for_load_state("load", timeout=15000)

        wait_cloudflare_gone(page, timeout_ms=cloudflare_timeout_ms, selectors=cloudflare_selectors)

        if do_scroll_before_continue:
            scroll_realistic(page, delta_y=random.randint(300, 600), steps=random.randint(6, 12))
            _human_sleep(0.3, 0.9)

        token = wait_turnstile_ready_and_get_token(
            page, timeout_ms=turnstile_timeout_ms, callback=turnstile_callback
        )

        if do_bezier_click and token:
            # Exemplo: clicar no centro da viewport com movimento Bézier
            vp = page.viewport_size or {}
            w, h = vp.get("width", 800), vp.get("height", 600)
            cx, cy = w / 2 + random.uniform(-50, 50), h / 2 + random.uniform(-30, 30)
            mouse_move_bezier(page, cx, cy, steps=random.randint(30, 50))
            _human_sleep(0.1, 0.3)
            page.mouse.click(cx, cy)

        return token
    finally:
        if browser:
            browser.close()
        else:
            context.close()
        p.stop()

    return token


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="E2E Playwright: Cloudflare Turnstile, profile quente, Bézier")
    parser.add_argument("url", help="URL alvo")
    parser.add_argument("--profile", default=None, help="Diretório do profile (user data dir)")
    parser.add_argument("--cloudflare-timeout", type=int, default=60_000, help="Timeout Cloudflare (ms)")
    parser.add_argument("--headless", action="store_true", default=False)
    parser.add_argument("--no-headless", dest="headless", action="store_false")
    args = parser.parse_args()

    def on_token(t: str):
        print("Turnstile token:", t[:80] + "..." if len(t) > 80 else t)

    run_e2e(
        args.url,
        user_data_dir=args.profile,
        cloudflare_timeout_ms=args.cloudflare_timeout,
        turnstile_callback=on_token,
        headless=args.headless,
    )
