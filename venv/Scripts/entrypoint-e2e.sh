#!/bin/sh
set -e
# Inicia Xvfb em background (display :99)
Xvfb :99 -screen 0 1920x1080x24 -ac &
XVFB_PID=$!
sleep 2
export DISPLAY=:99
exec python3 /app/e2e_playwright.py "$@"
