# HANO Cyber Security Agent 🛡️

Telegram-based defensive cybersecurity assistant in Kurdish Sorani. This version introduces a scoped task workflow; it is **not yet a full LLM-powered autonomous agent**.

## Commands
- `/start`, `/help` — instructions
- `/agent <task>` — classify a request, outline a safe plan, and run the supported passive check when applicable
- `/status` — configuration status
- `/scope` — configured authorized domains
- `/urlcheck example.com` — passive HTTPS and response-header check
- `/analyzelog <log text>` — local heuristic review of pasted logs; does not execute log content
- `/password` — generate a 24-character password
- `/learn`, `/quiz` — security basics

## Scope and safety
- Website checks only run for domains explicitly listed in `AUTHORIZED_TARGETS`.
- Use only domains you own or have explicit permission to assess.
- Checks are passive and limited to HTTPS and common security response headers; they are not penetration tests and do not prove a system is secure.
- Private/loopback/non-public IP destinations are rejected; redirects are not followed.
- The bot does not execute shell commands, exploit targets, bypass authentication, steal credentials, deploy malware, or exfiltrate data.
- Log analysis is heuristic and may miss indicators or flag benign text. Do not send passwords, tokens, personal data, or other secrets in logs.
- Never commit bot tokens or API keys. Store secrets only in the host's private environment variables.

## Environment variables
- `TELEGRAM_BOT_TOKEN` — required token from Telegram's official @BotFather
- `AUTHORIZED_TARGETS` — comma-separated domains approved for passive checks, e.g. `example.com,yourdomain.org`
- `LOG_LEVEL` — optional logging level, default `INFO`

An empty `AUTHORIZED_TARGETS` means no website is authorized for scanning.

## Run locally
Requires Python 3.11+.

1. Install dependencies: `pip install -r requirements.txt`
2. Set `TELEGRAM_BOT_TOKEN` and optionally `AUTHORIZED_TARGETS`.
3. Run: `python main.py`

Linux/macOS:
```bash
export TELEGRAM_BOT_TOKEN="your-token"
export AUTHORIZED_TARGETS="yourdomain.org"
python main.py
```

Windows PowerShell:
```powershell
$env:TELEGRAM_BOT_TOKEN="your-token"
$env:AUTHORIZED_TARGETS="yourdomain.org"
python main.py
```

## Railway deployment
1. Open the service's **Variables** section.
2. Add `TELEGRAM_BOT_TOKEN` using the token privately; do not paste it into chat or GitHub.
3. Add `AUTHORIZED_TARGETS` with only domains you are authorized to test.
4. Redeploy and check runtime logs for `HANO Cyber Security Agent starting`.
5. In Telegram, send `/start` and then `/status`.

## Current limitations / next phase
This release uses deterministic rules for task routing; it does not yet use an external AI model, persistent task queue, database, or scheduled monitoring. Those should be added as separate, testable components with explicit approval gates before any impactful action.
