# HANO Cyber Security Bot 🛡️

Telegram bot with Kurdish Sorani cybersecurity education and basic defensive checks.

## Commands
- `/start`, `/help` — introduction and command list in Kurdish Sorani
- `/learn` — short account-security lesson
- `/password` — generates a 20-character password using Python's secure random generator
- `/urlcheck example.com` — checks HTTPS and common security response headers for a public website
- `/quiz` — short security-awareness quiz

## Safety
- The URL check is a basic header review, not a penetration test or a guarantee that a website is secure.
- Private, loopback, and non-public IP destinations are rejected; redirects are not followed.
- Only check systems you own or are explicitly authorized to assess.
- Never commit your Telegram bot token. Store it only in your hosting provider's environment variables.
- The repository is currently public. Do not add secrets or personal data to it. Change repository visibility to Private in GitHub Settings if you want the source code private.

## Run locally
Requires Python 3.11 or newer.

1. Install dependencies: `pip install -r requirements.txt`
2. Set environment variable `TELEGRAM_BOT_TOKEN` to the token from Telegram's official @BotFather. Never paste it into source code or chat.
3. Run: `python main.py`

Linux/macOS:
```bash
export TELEGRAM_BOT_TOKEN="your-token"
python main.py
```

Windows PowerShell:
```powershell
$env:TELEGRAM_BOT_TOKEN="your-token"
python main.py
```

## Deploy on Railway
1. Create a Railway project and deploy this GitHub repository from branch `main`.
2. In the service's **Variables** section, add `TELEGRAM_BOT_TOKEN` and paste the token privately there.
3. Deploy/redeploy. Check the deployment logs for `HANO Cyber Security Bot is starting.`
4. Open your Telegram bot and send `/start`.

The included `Procfile` defines a worker process: `python main.py`.

## Troubleshooting
- If logs say `TELEGRAM_BOT_TOKEN environment variable is missing`, add the variable in the hosting dashboard.
- If Telegram reports another `getUpdates` request, stop any duplicate bot process. Run only one polling instance for this token.
- If a token was exposed, revoke it with @BotFather and set the replacement in the host's Variables.
