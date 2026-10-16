import asyncio
import ipaddress
import logging
import os
import secrets
import socket
import string
from urllib.parse import urlparse

import requests
from telegram import Update
from telegram.ext import Application, ApplicationHandlerStop, CommandHandler, ContextTypes, MessageHandler, TypeHandler, filters

BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
AUTHORIZED_USER_IDS = {
    item.strip() for item in os.getenv("AUTHORIZED_USER_IDS", "").split(",") if item.strip()
}
AUTHORIZED_TARGETS = tuple(
    item.strip().lower().lstrip(".")
    for item in os.getenv("AUTHORIZED_TARGETS", "").split(",")
    if item.strip()
)
MAX_LOG_CHARS = 3500

logging.basicConfig(
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
)
logger = logging.getLogger("hano-cyber-bot")

SECURITY_HEADERS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "Content-Security-Policy",
    "x-content-type-options": "X-Content-Type-Options",
    "x-frame-options": "X-Frame-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
}

HELP = """🛡️ HANO Cyber Security Agent

/agent <ئەرک> — پلانکردن و جێبەجێکردنی ئەرکی پارێزراو
/id — بینینی Telegram user ID ـی خۆت
/status — دۆخی بۆت و ڕێکخستنەکان
/scope — دۆمەینە ڕێگەپێدراوەکان
/urlcheck example.com — پشکنینی passive هێدەرەکانی وێب
/analyzelog <لۆگ> — شیکردنەوەی لۆگی ناردراو
/password — دروستکردنی وشەی نهێنی
/learn — ڕێنمایی پاراستن
/quiz — پرسیاری فێرکاری
/help — ئەم لیستە

⚠️ پشکنینی دۆمەین تەنها بۆ ئامانجێک کار دەکات کە لە AUTHORIZED_TARGETS دانراوە.
بۆتەکە exploit، هاککردنی بێ‌مۆڵەت، دزینی وشەی نهێنی یان شکاندنی دەسەڵات جێبەجێ ناکات.
"""

LESSON = """📘 ڕێنمایی پاراستنی هەژمار
• وشەی نهێنیی درێژ و جیاواز بۆ هەر هەژمارێک بەکاربهێنە.
• 2FA/MFA چالاک بکە.
• Token و کۆدی پشتڕاستکردنەوە مەدەرەوە.
• سیستەم و پەکێجەکان نوێ بکەرەوە.
• لۆگ و ئاگادارکردنەوەکانی چوونەژوورەوە چاودێری بکە.
"""

def is_authorized_host(host: str) -> bool:
    host = host.rstrip(".").lower()
    return any(host == allowed or host.endswith("." + allowed) for allowed in AUTHORIZED_TARGETS)

def normalize_public_url(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        raise ValueError("تکایە دۆمەین یان URL بنووسە.")
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("URL ـەکە دروست نییە؛ تەنها http یان https.")
    if parsed.username or parsed.password:
        raise ValueError("URL نابێت زانیاری چوونەژوورەوەی تێدا بێت.")
    host = parsed.hostname.rstrip(".").lower()
    if not is_authorized_host(host):
        raise PermissionError("ئەم دۆمەینە لە لیستی ئامانجە ڕێگەپێدراوەکاندا نییە. AUTHORIZED_TARGETS ڕێکبخە.")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        try:
            infos = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)
        except socket.gaierror:
            raise ValueError("دۆمەین نەدۆزرایەوە.")
        if not infos:
            raise ValueError("دۆمەین نەدۆزرایەوە.")
        for info in infos:
            address = ipaddress.ip_address(info[4][0])
            if not address.is_global:
                raise ValueError("دۆمەین بۆ IP ـی ناوخۆیی/تایبەت دەچێت؛ پشکنین ڕەتکرایەوە.")
    else:
        if not ip.is_global:
            raise ValueError("IP ـی تایبەت یان ناوخۆیی ڕێگەپێدراو نییە.")
    return raw

def inspect_url(raw: str) -> str:
    url = normalize_public_url(raw)
    parsed = urlparse(url)
    try:
        response = requests.get(
            url,
            timeout=(4, 8),
            allow_redirects=False,
            stream=True,
            headers={"User-Agent": "HANO-CyberSecurityAgent/2.0 (authorized passive check)"},
        )
    except requests.exceptions.SSLError:
        return "❌ کێشەی TLS/SSL هەیە؛ گواهینامە و زنجیرەی TLS بپشکنە."
    except requests.exceptions.Timeout:
        return "⏳ وەڵامی وێبسایت لە کاتی دیاریکراودا نەهات."
    except requests.RequestException:
        return "❌ پەیوەندی بە وێبسایتەکە سەرکەوتوو نەبوو."
    try:
        headers = {k.lower(): v for k, v in response.headers.items()}
        lines = [
            "🧾 HANO — ڕاپۆرتی پشکنینی passive",
            f"🌐 ئامانج: {parsed.hostname}",
            f"📡 HTTP status: {response.status_code}",
            f"🔒 HTTPS: {'بەڵێ' if parsed.scheme == 'https' else 'نەخێر — HTTPS پێشنیار دەکرێت'}",
            "",
            "هێدەرەکانی پاراستن:",
        ]
        for key, label in SECURITY_HEADERS.items():
            if key == "strict-transport-security" and parsed.scheme != "https":
                lines.append(f"⚪ {label}: تەنها لە HTTPS هەڵسەنگێنرێت")
            else:
                lines.append(f"{'✅' if key in headers else '⚠️'} {label}: {'هەیە' if key in headers else 'نەبینرا'}")
        if response.status_code in (301, 302, 303, 307, 308):
            lines.extend(["", "↪️ Redirect هەیە؛ بۆت بەدوای redirect ـەکەدا ناچێت."])
        lines.extend([
            "",
            "جۆری پشکنین: passive و کەم‌مەترسی؛ exploit یان penetration test نییە.",
            "ئەنجامەکان نیشانەی پشکنینن، نەک دڵنیایی تەواوی ئاسایش.",
        ])
        return "\n".join(lines)
    finally:
        response.close()

def analyze_log(raw: str) -> str:
    text = raw[:MAX_LOG_CHARS]
    if not text.strip():
        return "بەکارهێنان: /analyzelog <دەقی لۆگ>"
    patterns = [
        ("وشەی نهێنی/چوونەژوورەوەی هەڵە", ("failed password", "authentication failure", "login failed", "invalid user", "401", "403")),
        ("هەوڵی زۆری چوونەژوورەوە", ("brute force", "too many attempts", "rate limit", "many failed")),
        ("دەستگەیشتنی بەرز/گۆڕینی دەسەڵات", ("sudo", "privilege escalation", "administrator added", "new admin")),
        ("نیشانەی فرمانی گومانلێکراو", ("powershell -enc", "encodedcommand", "base64", "curl | sh", "wget | sh")),
        ("نیشانەی گۆڕینی ڕێکخستن یان پاککردنەوەی لۆگ", ("audit log cleared", "log deleted", "firewall disabled", "defender disabled")),
    ]
    lower = text.lower()
    hits = [label for label, needles in patterns if any(needle in lower for needle in needles)]
    lines = ["🔎 HANO — شیکردنەوەی لۆگ", f"📏 بڕی پشکنراو: {len(text)} پیت"]
    if hits:
        lines.append("⚠️ نیشانەی پێویست بە پشکنین:")
        lines.extend(f"• {item}" for item in hits)
        lines.append("پێش بڕیاری کۆتایی، timestamp، IP، user و ڕووداوە پێش/دوایەکان بەراورد بکە.")
    else:
        lines.append("✅ لە وشە نیشانە سادەکاندا هیچ هاوتایەک نەدۆزرایەوە؛ ئەمە بەڵگەی پاکبوونی لۆگ نییە.")
    lines.append("تێبینی: شیکردنەوەی سەرەتاییە؛ هیچ فرمانێک لە لۆگ جێبەجێ ناکرێت.")
    return "\n".join(lines)

def plan_agent_task(task: str) -> str:
    goal = task.strip()
    if not goal:
        return "بەکارهێنان: /agent ئەرکەکەت بە ڕوونی بنووسە."
    lower = goal.lower()
    if any(word in lower for word in ("hack", "exploit", "بشکێنە", "هەک", "دزی", "steal", "malware")):
        return (
            "🛑 ئەم داواکارییە ناتوانم وەک هێرش یان شکاندنی پاراستن جێبەجێ بکەم.\n"
            "دەتوانم بە شێوەی پارێزراو یارمەتیت بدەم: پشکنینی passive، شیکردنەوەی لۆگ، "
            "هەڵسەنگاندنی ڕێکخستنەکان، یان ڕاپۆرتی چارەسەر."
        )
    if any(word in lower for word in ("log", "لۆگ", "ڕووداو")):
        return "🧭 پلانی ئەرک:\n1) /analyzelog لەگەڵ دەقی لۆگ بنێرە.\n2) نیشانەکان پۆلێن دەکەم.\n3) هەنگاوی پشکنینی دواتر پێشنیار دەکەم.\n\nهیچ فرمانێک لە ناو لۆگ جێبەجێ ناکرێت."
    if any(word in lower for word in ("website", "website", "دۆمەین", "وێبسایت", "url", "https", "هێدەر")):
        tokens = goal.replace(",", " ").split()
        candidate = next((t for t in tokens if "." in t and "/" not in t and not t.startswith("http")), None)
        candidate = candidate or next((t for t in tokens if t.startswith(("http://", "https://"))), None)
        if not candidate:
            return "🧭 پلانی ئەرک:\n1) دۆمەین بنووسە.\n2) پشکنینی passiveی HTTPS و security headers.\n3) ڕاپۆرت و هەنگاوەکانی چاکسازی.\n\nنموونە: /agent پشکنینی وێبسایت example.com"
        try:
            return inspect_url(candidate)
        except (ValueError, PermissionError) as exc:
            return f"⛔ {exc}"
    return (
        "🧭 پلانی سەرەتایی HANO Agent\n"
        f"ئەرک: {goal[:500]}\n\n"
        "١) ئامانج و دەسەڵاتی ڕێگەپێدراو دیاری بکە.\n"
        "٢) بەکارهێنانی پشکنینی passive یان شیکردنەوەی لۆگ.\n"
        "٣) ئەنجامەکان کۆبکەرەوە و ڕاپۆرت دروست بکە.\n\n"
        "بۆ جێبەجێکردنی ئۆتۆماتیکی، ئەرکەکە بە وردی بنووسە و ئامانجی ڕێگەپێدراو لە AUTHORIZED_TARGETS زیاد بکە."
    )

async def authorize_update(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Fail closed: only allowlisted Telegram users can use bot features; /id is safe for setup."""
    user = update.effective_user
    message = update.effective_message
    if user is None or message is None:
        return
    text = (message.text or "").strip()
    if text.split(maxsplit=1)[0].split("@")[0].lower() == "/id":
        return
    if str(user.id) not in AUTHORIZED_USER_IDS:
        await message.reply_text(
            "🔒 ئەم بۆتە تایبەتە. بۆ ناسینی Telegram ID ـی خۆت /id بنێرە، "
            "پاشان ID ـەکەت لە Railway → Variables بە ناوی AUTHORIZED_USER_IDS زیاد بکە."
        )
        raise ApplicationHandlerStop

async def user_id(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.effective_message and update.effective_user:
        await update.effective_message.reply_text(
            f"Telegram user ID ـی تۆ: {update.effective_user.id}\n"
            "ئەم ژمارەیە تەنها لە Railway → Variables لە AUTHORIZED_USER_IDS دایبنێ؛ "
            "لە GitHub یان شوێنی گشتی دانەمەزرێنە."
        )

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.message:
        await update.message.reply_text(
            "سڵاو! 👋\nبەخێربێیت بۆ HANO Cyber Security Agent.\n"
            "ئەم وەشانە بنەمای agent و ئەرکە پارێزراوەکان دەخاتە کار.\n\n" + HELP
        )

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.message:
        await update.message.reply_text(HELP)

async def status(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.message:
        return
    targets = ", ".join(AUTHORIZED_TARGETS) if AUTHORIZED_TARGETS else "هیچ ئامانجێک دانەنراوە"
    token_state = "✅ دانراوە" if BOT_TOKEN else "❌ دانەنراوە"
    await update.message.reply_text(
        "🧩 HANO Agent Status\n"
        f"• Telegram token: {token_state}\n"
        f"• ئامانجە ڕێگەپێدراوەکان: {targets}\n"
        "• Passive website checks: چالاک، بە مەرجی allowlist\n"
        "• Log analysis: شیکردنەوەی ناوخۆیی، بێ جێبەجێکردنی فرمان\n"
        "• AI API: لەم وەشانەدا پەیوەست نەکراوە؛ agent workflow ـەکە سنووردار و rule-based ـە."
    )

async def scope(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.message:
        return
    if not AUTHORIZED_TARGETS:
        await update.message.reply_text(
            "🔐 هێشتا هیچ ئامانجێکی ڕێگەپێدراو نییە.\n"
            "لە Railway → Variables، گۆڕاوی AUTHORIZED_TARGETS زیاد بکە؛ "
            "نموونە: example.com,yourdomain.org\n"
            "تەنها دۆمەینەکانی خۆت یان ئەوانەی مۆڵەتی نووسراوت هەیە زیاد بکە."
        )
    else:
        await update.message.reply_text("🔐 ئامانجە ڕێگەپێدراوەکان:\n" + "\n".join(f"• {x}" for x in AUTHORIZED_TARGETS))

async def learn(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.message:
        await update.message.reply_text(LESSON)

async def password(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.message:
        return
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    value = "".join(secrets.choice(alphabet) for _ in range(24))
    await update.message.reply_text(
        "🔐 وشەی نهێنییەکی بەهێز (٢٤ پیت):\n"
        f"{value}\n\nلە شوێنێکی پارێزراودا هەڵیبگرە و بۆ هەژمارە جیاوازەکان دووبارە بەکاری مەهێنە."
    )

async def urlcheck(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.message:
        return
    if not context.args:
        await update.message.reply_text("بەکارهێنان: /urlcheck example.com")
        return
    await update.message.reply_text("⏳ پشکنینی passive دەکەم...")
    try:
        result = await asyncio.to_thread(inspect_url, " ".join(context.args))
    except (ValueError, PermissionError) as exc:
        result = f"⛔ {exc}"
    await update.message.reply_text(result, disable_web_page_preview=True)

async def agent(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.message:
        return
    task = " ".join(context.args)
    await update.message.reply_text("🧠 ئەرکەکە شیکاری دەکەم و سنووری پاراستن دەپشکنم...")
    try:
        result = await asyncio.to_thread(plan_agent_task, task)
    except Exception:
        logger.exception("Agent task failed")
        result = "❌ لە جێبەجێکردنی ئەرکەکەدا هەڵەیەک ڕوویدا؛ لۆگەکانی سێرڤەر بپشکنە."
    await update.message.reply_text(result, disable_web_page_preview=True)

async def analyzelog(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.message:
        return
    raw = " ".join(context.args)
    result = await asyncio.to_thread(analyze_log, raw)
    await update.message.reply_text(result)

async def quiz(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.message:
        context.user_data["quiz_active"] = True
        await update.message.reply_text(
            "🧠 کامەیان پاراستنی هەژمار زیاد دەکات؟\n"
            "A) هەمان وشەی نهێنی بۆ هەموو شوێنێک\n"
            "B) وشەی نهێنیی جیاواز + 2FA\n"
            "C) ناردنی کۆدی پشتڕاستکردنەوە بۆ هاوڕێ\n\nوەڵامت: A، B یان C"
        )

async def text_answer(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.message or not update.message.text or not context.user_data.get("quiz_active"):
        return
    answer = update.message.text.strip().upper()
    context.user_data["quiz_active"] = False
    if answer in {"B", "٢", "2"}:
        await update.message.reply_text("✅ ڕاستە! وشەی نهێنیی جیاواز و 2FA پاراستن زیاد دەکەن.")
    elif answer in {"A", "C", "١", "٣", "1", "3"}:
        await update.message.reply_text("❌ وەڵامی دروست B ـە: وشەی نهێنیی جیاواز + 2FA.")
    else:
        await update.message.reply_text("پرسیارەکە داخرا. بۆ دووبارەکردنەوە /quiz بنێرە.")

def main() -> None:
    if not BOT_TOKEN:
        raise RuntimeError("TELEGRAM_BOT_TOKEN environment variable is missing.")
    app = Application.builder().token(BOT_TOKEN).build()
    app.add_handler(TypeHandler(Update, authorize_update), group=-1)
    app.add_handler(CommandHandler("id", user_id))
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("status", status))
    app.add_handler(CommandHandler("scope", scope))
    app.add_handler(CommandHandler("learn", learn))
    app.add_handler(CommandHandler("password", password))
    app.add_handler(CommandHandler("urlcheck", urlcheck))
    app.add_handler(CommandHandler("agent", agent))
    app.add_handler(CommandHandler("analyzelog", analyzelog))
    app.add_handler(CommandHandler("quiz", quiz))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, text_answer))
    logger.info("HANO Cyber Security Agent starting; authorized targets=%d", len(AUTHORIZED_TARGETS))
    app.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()
