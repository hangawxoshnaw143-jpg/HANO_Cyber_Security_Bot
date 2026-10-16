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
from telegram.ext import Application, CommandHandler, ContextTypes

BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
logging.basicConfig(
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
)
logger = logging.getLogger("hano-cyber-bot")

KURDISH_HELP = """🛡️ HANO Cyber Security Bot

فەرمانەکان:
/start — دەستپێکردن
/help — لیستی فەرمانەکان
/learn — وانەیەکی کورت لە سایبێر سیکیوریتی
/urlcheck example.com — پشکنینی سەرەتایی HTTPS و هێدەرەکانی وێب
/password — دروستکردنی وشەی نهێنی بەهێز
/quiz — پرسیارێکی فێرکاری

⚠️ /urlcheck تەنها زانیارییە سەرەتاییەکانی پاراستنی وێب پشکنین دەکات؛ تاقیکردنەوەی هاکینگ یان دۆزینەوەی هەموو لاوازییەکان ناکات.
تەنها سیستەمێک پشکنین بکە کە خاوەندارێتی یان مۆڵەتی پشکنینت هەیە.
"""

LESSON = """📘 وانەی ١: پاراستنی هەژمار

• وشەی نهێنی بێ هاوشێوە و درێژ بەکاربهێنە.
• بۆ هەر خزمەتگوزارییەک وشەی نهێنیی جیاواز بەکاربهێنە.
• پشتڕاستکردنەوەی دوو هەنگاوی (2FA) چالاک بکە.
• کۆدی پشتڕاستکردنەوە و Token بە کەس مەدە.
• لە لینک و فایلە نەناسراوەکان ئاگاداربە.

داهاتوو: بنەماکانی HTTPS و هێدەرەکانی پاراستنی وێب.
"""

SECURITY_HEADERS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "Content-Security-Policy",
    "x-content-type-options": "X-Content-Type-Options",
    "x-frame-options": "X-Frame-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
}


def _public_http_url(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        raise ValueError("تکایە دۆمەین یان URL بنووسە.")
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("تەنها URL ـی http:// یان https:// ڕێگەپێدراوە.")
    if not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("URL ـەکە دروست نییە.")
    if parsed.port and not (1 <= parsed.port <= 65535):
        raise ValueError("ژمارەی پۆرت دروست نییە.")
    host = parsed.hostname.rstrip(".").lower()
    if host == "localhost" or host.endswith(".localhost") or host.endswith(".local"):
        raise ValueError("ناونیشانی ناوخۆیی ڕێگەپێدراو نییە.")
    try:
        ip = ipaddress.ip_address(host)
        if not ip.is_global:
            raise ValueError("IP ـی تایبەت/ناوخۆیی ڕێگەپێدراو نییە.")
    except ValueError as exc:
        if str(exc).startswith("IP"):
            raise
        # Non-IP hostnames are resolved below.
        try:
            infos = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)
        except socket.gaierror:
            raise ValueError("دۆمەین نەدۆزرایەوە.")
        if not infos:
            raise ValueError("دۆمەین نەدۆزرایەوە.")
        for info in infos:
            address = ipaddress.ip_address(info[4][0])
            if not address.is_global:
                raise ValueError("دۆمەین بۆ IP ـی ناوخۆیی/تایبەت دەچێت و ڕێگەپێدراو نییە.")
    return raw


def inspect_url(raw: str) -> str:
    url = _public_http_url(raw)
    try:
        response = requests.get(
            url,
            timeout=(4, 8),
            allow_redirects=False,
            stream=True,
            headers={"User-Agent": "HANO-CyberSecurityBot/1.0 (basic defensive header check)"},
        )
    except requests.exceptions.SSLError:
        return "❌ پەیوەندی TLS/SSL سەرکەوتوو نەبوو. پێویستە گۆڕانکارییەکانی سێرڤەر بپشکنرێن."
    except requests.exceptions.Timeout:
        return "⏳ وەڵامی وێبسایت لە کاتی دیاریکراودا نەهات."
    except requests.RequestException:
        return "❌ نەمتوانی بە وێبسایتەکە بگەم. URL و پەیوەندییەکە بپشکنە."

    try:
        status = response.status_code
        headers = {k.lower(): v for k, v in response.headers.items()}
        is_https = urlparse(url).scheme == "https"
        lines = [
            "🔎 ئەنجامی پشکنینی سەرەتایی",
            f"🌐 URL: {url}",
            f"📡 HTTP status: {status}",
            f"🔒 HTTPS: {'بەکارهاتووە' if is_https else 'نەخێر — HTTPS پێشنیار دەکرێت'}",
            "",
            "هێدەرەکانی پاراستن:",
        ]
        for key, label in SECURITY_HEADERS.items():
            present = key in headers
            # HSTS is meaningful only over HTTPS.
            if key == "strict-transport-security" and not is_https:
                lines.append(f"⚪ {label}: تەنها بۆ HTTPS هەڵسەنگێنرێت")
            else:
                lines.append(f"{'✅' if present else '⚠️'} {label}: {'هەیە' if present else 'نەبینرا'}")
        if status in (301, 302, 303, 307, 308):
            lines.extend(["", "↪️ وێبسایتەکە redirect دەکات؛ بۆ پاراستن، بۆت بەدوای redirect ـەکەدا ناچێت."])
        lines.extend([
            "",
            "⚠️ ئەمە تەنها پشکنینی هێدەرەکانە؛ دڵنیایی تەواوی ئاسایش نییە و هەموو لاوازییەکان نادۆزێتەوە.",
            "تەنها وێبسایتێک پشکنین بکە کە مۆڵەتی پشکنینت هەیە.",
        ])
        return "\n".join(lines)
    finally:
        response.close()


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.message:
        await update.message.reply_text(
            "سڵاو! 👋\nبەخێربێیت بۆ HANO Cyber Security Bot.\n"
            "ئامانجمان فێربوونی سایبێر سیکیوریتی بە شێوەیەکی ئەخلاقی و پارێزراوە.\n\n"
            + KURDISH_HELP
        )


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.message:
        await update.message.reply_text(KURDISH_HELP)


async def learn(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.message:
        await update.message.reply_text(LESSON)


async def password(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.message:
        return
    # Generate locally using Python's cryptographically secure secrets module.
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    value = "".join(secrets.choice(alphabet) for _ in range(20))
    await update.message.reply_text(
        "🔐 وشەی نهێنییەکی بەهێز (٢٠ پیت):\n"
        f"{value}\n\n"
        "لە هەژمارە جیاوازەکاندا دووبارە بەکاری مەهێنە و لە شوێنێکی پارێزراودا هەڵیبگرە."
    )


async def urlcheck(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.message:
        return
    if not context.args:
        await update.message.reply_text("بەکارهێنان: /urlcheck example.com\nتەنها دۆمەینی خۆت یان ئەوەی مۆڵەتی پشکنینت هەیە.")
        return
    await update.message.reply_text("⏳ پشکنینی سەرەتایی دەکەم...")
    try:
        result = await asyncio.to_thread(inspect_url, " ".join(context.args))
    except ValueError as exc:
        result = f"❌ {exc}"
    await update.message.reply_text(result, disable_web_page_preview=True)


async def quiz(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.message:
        context.user_data["quiz_active"] = True
        await update.message.reply_text(
            "🧠 پرسیاری فێرکاری\n\n"
            "کامەیان باشترین ڕێگای زیادکردنی پاراستنی هەژمارە؟\n"
            "A) بەکارهێنانی هەمان وشەی نهێنی بۆ هەموو شوێنێک\n"
            "B) وشەی نهێنیی جیاواز + 2FA\n"
            "C) ناردنی کۆدی پشتڕاستکردنەوە بۆ هاوڕێ\n\n"
            "وەڵامت بنووسە: A، B یان C."
        )


async def text_answer(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.message or not update.message.text:
        return
    if not context.user_data.get("quiz_active"):
        return
    answer = update.message.text.strip().upper()
    if answer in {"B", "٢", "2"}:
        context.user_data["quiz_active"] = False
        await update.message.reply_text("✅ ڕاستە! وشەی نهێنیی جیاواز و 2FA پاراستن زیاد دەکەن.")
    elif answer in {"A", "C", "١", "٣", "1", "3"}:
        context.user_data["quiz_active"] = False
        await update.message.reply_text("❌ ئەوە وەڵامی دروست نییە. وەڵامی دروست B ـە: وشەی نهێنیی جیاواز + 2FA.")
    else:
        await update.message.reply_text("تکایە تەنها A، B یان C بنووسە.")


def main() -> None:
    if not BOT_TOKEN:
        raise RuntimeError("TELEGRAM_BOT_TOKEN environment variable is missing.")
    app = Application.builder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("learn", learn))
    app.add_handler(CommandHandler("password", password))
    app.add_handler(CommandHandler("urlcheck", urlcheck))
    app.add_handler(CommandHandler("quiz", quiz))
    from telegram.ext import MessageHandler, filters
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, text_answer))
    logger.info("HANO Cyber Security Bot is starting.")
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
