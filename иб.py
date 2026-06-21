# бот для проверки ссылок
import time
import requests
import os
from dotenv import load_dotenv
from aiogram import Bot, Dispatcher
from aiogram.filters import Command
from aiogram.types import Message
import asyncio

# загружаем переменные из .env файла
load_dotenv()

# получаем токены из переменных окружения
BOT_TOKEN = os.getenv("BOT_TOKEN")
VT_KEY = os.getenv("VT_KEY")

# создаем бот
bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()

cache = {}

# свой алгоритм
def proverka_url(url):
    url = url.lower()
    problem = []

    bad_domains = [".xyz", ".top", ".tk", ".ml", ".ga", ".cf"]
    for d in bad_domains:
        if d in url:
            problem.append(f"хмм.. странный домен {d}")

    if len(url) > 100:
        problem.append("подозрительно длинный url..")

    if "faceb00k" in url or "g00gle" in url:
        problem.append("похоже на подделку известного сайта..")

    return problem

# проверка через virustotal
def check_vt(url):
    if not VT_KEY:
        return {"error": "нет ключа"}

    headers = {"x-apikey": VT_KEY}
    vt_url = "https://www.virustotal.com/api/v3/urls"
    data = {"url": url}

    try:
        resp = requests.post(vt_url, headers=headers, data=data)
        if resp.status_code == 200:
            analiz_id = resp.json()['data']['id']
            time.sleep(2)
            result_url = f"https://www.virustotal.com/api/v3/analyses/{analiz_id}"
            result = requests.get(result_url, headers=headers)
            if result.status_code == 200:
                stats = result.json()['data']['attributes']['stats']
                return {
                    "vt_ok": True,
                    "opasno": stats.get('malicious', 0),
                    "podozritelno": stats.get('suspicious', 0),
                    "bezopasno": stats.get('harmless', 0)
                }
    except:
        return {"error": "ошибка запроса"}

    return {"error": "не удалось проверить"}


# команда старт
@dp.message(Command("start"))
async def start_cmd(message: Message):
    text = """
привет! это бот для проверки ссылок.
просто скинь ссылку или напиши /check ссылка

команды:
/start - начало
/check ссылка - проверить ссылку
/help - помощь
"""
    await message.answer(text)


# команда помощь
async def help_cmd(message: Message):
    text = """
просто скинь ссылку или напиши /check ссылка

команды:

/start - начало
/check ссылка - проверить ссылку
/help - помощь

советы:
1. не переходи по ссылкам от незнакомцев
2. проверяй домен сайта

3. если сомневаешься - не нажимай
"""
    await message.answer(text)


# команда проверки
@dp.message(Command("check"))
async def check_cmd(message: Message):
    parts = message.text.split()
    if len(parts) < 2:
        await message.answer("укажи ссылку: /check https://пример.ru")
        return
    url = parts[1]
    await proverka(message, url)


# обработка любой ссылки в тексте
@dp.message()
async def any_message(message: Message):
    text = message.text
    if "http://" in text or "https://" in text:
        import re
        urls = re.findall(r'https?://\S+', text)
        if urls:
            url = urls[0]
            await message.answer(f"нашел ссылку: {url}\nпроверяю...")
            await proverka(message, url)
    else:
        await message.answer("скинь ссылку для проверки или напиши /help")


# основная функция проверки
async def proverka(message: Message, url: str):
    await message.answer("проверяю...")
    heur = proverka_url(url)
    vt = check_vt(url)
    result = {"heur": heur, "vt": vt}
    cache[url] = result
    if len(cache) > 50:
        first = list(cache.keys())[0]
        del cache[first]

    otvet = "проверка завершена "

    if result["heur"]:
        otvet += "проблемы:\n"
        for p in result["heur"]:
            otvet += f"• {p}\n"

    if "error" in result["vt"]:
        otvet += f"\nvirustotal: {result['vt']['error']}"
    elif result["vt"].get("vt_ok"):
        v = result["vt"]
        if v['opasno'] > 2:
            otvet += "\nне переходи!"
        elif v['opasno'] > 0 or v['podozritelno'] > 3:
            otvet += "\nбудь осторожен!"
        else:
            otvet += "\nвсе хорошо! выглядит безопасно!"

    otvet += "\nсовет: всегда проверяй ссылки))"
    await message.answer(otvet)


# в консоли
print("бот для проверки ссылок")
print(f"токен бота: {'есть' if BOT_TOKEN else 'нет'}")
print(f"ключ virustotal: {'есть' if VT_KEY else 'нет'}")

loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)

print("\nподготовка бота...")
try:
    loop.run_until_complete(bot.delete_webhook(drop_pending_updates=True))
    print("очистка завершена")
except:
    print("не удалось очистить старые сообщения")

print("\nбот запущен!")
print("для остановки нажмите ctrl+c")

try:
    loop.run_until_complete(dp.start_polling(bot))
except KeyboardInterrupt:
    print("\nполучена команда остановки")
except Exception as e:
    print(f"\nошибка: {e}")
finally:
    if not loop.is_closed():
        loop.close()
    print("бот остановлен")
