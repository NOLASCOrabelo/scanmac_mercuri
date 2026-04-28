import os
import telebot
from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton
import nmap
from dotenv import load_dotenv

load_dotenv()

# Configurações iniciais
TOKEN = os.getenv("TOKEN")
CHAT_ID = int(os.getenv("CHAT_ID"))
bot = telebot.TeleBot(TOKEN)
nm = nmap.PortScanner()
def gerar_botoes(ip, mac):
    markup = InlineKeyboardMarkup()
    # Callback data armazena o que o bot deve fazer e os dados do alvo
    btn_investigar = InlineKeyboardButton("🔍 Investigar (Nmap)", callback_data=f"scan_{ip}")
    btn_whitelist = InlineKeyboardButton("✅ Adicionar à Whitelist", callback_data=f"white_{mac}")
    markup.add(btn_investigar, btn_whitelist)
    return markup

@bot.callback_query_handler(func=lambda call: True)
def handle_query(call):
    if call.data.startswith("scan_"):
        ip = call.data.split("_")[1]
        bot.answer_callback_query(call.id, "Iniciando scan completo... Isso pode levar um tempo.")
        # Executa o scan agressivo
        res = nm.scan(ip, arguments='-A')
        bot.send_message(call.message.chat.id, f"📌 Resultado para {ip}:\n{res}")

    elif call.data.startswith("white_"):
        mac = call.data.split("_")[1]
        # Lógica para salvar no seu whitelist.json
        salvar_na_whitelist(mac)
        bot.edit_message_text(f"✅ MAC {mac} adicionado com sucesso!", 
                             call.message.chat.id, call.message.message_id)

# Função de exemplo para enviar o alerta
# bot.send_message(CHAT_ID, "⚠️ Novo dispositivo detectado!", reply_markup=gerar_botoes("192.168.1.4", "6A:8B:13..."))

bot.polling()