import os
import subprocess
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
def eh_mac_aleatorio(mac):
    # O segundo caractere do MAC define se ele é local/aleatório
    # Se for 2, 6, A ou E, o bit U/L está ativo.
    segundo_char = mac[1].upper()
    return segundo_char in ['2', '6', 'A', 'E']

def investigar_dispositivo(ip):
    nm = nmap.PortScanner()
    # Tentamos resolver o Hostname via rede local (mDNS)
    try:
        hostname = subprocess.getoutput(f"avahi-resolve --address {ip}").split('\t')[-1]
    except:
        hostname = "Desconhecido"

    # Executa Scan de Versão + Scripts de Vulnerabilidade
    print(f"Iniciando scan de vulnerabilidades em {ip}...")
    nm.scan(ip, arguments='-sV --script vuln --open')

    resultado = f"📌 Relatório de Recon: {hostname} ({ip})\n"
    for proto in nm[ip].all_protocols():
        lport = nm[ip][proto].keys()
        for port in lport:
            state = nm[ip][proto][port]['state']
            service = nm[ip][proto][port]['name']
            resultado += f"Porta {port}/{proto}: {service} ({state})\n"
            # Se o Nmap encontrar scripts de vulnerabilidade
            if 'script' in nm[ip][proto][port]:
                for script_name, output in nm[ip][proto][port]['script'].items():
                    resultado += f"   🛑 VULN: {script_name}\n"
    return resultado

def alertar_novo_dispositivo(ip, mac):
    status_mac = "🎲 Aleatório" if eh_mac_aleatorio(mac) else "🏢 Fábrica"
    nome_dispositivo = subprocess.getoutput(f"avahi-resolve --address {ip}").split('\t')[-1] or "Desconhecido"
    texto = (
        f"🚨 *Novo Dispositivo Detectado!*\n\n"
        f"🌐 *IP:* `{ip}`\n"
        f"🆔 *MAC:* `{mac}` ({status_mac})\n"
        f"🏷️ *Hostname:* {nome_dispositivo}\n"
    )
    bot.send_message(CHAT_ID, texto, parse_mode="Markdown", reply_markup=gerar_botoes(ip, mac))

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
        resultado = investigar_dispositivo(ip)
        bot.send_message(call.message.chat.id, resultado)

    elif call.data.startswith("white_"):
        mac = call.data.split("_")[1]
        # Lógica para salvar no seu whitelist.json
        salvar_na_whitelist(mac)
        bot.edit_message_text(f"✅ MAC {mac} adicionado com sucesso!", 
                             call.message.chat.id, call.message.message_id)

# Função de exemplo para enviar o alerta
# bot.send_message(CHAT_ID, "⚠️ Novo dispositivo detectado!", reply_markup=gerar_botoes("192.168.1.4", "6A:8B:13..."))

bot.polling()