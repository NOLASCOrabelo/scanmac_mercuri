import os
import telebot
from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton
import subprocess
import json
import nmap
import threading
import time
import re

# Configurações do ambiente
TOKEN = os.getenv('TELEGRAM_TOKEN')
CHAT_ID = os.getenv('CHAT_ID')
WHITELIST_FILE = "whitelist.json"

bot = telebot.TeleBot(TOKEN)
nm = nmap.PortScanner()

# --- Gestão da Whitelist ---

def carregar_whitelist():
    if not os.path.exists(WHITELIST_FILE):
        with open(WHITELIST_FILE, 'w') as f:
            json.dump([], f)
        return []
    with open(WHITELIST_FILE, 'r') as f:
        return json.load(f)

def salvar_na_whitelist(mac):
    whitelist = carregar_whitelist()
    if mac not in whitelist:
        whitelist.append(mac)
        with open(WHITELIST_FILE, 'w') as f:
            json.dump(whitelist, f)
        return True
    return False

# --- Lógica de Segurança ---

def eh_mac_aleatorio(mac):
    # O segundo caractere define se é Locally Administered (2, 6, A, E)
    return mac[1].upper() in ['2', '6', 'A', 'E']

def gerar_botoes(ip, mac):
    markup = InlineKeyboardMarkup()
    btn_inv = InlineKeyboardButton("🔍 Investigar Vulns", callback_data=f"investigar|{ip}")
    btn_white = InlineKeyboardButton("✅ Confiar", callback_data=f"whitelist|{mac}")
    markup.add(btn_inv, btn_white)
    return markup

def investigar_vulnerabilidades(ip):
    print(f"Iniciando scan de vulnerabilidades em {ip}")
    # Scan de serviços + scripts de vuln
    nm.scan(ip, arguments='-sV --script vuln --open')
    
    if ip not in nm.all_hosts():
        return "⚠️ Dispositivo não respondeu ao scan de portas."
    
    relatorio = f"🛡️ *Relatório de Segurança:* `{ip}`\n"
    for proto in nm[ip].all_protocols():
        for port in nm[ip][proto]:
            info = nm[ip][proto][port]
            relatorio += f"\n🚪 *{port}/{proto}:* {info['name']} ({info['state']})"
            if 'script' in info:
                for s_name, _ in info['script'].items():
                    relatorio += f"\n   🛑 *VULN:* `{s_name}`"
    return relatorio

# --- Handlers do Telegram ---

@bot.callback_query_handler(func=lambda call: True)
def callback_handler(call):
    data = call.data.split("|")
    acao, valor = data[0], data[1]
    
    if acao == "investigar":
        bot.answer_callback_query(call.id, "Escaneando... aguarde.")
        relatorio = investigar_vulnerabilidades(valor)
        bot.send_message(CHAT_ID, relatorio, parse_mode="Markdown")
        
    elif acao == "whitelist":
        salvar_na_whitelist(valor)
        bot.answer_callback_query(call.id, "Adicionado!")
        bot.edit_message_text(f"✅ Dispositivo `{valor}` agora é confiável.", 
                             call.message.chat.id, call.message.message_id)

# --- Loop de Monitoramento ---

def loop_scanner():
    while True:
        print("Buscando novos dispositivos...")
        # Executa arp-scan e captura a saída
        iface = os.getenv('NETWORK_INTERFACE', 'eth0')
        cmd = f"arp-scan -I {iface} --localnet"
        resultado = subprocess.getoutput(cmd)
        
        whitelist = carregar_whitelist()
        
        # Regex para capturar IP e MAC da saída do arp-scan
        # Exemplo: 192.168.1.4  6a:8b:13:f1:34:5b
        dispositivos = re.findall(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:]{17})', resultado)

        for ip, mac in dispositivos:
            if mac not in whitelist:
                # Tenta pegar hostname via mDNS (Avahi)
                host = subprocess.getoutput(f"avahi-resolve --address {ip}").split('\t')[-1] or "Desconhecido"
                tipo_mac = "🎲 Aleatório" if eh_mac_aleatorio(mac) else "🏢 Fábrica"
                
                texto = (
                    f"⚠️ *Novo Dispositivo Detectado!*\n\n"
                    f"🌐 *IP:* `{ip}`\n"
                    f"🆔 *MAC:* `{mac}`\n"
                    f"🏷️ *Tipo:* {tipo_mac}\n"
                    f"👤 *Host:* `{host}`"
                )
                
                bot.send_message(CHAT_ID, texto, parse_mode="Markdown", 
                                 reply_markup=gerar_botoes(ip, mac))
                
                # Para não inundar o Telegram, adicionamos temporariamente à lista da sessão
                whitelist.append(mac)

        time.sleep(60) # Verifica a cada 1 minuto

# --- Start ---

if __name__ == "__main__":
    # Garante que o arquivo de whitelist existe
    carregar_whitelist()
    
    # Thread para o Scanner
    threading.Thread(target=loop_scanner, daemon=True).start()
    
    print("Bot NetGuard Online...")
    bot.polling(none_stop=True)