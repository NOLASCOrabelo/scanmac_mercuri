#!/bin/bash

REDE="192.168.1.1/24"
WHITELIST="/home/mercurix/CyberSecurity/scanmac_mercuri/whitelist1.txt"
TOKEN="8683663523:AAFAY4TH8bAsugCAtwVTDeyr8osRGJm0V4E"
CHAT_ID="6317626166"

nmap -sn $REDE | awk '/Nmap scan report for/{ip=$NF; gsub(/[()]/,"",ip)} /MAC Address:/{print ip, $3}' > /tmp/hosts_ativos.txt

while read -r IP MAC; do
    if [ -z "$MAC" ]; then continue; fi

    if ! grep -qi "$MAC" "$WHITELIST"; then
        echo "Intruso detectado: IP $IP | MAC $MAC. Iniciando perfilamento..."

        PERFIL=$(nmap -F -sV -T4 -Pn "$IP" | grep -E "^[0-9]|Service Info|MAC Address")

        curl -s -X POST "https://api.telegram.org/bot$TOKEN/sendMessage" \
        -d chat_id="$CHAT_ID" \
        -d parse_mode="Markdown" \
        --data-urlencode "text=*ALERTA DE SEGURANÇA - REDE*
*Dispositivo desconhecido conectado!*
*MAC Address:* $MAC
*Serviços identificados:*
\`\`\`text
$PERFIL
\`\`\`" > /dev/null
        echo ""
    fi
done < /tmp/hosts_ativos.txt

rm -f /tmp/hosts_ativos.txt
