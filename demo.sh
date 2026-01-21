#!/bin/bash

# Script de demonstração - inicia servidor e 3 clientes em terminais separados

echo "🚀 Iniciando demonstração do sistema de mensageria segura..."
echo ""
echo "Abrindo terminais:"
echo "  - Terminal 1: Servidor"
echo "  - Terminal 2: Cliente Alice"
echo "  - Terminal 3: Cliente Bob"
echo "  - Terminal 4: Cliente Charlie"
echo ""

# Detecta o terminal disponível
if command -v gnome-terminal &> /dev/null; then
    TERM_CMD="gnome-terminal"
elif command -v xterm &> /dev/null; then
    TERM_CMD="xterm -e"
elif command -v konsole &> /dev/null; then
    TERM_CMD="konsole -e"
else
    echo "⚠️  Nenhum terminal gráfico detectado."
    echo "Por favor, abra manualmente os terminais e execute:"
    echo ""
    echo "Terminal 1: python3 server.py"
    echo "Terminal 2: python3 client.py Alice"
    echo "Terminal 3: python3 client.py Bob"
    echo "Terminal 4: python3 client.py Charlie"
    exit 1
fi

# Inicia servidor
$TERM_CMD -- bash -c "python3 server.py; exec bash" &
sleep 2

# Inicia clientes
$TERM_CMD -- bash -c "python3 client.py Alice; exec bash" &
sleep 1
$TERM_CMD -- bash -c "python3 client.py Bob; exec bash" &
sleep 1
$TERM_CMD -- bash -c "python3 client.py Charlie; exec bash" &

echo "✅ Terminais abertos!"
echo ""
echo "Para enviar mensagens, use o formato:"
echo "  Para:Destinatário Mensagem aqui"
echo ""
echo "Exemplos:"
echo "  Para:Bob Olá Bob!"
echo "  Para:Alice Oi Alice, tudo bem?"
echo "  Para:Charlie Hey Charlie!"
echo ""
