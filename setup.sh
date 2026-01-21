#!/bin/bash

# Script de setup completo do projeto

echo "=================================="
echo "🔐 Setup - Mensageria Segura"
echo "=================================="
echo ""

# 1. Verifica Python
echo "[1/4] Verificando Python..."
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 não encontrado. Por favor, instale Python 3.8 ou superior."
    exit 1
fi
PYTHON_VERSION=$(python3 --version)
echo "✓ $PYTHON_VERSION encontrado"
echo ""

# 2. Instala dependências
echo "[2/4] Instalando dependências Python..."
pip3 install -r requirements.txt
if [ $? -ne 0 ]; then
    echo "❌ Erro ao instalar dependências"
    exit 1
fi
echo "✓ Dependências instaladas"
echo ""

# 3. Gera certificado RSA
echo "[3/4] Gerando certificado RSA..."
python3 generate_cert.py <<EOF
s
EOF
if [ $? -ne 0 ]; then
    echo "❌ Erro ao gerar certificado"
    exit 1
fi
echo ""

# 4. Testa módulo de criptografia
echo "[4/4] Testando módulo de criptografia..."
python3 crypto_utils.py
if [ $? -ne 0 ]; then
    echo "❌ Erro nos testes de criptografia"
    exit 1
fi
echo ""

echo "=================================="
echo "✅ Setup concluído com sucesso!"
echo "=================================="
echo ""
echo "Para iniciar o sistema:"
echo ""
echo "1. Terminal 1 (Servidor):"
echo "   python3 server.py"
echo ""
echo "2. Terminal 2 (Cliente Alice):"
echo "   python3 client.py Alice"
echo ""
echo "3. Terminal 3 (Cliente Bob):"
echo "   python3 client.py Bob"
echo ""
echo "4. Enviar mensagem:"
echo "   Para:Bob Olá Bob, tudo bem?"
echo ""
