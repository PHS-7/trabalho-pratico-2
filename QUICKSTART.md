# 🚀 Guia de Início Rápido

## Setup Rápido (3 comandos)

```bash
# 1. Instalar dependências
pip3 install -r requirements.txt

# 2. Gerar certificado
python3 generate_cert.py

# 3. Testar sistema
python3 test_system.py
```

---

## Uso Básico

### Iniciar Servidor

```bash
python3 server.py
```

Saída esperada:

```
======================================================================
🔐 SERVIDOR DE MENSAGERIA SEGURA MULTI-CLIENTE
======================================================================
✓ Chaves RSA carregadas de 'server.key' e 'server.crt'

🚀 Servidor iniciado em ('0.0.0.0', 8888)
   Aguardando conexões...
```

### Conectar Cliente

```bash
# Terminal 2
python3 client.py Alice

# Terminal 3
python3 client.py Bob

# Terminal 4
python3 client.py Charlie
```

### Enviar Mensagens

No terminal de Alice:

```
Para:Bob Olá Bob, como vai?
Para:Charlie Hey Charlie!
```

No terminal de Bob:

```
Para:Alice Oi Alice! Tudo bem, e você?
Para:Charlie Oi Charlie!
```

---

## Scripts Auxiliares

### Setup Automatizado

```bash
./setup.sh
```

- Instala dependências
- Gera certificado
- Testa sistema

### Demo com Múltiplos Terminais

```bash
./demo.sh
```

- Abre 4 terminais automaticamente
- 1 servidor + 3 clientes

---

## Exemplos de Uso

### Cenário 1: Conversa entre 2 clientes

**Alice** → Bob:

```
Para:Bob Olá, você recebeu os documentos?
```

**Bob** → Alice:

```
Para:Alice Sim, acabei de revisar. Tudo perfeito!
```

### Cenário 2: Broadcast para múltiplos clientes

**Alice** envia para vários destinatários:

```
Para:Bob Reunião às 15h
Para:Charlie Reunião às 15h
Para:Dave Reunião às 15h
```

### Cenário 3: Teste de confidencialidade

1. Alice, Bob e Charlie conectados
2. Alice envia: `Para:Bob Mensagem secreta`
3. Resultado:
   - ✅ Bob recebe e exibe
   - ❌ Charlie NÃO recebe (não é destinatário)
   - ❌ Servidor NÃO consegue ler (cifrado)

---

## Comandos de Debug

### Ver logs detalhados do servidor

O servidor já exibe logs automaticamente:

- `[HANDSHAKE]` - Processo de autenticação
- `📨` - Mensagens sendo roteadas
- `✓` - Operações bem-sucedidas
- `⚠️` - Avisos (cliente offline, etc.)
- `❌` - Erros

### Testar proteções de segurança

**1. Replay Attack:**

- Servidor detecta automaticamente
- Mensagens com `seq_no` antigo são rejeitadas

**2. Man-in-the-Middle:**

- Modificar `server.crt` e tentar conectar
- Cliente rejeitará: "Certificado não corresponde"

**3. Tampering:**

- Servidor valida tag GCM automaticamente
- Mensagens modificadas são descartadas

---

## Solução de Problemas

### Erro: "Connection refused"

**Causa**: Servidor não está rodando  
**Solução**: Execute `python3 server.py` primeiro

### Erro: "Certificate not found"

**Causa**: Certificado não foi gerado  
**Solução**: Execute `python3 generate_cert.py`

### Erro: "Module not found"

**Causa**: Dependências não instaladas  
**Solução**: Execute `pip3 install -r requirements.txt`

### Erro: "Port already in use"

**Causa**: Servidor já está rodando ou porta 8888 ocupada  
**Solução**:

```bash
# Linux/Mac
lsof -i :8888
kill <PID>

# Ou altere a porta em server.py (linha 23):
SERVER_PORT = 9999
```

### Cliente não recebe mensagens

**Causa**: Formato de mensagem incorreto  
**Solução**: Use `Para:Destinatário Mensagem` (com maiúsculo em "Para")

---

## Testes Automatizados

### Teste completo do sistema

```bash
python3 test_system.py
```

Verifica:

- ✅ Python 3.8+
- ✅ Dependências instaladas
- ✅ Certificados gerados
- ✅ ECDHE funcional
- ✅ HKDF funcional
- ✅ AES-GCM funcional

### Teste do módulo de criptografia

```bash
python3 crypto_utils.py
```

Saída esperada:

```
=== Teste do Módulo crypto_utils ===

1. Testando ECDHE...
   Segredos iguais: True ✓

2. Testando HKDF...
   Chaves diferentes: True ✓

3. Testando AES-128-GCM...
   Sucesso: True ✓

4. Testando proteção contra replay...
   seq_no 2 > 1: True ✓
   seq_no 1 > 2: False (replay detectado) ✓

=== Todos os testes passaram! ===
```

---

## Variáveis de Ambiente

### Alterar host/porta do servidor

```bash
# No arquivo server.py (linhas 22-23)
SERVER_HOST = "0.0.0.0"  # Alterar para IP específico
SERVER_PORT = 8888       # Alterar porta
```

### Conectar a servidor remoto

```bash
# No arquivo client.py (linhas 27-28)
SERVER_HOST = "192.168.1.100"  # IP do servidor
SERVER_PORT = 8888
```