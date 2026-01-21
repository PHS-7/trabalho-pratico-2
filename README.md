# Sistema de Mensageria Segura Multi-Cliente

🔐 Aplicação de mensageria segura com criptografia end-to-end, sigilo perfeito e autenticação de servidor.

## 👥 Equipe

- [Italo Kauan Vitor Fernandes]
- [Pedro Henrique Santos Moreira]
- [Vitor Loula Silva]

## 🎯 Características de Segurança

- **Confidencialidade**: AES-128-GCM (AEAD)
- **Integridade**: Tag de autenticação GCM
- **Autenticidade**: Certificado RSA autoassinado
- **Sigilo Perfeito**: ECDHE (Elliptic Curve Diffie-Hellman Ephemeral)
- **Anti-Replay**: Números de sequência monotônicos

## 📋 Requisitos

- Python 3.8 ou superior
- Bibliotecas: cryptography

## 🚀 Instalação

```bash
# Instalar dependências
pip install -r requirements.txt

# Gerar certificado do servidor (executar apenas uma vez)
python generate_cert.py
```

## 🔧 Como Usar

### 1. Iniciar o Servidor

```bash
python server.py
```

O servidor iniciará na porta 8888 e aguardará conexões de clientes.

### 2. Conectar Clientes

Em terminais diferentes, execute:

```bash
# Cliente 1
python client.py Alice

# Cliente 2
python client.py Bob

# Cliente 3
python client.py Charlie
```

### 3. Enviar Mensagens

No cliente, digite:

```
Para:Destinatário Mensagem aqui
```

Exemplos:

```
Para:Bob Olá Bob, tudo bem?
Para:Alice Oi Alice!
```

Para sair, digite `sair` ou pressione Ctrl+C.

## 🔄 Fluxo do Protocolo

### 1. Handshake (Troca de Chaves)

1. Cliente envia `client_id` + `pk_C` (chave pública ECDHE)
2. Servidor responde com:
   - `pk_S` (chave pública ECDHE do servidor)
   - `server.crt` (certificado RSA)
   - Assinatura RSA de `pk_S || client_id || transcript || salt`
   - `salt` para HKDF
3. Cliente valida assinatura usando certificado
4. Ambos calculam segredo compartilhado: `Z = ECDH(sk_local, pk_peer)`
5. Derivação de chaves via HKDF (TLS 1.3):

   ```
   PRK = HKDF-Extract(salt, Z)
   Key_c2s = HKDF-Expand(PRK, "c2s", 16)
   Key_s2c = HKDF-Expand(PRK, "s2c", 16)
   ```

### 2. Troca de Mensagens

Formato do pacote:

```
[nonce (12B)] + [sender_id (16B)] + [recipient_id (16B)] + [seq_no (8B)] + [ciphertext+tag]
```

- **AAD** (Associated Data): `sender_id || recipient_id || seq_no`
- **Cifra**: AES-128-GCM
- **Proteções**: Tag GCM + validação de seq_no

Fluxo:

1. Cliente A cifra mensagem com `Key_c2s_A` → Servidor
2. Servidor decifra com `Key_c2s_A`, valida tag e seq_no
3. Servidor re-cifra com `Key_s2c_B` → Cliente B
4. Cliente B decifra com `Key_s2c_B`, valida e exibe

### 3. Proteções Implementadas

- **Replay Attack**: Cada mensagem tem seq_no único e monotônico
- **Man-in-the-Middle**: Assinatura RSA garante autenticidade do servidor
- **Forward Secrecy**: Chaves efêmeras ECDHE (não reutilizadas)
- **Tampering**: Tag GCM detecta qualquer modificação

## 📂 Estrutura do Projeto

```
trabalho-pratico-2/
│
├── 📄 Documentação
│   ├── README.md              # Este arquivo (visão geral)
│   ├── QUICKSTART.md          # Guia de início rápido
│   ├── SEGURANCA.md           # Análise detalhada de segurança
│
├── 🐍 Código Python
│   ├── crypto_utils.py        # Funções criptográficas (ECDHE, HKDF, AES-GCM)
│   ├── server.py              # Servidor multi-cliente assíncrono
│   ├── client.py              # Cliente com interface CLI
│   ├── generate_cert.py       # Gerador de certificado RSA
│   └── test_system.py         # Testes automatizados
│
├── 🔧 Scripts Auxiliares
│   ├── setup.sh               # Setup automatizado (deps + cert + testes)
│   └── demo.sh                # Demo com múltiplos terminais
│
├── ⚙️ Configuração
│   ├── requirements.txt       # Dependências Python
│   └── .gitignore            # Arquivos ignorados pelo Git
│
└── 🔐 Certificados (gerados após setup)
    ├── server.key             # Chave privada RSA (2048 bits)
    └── server.crt             # Certificado autoassinado X.509
```

## 🔐 Detalhes de Implementação

### Criptografia

- **ECDHE**: Curva `SECP256R1` (P-256)
- **RSA**: 2048 bits para assinatura
- **AES-GCM**: 128 bits (chave) + 96 bits (nonce) + 128 bits (tag)
- **HKDF**: SHA-256 como função hash

### Sessões no Servidor

```python
sessions = {
   client_id: {
      "writer": StreamWriter,
      "key_c2s": bytes(16),     # Cliente → Servidor
      "key_s2c": bytes(16),     # Servidor → Cliente
      "seq_recv": int,          # Último seq recebido
      "seq_send": int,          # Próximo seq a enviar
      "salt": bytes(32)         # Salt do HKDF
   }
}
```

## 📝 Licença

Este projeto é para fins acadêmicos.
