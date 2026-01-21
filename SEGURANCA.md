# Análise de Segurança do Sistema

## 📋 Visão Geral

Este documento detalha as propriedades de segurança implementadas no sistema de mensageria segura, explicando como cada requisito é atendido e quais ataques são mitigados.

---

## 🔐 Propriedades de Segurança Implementadas

### 1. Confidencialidade

**Objetivo**: As mensagens devem ser ilegíveis para terceiros (incluindo o servidor).

**Implementação**:

- **Cifra**: AES-128-GCM (Advanced Encryption Standard, modo Galois/Counter)
- **Tamanho da chave**: 128 bits (16 bytes)
- **Modo de operação**: AEAD (Authenticated Encryption with Associated Data)

**Como funciona**:

```
plaintext → AES-GCM(Key, Nonce, AAD) → ciphertext + tag
```

**Garantia**: Mesmo que um atacante intercepte todas as mensagens na rede, não conseguirá decifrá-las sem as chaves derivadas durante o handshake ECDHE.

---

### 2. Integridade

**Objetivo**: Detectar qualquer modificação não autorizada nas mensagens.

**Implementação**:

- **Tag de autenticação**: GCM gera uma tag de 128 bits (16 bytes)
- **AAD (Associated Authenticated Data)**: `sender_id || recipient_id || seq_no`

**Como funciona**:

```
tag = GHASH(Key, AAD || ciphertext || len(AAD) || len(ciphertext))
```

**Garantia**: Se um atacante modificar qualquer byte da mensagem (ciphertext, nonce, AAD), a validação da tag GCM falhará e a mensagem será rejeitada.

**Código relevante** (crypto_utils.py):

```python
# Validação automática ao decifrar
plaintext = aesgcm.decrypt(nonce, ciphertext_and_tag, aad)
# Se a tag não validar, uma exceção é lançada
```

---

### 3. Autenticidade

**Objetivo**: O cliente deve ter certeza de que está se comunicando com o servidor legítimo.

**Implementação**:

- **Certificado RSA**: Autoassinado X.509 (2048 bits)
- **Assinatura RSA**: Servidor assina `pk_S || client_id || transcript || salt`
- **Certificate Pinning**: Cliente valida que o certificado recebido é exatamente o esperado

**Como funciona**:

1. Servidor assina sua chave pública ECDHE com sua chave privada RSA
2. Cliente valida a assinatura usando o certificado pinado
3. Se a assinatura for inválida, o handshake é abortado

**Proteção contra**:

- **Man-in-the-Middle (MITM)**: Atacante não consegue se passar pelo servidor sem a chave privada RSA
- **Servidor falso**: Certificate pinning garante que apenas o servidor correto é aceito

**Código relevante** (client.py):

```python
# Certificate pinning
if cert_bytes != expected_cert_bytes:
    print("Possível ataque Man-in-the-Middle!")
    return False

# Validação de assinatura
public_key.verify(signature, message_to_verify, ...)
```

---

### 4. Sigilo Perfeito (Forward Secrecy)

**Objetivo**: Mesmo que a chave RSA seja comprometida no futuro, as sessões passadas permanecem seguras.

**Implementação**:

- **ECDHE**: Elliptic Curve Diffie-Hellman Ephemeral
- **Curva**: SECP256R1 (P-256, NIST)
- **Chaves efêmeras**: Novas chaves são geradas para cada sessão e descartadas após uso

**Como funciona**:

```
Cliente:  sk_C (privada), pk_C (pública)
Servidor: sk_S (privada), pk_S (pública)

Segredo compartilhado: Z = ECDH(sk_C, pk_S) = ECDH(sk_S, pk_C)
```

**Garantia**:

- As chaves efêmeras nunca são armazenadas permanentemente
- Se um atacante capturar todas as mensagens e, anos depois, comprometer a chave RSA do servidor, ainda assim não conseguirá decifrar as sessões passadas
- Cada sessão tem seu próprio par de chaves efêmeras

**Propriedade matemática**:

- `Z = sk_C × pk_S = sk_S × pk_C` (propriedade do ECDH)
- Problema do Logaritmo Discreto em Curvas Elípticas (ECDLP) torna computacionalmente inviável recuperar `Z` apenas conhecendo `pk_C` e `pk_S`

---

### 5. Derivação de Chaves (HKDF - TLS 1.3)

**Objetivo**: Derivar múltiplas chaves independentes a partir de um único segredo compartilhado.

**Implementação**:

- **Algoritmo**: HKDF (HMAC-based Key Derivation Function)
- **Hash**: SHA-256
- **Fases**: Extract + Expand

**Como funciona**:

```
PRK = HKDF-Extract(salt, shared_secret)
Key_c2s = HKDF-Expand(PRK, "c2s" || client_id || transcript, 16)
Key_s2c = HKDF-Expand(PRK, "s2c" || client_id || transcript, 16)
```

**Propriedades**:

- **Chaves direcionais**: Key_c2s ≠ Key_s2c (prevenção de reflection attacks)
- **Context binding**: `client_id` e `transcript` garantem que as chaves são únicas para cada sessão
- **Salt aleatório**: Adiciona entropia adicional

**Código relevante** (crypto_utils.py):

```python
hkdf_c2s = HKDF(
    algorithm=hashes.SHA256(),
    length=16,
    salt=salt,
    info=b"c2s" + client_id.encode() + transcript
)
key_c2s = hkdf_c2s.derive(shared_secret)
```

---

## 🛡️ Proteções Contra Ataques

### 1. Replay Attack

**Ataque**: Atacante captura uma mensagem válida e a reenvia posteriormente.

**Proteção**:

- **Números de sequência monotônicos**: Cada mensagem tem um `seq_no` único e crescente
- **Validação no servidor**: Rejeita mensagens com `seq_no ≤ último_recebido`

**Implementação**:

```python
def validate_sequence_number(seq_recv, seq_new):
    return seq_new > seq_recv

# No servidor
if not validate_sequence_number(session["seq_recv"], seq_no):
    print("REPLAY ATTACK detectado")
    return
```

**Limitação conhecida**:

- Se o servidor reiniciar, os `seq_no` resetam para 1
- Solução em produção: Persistir estado em banco de dados

---

### 2. Man-in-the-Middle (MITM)

**Ataque**: Atacante intercepta a comunicação e tenta se passar pelo servidor ou modificar mensagens.

**Proteção**:

1. **Certificate Pinning**: Cliente só aceita o certificado específico do servidor
2. **Assinatura RSA**: Servidor assina sua chave ECDHE, provando identidade
3. **Tag GCM**: Qualquer modificação de mensagem é detectada

**Fluxo de proteção**:

```
Cliente → [Atacante] → Servidor

1. Atacante intercepta pk_S e tenta enviar sua própria pk_fake
2. Atacante não consegue assinar pk_fake com a chave RSA do servidor
3. Cliente rejeita a assinatura inválida
4. Handshake falha, conexão é abortada
```

---

### 3. Tampering (Modificação de Mensagens)

**Ataque**: Atacante modifica bits de uma mensagem cifrada.

**Proteção**:

- **Tag GCM**: Vinculada criptograficamente ao ciphertext e AAD
- **Validação automática**: Qualquer modificação causa falha na decriptação

**Exemplo**:

```
Mensagem original:  [nonce][AAD][ciphertext][tag_válida]
Mensagem modificada:[nonce][AAD][ciphertext_alterado][tag_válida]

Resultado: aesgcm.decrypt() lança exceção, mensagem rejeitada
```

---

### 4. Eavesdropping (Espionagem)

**Ataque**: Atacante captura todo o tráfego de rede para análise posterior.

**Proteção**:

- **Criptografia forte**: AES-128-GCM com chaves de 128 bits
- **Segurança computacional**: Inviável quebrar por força bruta (2^128 tentativas)
- **Forward Secrecy**: Mesmo comprometendo a chave RSA, sessões passadas permanecem seguras

**Análise de força bruta**:

```
Chaves possíveis: 2^128 = 340,282,366,920,938,463,463,374,607,431,768,211,456
Assumindo 1 trilhão de tentativas/segundo: ~10^25 anos para quebrar
```

---

### 5. Impersonation (Personificação)

**Ataque**: Atacante tenta se passar por outro cliente.

**Proteção**:

- **AAD**: Inclui `sender_id` na autenticação GCM
- **Servidor valida**: Apenas aceita mensagens cifradas com a chave correta do remetente
- **Chaves únicas**: Cada cliente tem suas próprias Key_c2s e Key_s2c

**Como funciona**:

```
Alice (client_id=Alice, Key_c2s_Alice) tenta se passar por Bob:
1. Alice envia mensagem com sender_id="Bob"
2. Servidor decifra com Key_c2s_Alice (associada a Alice)
3. AAD contém "Bob", mas a mensagem foi cifrada por Alice
4. Servidor pode implementar validação adicional (não implementado nesta versão)
```

**Nota**: Na implementação atual, o servidor confia no `client_id` enviado no handshake. Em produção, adicionar autenticação adicional (usuário/senha, token JWT, etc.).

---

## 📊 Formato Detalhado das Mensagens

### Estrutura do Pacote

```
+--------+--------+--------+--------+--------+
| Nonce  |Sender  |Recip.  |Seq No  |Cipher  |
| 12B    |ID 16B  |ID 16B  |8B      |text+tag|
+--------+--------+--------+--------+--------+
    ↓        ↓        ↓        ↓        ↓
    |        |        |        |        |
    |        └────────┴────────┘        |
    |              AAD (40B)            |
    |                                   |
    └───────────────┬───────────────────┘
                    |
              AES-GCM Encrypt
```

### Campos

1. **Nonce (12 bytes)**:
   - Gerado aleatoriamente para cada mensagem
   - NUNCA deve ser reutilizado com a mesma chave
   - Garante que a mesma mensagem cifrada duas vezes resulta em ciphertexts diferentes

2. **Sender ID (16 bytes)**:
   - ID do remetente (com padding)
   - Parte do AAD (autenticado, mas não cifrado)

3. **Recipient ID (16 bytes)**:
   - ID do destinatário (com padding)
   - Parte do AAD

4. **Sequence Number (8 bytes)**:
   - Contador monotônico (big-endian)
   - Previne replay attacks
   - Parte do AAD

5. **Ciphertext + Tag (variável)**:
   - Ciphertext: mensagem cifrada (mesmo tamanho do plaintext)
   - Tag: 16 bytes de autenticação GCM

---

## 🔬 Análise de Segurança por Camada

### Camada 1: Transporte (TCP)

**Propriedades**:

- Confiabilidade: garante entrega ordenada de bytes
- **NÃO** fornece segurança: mensagens em claro

**Proteção adicionada**:

- Todas as mensagens são cifradas antes de serem enviadas
- Metadados mínimos expostos (apenas tamanho do pacote)

---

### Camada 2: Handshake (ECDHE + RSA)

**Propriedades**:

- Autenticação do servidor (via RSA)
- Acordo de chaves efêmeras (via ECDHE)
- Forward secrecy

**Ataques mitigados**:

- MITM: Assinatura RSA + certificate pinning
- Passive eavesdropping: ECDLP garante que Z não pode ser calculado

---

### Camada 3: Derivação de Chaves (HKDF)

**Propriedades**:

- Geração de chaves direcionais independentes
- Context binding

**Ataques mitigados**:

- Reflection attack: Key_c2s ≠ Key_s2c
- Session confusion: transcript vincula chaves à sessão específica

---

### Camada 4: Criptografia de Mensagens (AES-GCM)

**Propriedades**:

- Confidencialidade: AES-128
- Integridade + Autenticidade: tag GCM
- AEAD: cifra e autentica em uma única operação

**Ataques mitigados**:

- Eavesdropping: ciphertext é criptograficamente seguro
- Tampering: tag GCM detecta modificações
- Replay: seq_no validado

---

## 🎯 Conformidade com Requisitos

| Requisito | Implementação | Status |
|-----------|---------------|--------|
| Confidencialidade | AES-128-GCM | ✅ |
| Integridade | Tag GCM | ✅ |
| Autenticidade | Certificado RSA + Assinatura | ✅ |
| Sigilo Perfeito | ECDHE (P-256) | ✅ |
| Anti-replay | Seq_no monotônico | ✅ |
| Multi-cliente | Servidor assíncrono | ✅ |
| Chaves direcionais | HKDF com labels c2s/s2c | ✅ |

---

## 🔍 Considerações para Produção

### Melhorias Recomendadas

1. **Autenticação de clientes**:
   - Adicionar autenticação mútua (cliente também deve ser autenticado)
   - Implementar sistema de usuário/senha ou tokens JWT

2. **Persistência de estado**:
   - Armazenar `seq_no` em banco de dados
   - Prevenir reset de contadores após reinício do servidor

3. **Rotação de chaves**:
   - Implementar re-keying após N mensagens ou T minutos
   - Limitar lifetime das chaves de sessão

4. **Revogação de certificados**:
   - Implementar OCSP (Online Certificate Status Protocol)
   - Sistema de CRL (Certificate Revocation List)

5. **Rate limiting**:
   - Prevenir DoS attacks limitando mensagens por segundo
   - Implementar backoff exponencial

6. **Auditoria e logging**:
   - Log seguro de eventos (sem expor chaves ou mensagens)
   - Detecção de tentativas de ataque

7. **Certificados CA-signed**:
   - Substituir certificado autoassinado por um emitido por CA confiável
   - Remover necessidade de certificate pinning

8. **TLS como camada adicional**:
   - Adicionar TLS 1.3 para proteção de camada de transporte
   - Defesa em profundidade (defense in depth)

---

## 📚 Referências

- **AES-GCM**: NIST SP 800-38D
- **ECDHE**: NIST SP 800-56A Rev. 3
- **HKDF**: RFC 5869
- **RSA**: RFC 8017 (PKCS #1 v2.2)
- **TLS 1.3**: RFC 8446
- **Certificate Pinning**: OWASP Mobile Security Testing Guide

---

## ✅ Conclusão

O sistema implementado fornece um alto nível de segurança, atendendo a todos os requisitos especificados:

- **Confidencialidade** garantida por AES-128-GCM
- **Integridade** e **autenticidade** via tags GCM
- **Autenticação do servidor** via RSA e certificate pinning
- **Sigilo perfeito** através de ECDHE com chaves efêmeras
- **Proteção contra replay** via números de sequência

Para uso em produção, recomenda-se implementar as melhorias listadas, especialmente autenticação mútua e persistência de estado.
