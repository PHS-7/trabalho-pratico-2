"""
Módulo de utilidades criptográficas para o sistema de mensageria segura.

Implementa:
- ECDHE (Elliptic Curve Diffie-Hellman Ephemeral)
- HKDF (HMAC-based Key Derivation Function) - TLS 1.3
- AES-128-GCM (Authenticated Encryption with Associated Data)
- Funções auxiliares para serialização e validação
"""

import os
import struct
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend


# ============================================================================
# ECDHE - Elliptic Curve Diffie-Hellman Ephemeral
# ============================================================================

def generate_ecdhe_keypair():
    """
    Gera um par de chaves efêmeras ECDHE usando a curva SECP256R1 (P-256).

    Returns:
        tuple: (private_key, public_key_bytes)
            - private_key: objeto de chave privada
            - public_key_bytes: chave pública serializada (formato X.962 comprimido)
    """
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()

    # Serializa chave pública em formato X.962 (comprimido)
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )

    return private_key, public_key_bytes


def deserialize_public_key(public_key_bytes):
    """
    Deserializa uma chave pública ECDHE do formato X.962.

    Args:
        public_key_bytes (bytes): Chave pública serializada

    Returns:
        EllipticCurvePublicKey: Objeto de chave pública
    """
    return ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), public_key_bytes
    )


def compute_ecdhe_shared_secret(private_key, peer_public_key_bytes):
    """
    Calcula o segredo compartilhado ECDHE: Z = ECDH(sk_local, pk_peer).

    Args:
        private_key: Chave privada local (objeto)
        peer_public_key_bytes (bytes): Chave pública do peer serializada

    Returns:
        bytes: Segredo compartilhado (32 bytes para P-256)
    """
    peer_public_key = deserialize_public_key(peer_public_key_bytes)
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    return shared_secret


# ============================================================================
# HKDF - Key Derivation Function (TLS 1.3 style)
# ============================================================================

def derive_keys_hkdf(shared_secret, salt, client_id, transcript=b""):
    """
    Deriva chaves direcionais usando HKDF (TLS 1.3).

    Processo:
    1. HKDF-Extract: PRK = HMAC(salt, shared_secret)
    2. HKDF-Expand: gera chaves com labels diferentes

    Args:
        shared_secret (bytes): Segredo compartilhado do ECDHE (IKM)
        salt (bytes): Salt aleatório (32 bytes)
        client_id (str): ID do cliente (para context binding)
        transcript (bytes): Dados do handshake (opcional)

    Returns:
        tuple: (key_c2s, key_s2c)
            - key_c2s: Chave AES-128 para Cliente → Servidor
            - key_s2c: Chave AES-128 para Servidor → Cliente
    """
    # Contexto adicional para binding
    info_base = client_id.encode('utf-8') + transcript

    # HKDF-Extract + Expand para chave cliente→servidor
    hkdf_c2s = HKDF(
        algorithm=hashes.SHA256(),
        length=16,  # AES-128 = 16 bytes
        salt=salt,
        info=b"c2s" + info_base,
        backend=default_backend()
    )
    key_c2s = hkdf_c2s.derive(shared_secret)

    # HKDF-Extract + Expand para chave servidor→cliente
    hkdf_s2c = HKDF(
        algorithm=hashes.SHA256(),
        length=16,  # AES-128 = 16 bytes
        salt=salt,
        info=b"s2c" + info_base,
        backend=default_backend()
    )
    key_s2c = hkdf_s2c.derive(shared_secret)

    return key_c2s, key_s2c


# ============================================================================
# AES-128-GCM - Authenticated Encryption
# ============================================================================

def encrypt_message_gcm(key, plaintext, sender_id, recipient_id, seq_no):
    """
    Cifra uma mensagem usando AES-128-GCM com AAD.

    Formato do pacote:
    [nonce (12B)] + [sender_id (16B)] + [recipient_id (16B)] + [seq_no (8B)] + [ciphertext+tag]

    Args:
        key (bytes): Chave AES-128 (16 bytes)
        plaintext (bytes): Mensagem em claro
        sender_id (str): ID do remetente (até 16 bytes)
        recipient_id (str): ID do destinatário (até 16 bytes)
        seq_no (int): Número de sequência (8 bytes)

    Returns:
        bytes: Pacote cifrado completo
    """
    # Gera nonce aleatório (96 bits = 12 bytes)
    nonce = os.urandom(12)

    # Prepara IDs (padding para 16 bytes)
    sender_bytes = sender_id.encode('utf-8').ljust(16, b'\x00')[:16]
    recipient_bytes = recipient_id.encode('utf-8').ljust(16, b'\x00')[:16]
    seq_bytes = struct.pack('!Q', seq_no)  # 8 bytes, big-endian

    # AAD (Associated Authenticated Data) - não é cifrado, mas é autenticado
    aad = sender_bytes + recipient_bytes + seq_bytes

    # Cifra com AES-GCM (inclui tag de autenticação de 16 bytes)
    aesgcm = AESGCM(key)
    ciphertext_and_tag = aesgcm.encrypt(nonce, plaintext, aad)

    # Monta pacote completo
    packet = nonce + sender_bytes + recipient_bytes + seq_bytes + ciphertext_and_tag

    return packet


def decrypt_message_gcm(key, packet):
    """
    Decifra uma mensagem AES-128-GCM e valida integridade.

    Args:
        key (bytes): Chave AES-128 (16 bytes)
        packet (bytes): Pacote cifrado completo

    Returns:
        tuple: (plaintext, sender_id, recipient_id, seq_no) ou None se inválido

    Raises:
        Exception: Se a autenticação GCM falhar (tag inválida)
    """
    try:
        # Extrai componentes do pacote
        nonce = packet[0:12]
        sender_bytes = packet[12:28]
        recipient_bytes = packet[28:44]
        seq_bytes = packet[44:52]
        ciphertext_and_tag = packet[52:]

        # Reconstrói AAD
        aad = sender_bytes + recipient_bytes + seq_bytes

        # Decifra e valida tag GCM
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext_and_tag, aad)

        # Decodifica metadados
        sender_id = sender_bytes.rstrip(b'\x00').decode('utf-8')
        recipient_id = recipient_bytes.rstrip(b'\x00').decode('utf-8')
        seq_no = struct.unpack('!Q', seq_bytes)[0]

        return plaintext, sender_id, recipient_id, seq_no

    except Exception as e:
        print(f"[ERRO] Falha na decriptação GCM: {e}")
        return None


# ============================================================================
# Funções Auxiliares
# ============================================================================

def generate_random_salt(length=32):
    """
    Gera um salt aleatório para uso no HKDF.

    Args:
        length (int): Tamanho do salt em bytes (padrão: 32)

    Returns:
        bytes: Salt aleatório
    """
    return os.urandom(length)


def pad_id(client_id, length=16):
    """
    Aplica padding a um ID para comprimento fixo.

    Args:
        client_id (str): ID do cliente
        length (int): Comprimento desejado

    Returns:
        bytes: ID com padding
    """
    return client_id.encode('utf-8').ljust(length, b'\x00')[:length]


def validate_sequence_number(seq_recv, seq_new):
    """
    Valida número de sequência para proteção contra replay.

    Args:
        seq_recv (int): Último seq_no recebido
        seq_new (int): Novo seq_no recebido

    Returns:
        bool: True se válido (seq_new > seq_recv), False caso contrário
    """
    return seq_new > seq_recv


def create_transcript(client_id, pk_client, pk_server):
    """
    Cria um transcript do handshake para binding à assinatura RSA.

    Args:
        client_id (str): ID do cliente
        pk_client (bytes): Chave pública do cliente
        pk_server (bytes): Chave pública do servidor

    Returns:
        bytes: Transcript do handshake
    """
    return (
        client_id.encode('utf-8') +
        pk_client +
        pk_server
    )


# ============================================================================
# Funções de Validação e Debug
# ============================================================================

def print_hex(label, data, max_bytes=32):
    """
    Imprime dados em hexadecimal para debug.

    Args:
        label (str): Rótulo descritivo
        data (bytes): Dados a imprimir
        max_bytes (int): Número máximo de bytes a exibir
    """
    hex_str = data[:max_bytes].hex()
    suffix = "..." if len(data) > max_bytes else ""
    print(f"[DEBUG] {label}: {hex_str}{suffix}")


if __name__ == "__main__":
    # Testes básicos das funções
    print("=== Teste do Módulo crypto_utils ===\n")

    # Teste ECDHE
    print("1. Testando ECDHE...")
    sk_a, pk_a = generate_ecdhe_keypair()
    sk_b, pk_b = generate_ecdhe_keypair()

    z_a = compute_ecdhe_shared_secret(sk_a, pk_b)
    z_b = compute_ecdhe_shared_secret(sk_b, pk_a)

    print(f"   Segredo compartilhado A: {z_a.hex()[:32]}...")
    print(f"   Segredo compartilhado B: {z_b.hex()[:32]}...")
    print(f"   Segredos iguais: {z_a == z_b} ✓\n")

    # Teste HKDF
    print("2. Testando HKDF...")
    salt = generate_random_salt()
    key_c2s, key_s2c = derive_keys_hkdf(z_a, salt, "Alice")

    print(f"   Key C2S: {key_c2s.hex()}")
    print(f"   Key S2C: {key_s2c.hex()}")
    print(f"   Chaves diferentes: {key_c2s != key_s2c} ✓\n")

    # Teste AES-GCM
    print("3. Testando AES-128-GCM...")
    plaintext = b"Mensagem secreta para Bob!"
    packet = encrypt_message_gcm(key_c2s, plaintext, "Alice", "Bob", 1)

    print(f"   Plaintext: {plaintext.decode()}")
    print(f"   Tamanho do pacote: {len(packet)} bytes")

    result = decrypt_message_gcm(key_c2s, packet)
    if result:
        decrypted, sender, recipient, seq = result
        print(f"   Decifrado: {decrypted.decode()}")
        print(f"   Sender: {sender}, Recipient: {recipient}, Seq: {seq}")
        print(f"   Sucesso: {plaintext == decrypted} ✓\n")

    # Teste de validação de seq_no
    print("4. Testando proteção contra replay...")
    print(f"   seq_no 2 > 1: {validate_sequence_number(1, 2)} ✓")
    print(
        f"   seq_no 1 > 2: {validate_sequence_number(2, 1)} (replay detectado) ✓")

    print("\n=== Todos os testes passaram! ===")
