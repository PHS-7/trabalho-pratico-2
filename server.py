"""
Servidor de Mensageria Segura Multi-Cliente

Funcionalidades:
- Aceita múltiplas conexões TCP simultâneas
- Realiza handshake ECDHE com cada cliente
- Assina chaves efêmeras com RSA para autenticação
- Deriva chaves direcionais com HKDF (TLS 1.3)
- Decifra mensagens dos clientes (Key_c2s)
- Re-cifra e encaminha para destinatários (Key_s2c)
- Gerencia sessões com proteção contra replay
"""

import asyncio
import struct
import sys
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

from crypto_utils import (
    generate_ecdhe_keypair,
    compute_ecdhe_shared_secret,
    derive_keys_hkdf,
    encrypt_message_gcm,
    decrypt_message_gcm,
    generate_random_salt,
    validate_sequence_number,
    create_transcript
)


# ============================================================================
# Configurações do Servidor
# ============================================================================

SERVER_HOST = "0.0.0.0"
SERVER_PORT = 8888
SERVER_KEY_FILE = "server.key"
SERVER_CERT_FILE = "server.crt"


# ============================================================================
# Armazenamento de Sessões
# ============================================================================

sessions = {}
"""
Estrutura:
{
    client_id: {
        "writer": StreamWriter,
        "key_c2s": bytes,      # Cliente → Servidor
        "key_s2c": bytes,      # Servidor → Cliente
        "seq_recv": int,       # Último seq_no recebido
        "seq_send": int,       # Próximo seq_no a enviar
        "salt": bytes,         # Salt usado no HKDF
        "pk_client": bytes,    # Chave pública ECDHE do cliente
    }
}
"""


# ============================================================================
# Carregamento de Chaves RSA
# ============================================================================

def load_server_rsa_keys():
    """
    Carrega a chave privada RSA e o certificado do servidor.

    Returns:
        tuple: (private_key, certificate_bytes)
    """
    try:
        # Carrega chave privada
        with open(SERVER_KEY_FILE, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )

        # Carrega certificado
        with open(SERVER_CERT_FILE, "rb") as f:
            certificate_bytes = f.read()

        print(
            f"✓ Chaves RSA carregadas de '{SERVER_KEY_FILE}' e '{SERVER_CERT_FILE}'")
        return private_key, certificate_bytes

    except FileNotFoundError as e:
        print(f"❌ ERRO: Arquivo não encontrado: {e.filename}")
        print(f"   Execute primeiro: python generate_cert.py")
        sys.exit(1)
    except Exception as e:
        print(f"❌ ERRO ao carregar chaves RSA: {e}")
        sys.exit(1)


# ============================================================================
# Handshake com Cliente
# ============================================================================

async def perform_handshake(reader, writer, rsa_private_key, certificate_bytes):
    """
    Realiza o handshake ECDHE + RSA com um cliente.

    Protocolo:
    1. Cliente → Servidor: [len(client_id)] + client_id + pk_C
    2. Servidor → Cliente: [len(pk_S)] + pk_S + [len(cert)] + cert + [len(sig)] + sig + salt
    3. Ambos derivam chaves com HKDF

    Args:
        reader: StreamReader assíncrono
        writer: StreamWriter assíncrono
        rsa_private_key: Chave privada RSA do servidor
        certificate_bytes: Certificado RSA serializado

    Returns:
        tuple: (client_id, key_c2s, key_s2c, salt) ou None em caso de erro
    """
    try:
        # 1. Recebe client_id e pk_C do cliente
        client_id_len = struct.unpack('!I', await reader.readexactly(4))[0]
        client_id = (await reader.readexactly(client_id_len)).decode('utf-8')

        pk_C_len = struct.unpack('!I', await reader.readexactly(4))[0]
        pk_C = await reader.readexactly(pk_C_len)

        print(f"\n[HANDSHAKE] Cliente '{client_id}' conectado")
        print(f"            Recebida pk_C ({pk_C_len} bytes)")

        # 2. Gera par de chaves ECDHE efêmero do servidor
        sk_S, pk_S = generate_ecdhe_keypair()
        print(f"            Gerada pk_S ({len(pk_S)} bytes)")

        # 3. Cria transcript do handshake
        transcript = create_transcript(client_id, pk_C, pk_S)

        # 4. Gera salt aleatório
        salt = generate_random_salt(32)

        # 5. Assina: pk_S || client_id || transcript || salt
        message_to_sign = pk_S + client_id.encode('utf-8') + transcript + salt
        signature = rsa_private_key.sign(
            message_to_sign,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print(f"            Assinatura RSA criada ({len(signature)} bytes)")

        # 6. Envia pk_S + certificado + assinatura + salt
        response = (
            struct.pack('!I', len(pk_S)) + pk_S +
            struct.pack('!I', len(certificate_bytes)) + certificate_bytes +
            struct.pack('!I', len(signature)) + signature +
            salt
        )
        writer.write(response)
        await writer.drain()
        print(f"            Enviado: pk_S + cert + assinatura + salt")

        # 7. Calcula segredo compartilhado ECDHE
        shared_secret = compute_ecdhe_shared_secret(sk_S, pk_C)
        print(
            f"            Segredo compartilhado calculado ({len(shared_secret)} bytes)")

        # 8. Deriva chaves com HKDF
        key_c2s, key_s2c = derive_keys_hkdf(
            shared_secret, salt, client_id, transcript)
        print(f"            Chaves derivadas: Key_c2s e Key_s2c (16 bytes cada)")

        print(f"✓ Handshake com '{client_id}' concluído com sucesso!")

        return client_id, key_c2s, key_s2c, salt, pk_C

    except Exception as e:
        print(f"❌ ERRO no handshake: {e}")
        return None


# ============================================================================
# Processamento de Mensagens
# ============================================================================

async def handle_message(packet, client_id):
    """
    Processa uma mensagem recebida de um cliente.

    1. Decifra com Key_c2s do remetente
    2. Valida tag GCM e seq_no
    3. Re-cifra com Key_s2c do destinatário
    4. Encaminha ao destinatário

    Args:
        packet (bytes): Pacote cifrado recebido
        client_id (str): ID do cliente remetente
    """
    if client_id not in sessions:
        print(f"⚠️  Cliente '{client_id}' não tem sessão ativa")
        return

    session = sessions[client_id]

    try:
        # 1. Decifra mensagem com Key_c2s
        result = decrypt_message_gcm(session["key_c2s"], packet)

        if result is None:
            print(f"❌ Falha ao decifrar mensagem de '{client_id}'")
            return

        plaintext, sender_id, recipient_id, seq_no = result

        # 2. Valida seq_no para proteção contra replay
        if not validate_sequence_number(session["seq_recv"], seq_no):
            print(
                f"⚠️  REPLAY ATTACK detectado de '{client_id}': seq_no {seq_no} <= {session['seq_recv']}")
            return

        # Atualiza seq_recv
        session["seq_recv"] = seq_no

        print(f"\n📨 [{sender_id} → {recipient_id}] seq={seq_no}")
        print(f"   Mensagem: {plaintext.decode('utf-8', errors='replace')}")

        # 3. Verifica se destinatário está online
        if recipient_id not in sessions:
            print(f"⚠️  Destinatário '{recipient_id}' não está online")
            # Aqui poderia implementar fila de mensagens offline
            return

        recipient_session = sessions[recipient_id]

        # 4. Re-cifra com Key_s2c do destinatário
        seq_send = recipient_session["seq_send"]
        recipient_session["seq_send"] += 1

        new_packet = encrypt_message_gcm(
            recipient_session["key_s2c"],
            plaintext,
            sender_id,
            recipient_id,
            seq_send
        )

        # 5. Envia ao destinatário
        recipient_writer = recipient_session["writer"]

        # Envia tamanho do pacote + pacote
        packet_len = struct.pack('!I', len(new_packet))
        recipient_writer.write(packet_len + new_packet)
        await recipient_writer.drain()

        print(f"✓ Mensagem encaminhada para '{recipient_id}'")

    except Exception as e:
        print(f"❌ ERRO ao processar mensagem: {e}")


# ============================================================================
# Handler de Cliente
# ============================================================================

async def handle_client(reader, writer, rsa_private_key, certificate_bytes):
    """
    Handler assíncrono para cada conexão de cliente.

    1. Realiza handshake
    2. Registra sessão
    3. Loop de recebimento de mensagens
    4. Remove sessão ao desconectar
    """
    addr = writer.get_extra_info('peername')
    print(f"\n🔗 Nova conexão de {addr}")

    client_id = None

    try:
        # 1. Handshake
        handshake_result = await perform_handshake(
            reader, writer, rsa_private_key, certificate_bytes
        )

        if handshake_result is None:
            print(f"❌ Handshake falhou com {addr}")
            return

        client_id, key_c2s, key_s2c, salt, pk_client = handshake_result

        # 2. Registra sessão
        sessions[client_id] = {
            "writer": writer,
            "key_c2s": key_c2s,
            "key_s2c": key_s2c,
            "seq_recv": 0,
            "seq_send": 1,
            "salt": salt,
            "pk_client": pk_client
        }

        print(f"\n✅ Cliente '{client_id}' autenticado e sessão criada")
        print(f"   Clientes online: {list(sessions.keys())}")

        # 3. Loop de recebimento de mensagens
        while True:
            # Lê tamanho do pacote (4 bytes, big-endian)
            packet_len_bytes = await reader.readexactly(4)
            packet_len = struct.unpack('!I', packet_len_bytes)[0]

            # Lê pacote completo
            packet = await reader.readexactly(packet_len)

            # Processa mensagem
            await handle_message(packet, client_id)

    except asyncio.IncompleteReadError:
        print(f"\n🔌 Cliente '{client_id or addr}' desconectou")
    except Exception as e:
        print(f"\n❌ ERRO com cliente '{client_id or addr}': {e}")
    finally:
        # 4. Remove sessão
        if client_id and client_id in sessions:
            del sessions[client_id]
            print(f"🗑️  Sessão de '{client_id}' removida")
            print(f"   Clientes online: {list(sessions.keys())}")

        writer.close()
        await writer.wait_closed()


# ============================================================================
# Servidor Principal
# ============================================================================

async def main():
    """
    Função principal do servidor.
    """
    print("=" * 70)
    print("🔐 SERVIDOR DE MENSAGERIA SEGURA MULTI-CLIENTE")
    print("=" * 70)

    # Carrega chaves RSA
    rsa_private_key, certificate_bytes = load_server_rsa_keys()

    # Inicia servidor TCP
    server = await asyncio.start_server(
        lambda r, w: handle_client(r, w, rsa_private_key, certificate_bytes),
        SERVER_HOST,
        SERVER_PORT
    )

    addrs = ', '.join(str(sock.getsockname()) for sock in server.sockets)
    print(f"\n🚀 Servidor iniciado em {addrs}")
    print(f"   Aguardando conexões...\n")
    print("   Pressione Ctrl+C para encerrar\n")
    print("=" * 70)

    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\n⏹️  Servidor encerrado pelo usuário")
    except Exception as e:
        print(f"\n❌ ERRO FATAL: {e}")
        sys.exit(1)
