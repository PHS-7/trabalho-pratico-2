"""
Cliente de Mensageria Segura

Funcionalidades:
- Conecta ao servidor via TCP
- Realiza handshake ECDHE com o servidor
- Valida certificado RSA e assinatura do servidor
- Deriva chaves direcionais com HKDF
- Envia mensagens cifradas (Key_c2s)
- Recebe mensagens cifradas (Key_s2c)
- Interface simples de linha de comando
"""

import asyncio
import struct
import sys
import aioconsole
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

from crypto_utils import (
    generate_ecdhe_keypair,
    compute_ecdhe_shared_secret,
    derive_keys_hkdf,
    encrypt_message_gcm,
    decrypt_message_gcm,
    create_transcript
)


# ============================================================================
# Configurações do Cliente
# ============================================================================

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 8888
SERVER_CERT_FILE = "server.crt"


# ============================================================================
# Estado do Cliente
# ============================================================================

class ClientState:
    """Armazena o estado da conexão do cliente."""

    def __init__(self, client_id):
        self.client_id = client_id
        self.reader = None
        self.writer = None
        self.key_c2s = None  # Cliente → Servidor
        self.key_s2c = None  # Servidor → Cliente
        self.seq_send = 1    # Próximo seq_no a enviar
        self.seq_recv = 0    # Último seq_no recebido
        self.connected = False


# ============================================================================
# Validação de Certificado
# ============================================================================

def load_and_verify_certificate(cert_bytes):
    """
    Carrega e verifica o certificado do servidor.

    Args:
        cert_bytes (bytes): Certificado em formato PEM

    Returns:
        x509.Certificate: Objeto de certificado validado ou None
    """
    try:
        # Carrega certificado esperado (pinning)
        with open(SERVER_CERT_FILE, "rb") as f:
            expected_cert_bytes = f.read()

        expected_cert = x509.load_pem_x509_certificate(
            expected_cert_bytes, default_backend()
        )
        received_cert = x509.load_pem_x509_certificate(
            cert_bytes, default_backend()
        )

        # Valida que o certificado recebido é o esperado (pinning)
        if cert_bytes != expected_cert_bytes:
            print("❌ ERRO: Certificado do servidor não corresponde ao esperado!")
            print("   Possível ataque Man-in-the-Middle!")
            return None

        print(f"✓ Certificado validado (pinning)")
        print(f"  Emissor: {received_cert.issuer.rfc4514_string()}")
        print(f"  Válido até: {received_cert.not_valid_after}")

        return received_cert

    except FileNotFoundError:
        print(f"❌ ERRO: Certificado '{SERVER_CERT_FILE}' não encontrado!")
        print("   Certifique-se de que o arquivo está no mesmo diretório")
        return None
    except Exception as e:
        print(f"❌ ERRO ao validar certificado: {e}")
        return None


# ============================================================================
# Handshake com Servidor
# ============================================================================

async def perform_handshake(state):
    """
    Realiza o handshake ECDHE + RSA com o servidor.

    Protocolo:
    1. Cliente → Servidor: [len(client_id)] + client_id + pk_C
    2. Servidor → Cliente: pk_S + cert + assinatura + salt
    3. Cliente valida assinatura RSA
    4. Ambos derivam chaves com HKDF

    Args:
        state (ClientState): Estado da conexão

    Returns:
        bool: True se handshake foi bem-sucedido, False caso contrário
    """
    try:
        print("\n🔐 Iniciando handshake...")

        # 1. Gera par de chaves ECDHE efêmero
        sk_C, pk_C = generate_ecdhe_keypair()
        print(f"   [1/6] Chave ECDHE gerada ({len(pk_C)} bytes)")

        # 2. Envia client_id e pk_C ao servidor
        client_id_bytes = state.client_id.encode('utf-8')
        message = (
            struct.pack('!I', len(client_id_bytes)) + client_id_bytes +
            struct.pack('!I', len(pk_C)) + pk_C
        )
        state.writer.write(message)
        await state.writer.drain()
        print(f"   [2/6] Enviado: client_id + pk_C")

        # 3. Recebe pk_S do servidor
        pk_S_len = struct.unpack('!I', await state.reader.readexactly(4))[0]
        pk_S = await state.reader.readexactly(pk_S_len)
        print(f"   [3/6] Recebido: pk_S ({pk_S_len} bytes)")

        # 4. Recebe certificado
        cert_len = struct.unpack('!I', await state.reader.readexactly(4))[0]
        cert_bytes = await state.reader.readexactly(cert_len)
        print(f"   [4/6] Recebido: certificado ({cert_len} bytes)")

        # 5. Valida certificado (pinning)
        cert = load_and_verify_certificate(cert_bytes)
        if cert is None:
            return False

        # 6. Recebe assinatura RSA
        sig_len = struct.unpack('!I', await state.reader.readexactly(4))[0]
        signature = await state.reader.readexactly(sig_len)
        print(f"   [5/6] Recebida: assinatura RSA ({sig_len} bytes)")

        # 7. Recebe salt
        salt = await state.reader.readexactly(32)
        print(f"   [6/6] Recebido: salt (32 bytes)")

        # 8. Valida assinatura RSA
        transcript = create_transcript(state.client_id, pk_C, pk_S)
        message_to_verify = pk_S + \
            state.client_id.encode('utf-8') + transcript + salt

        try:
            public_key = cert.public_key()
            public_key.verify(
                signature,
                message_to_verify,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print(f"✓ Assinatura RSA validada (servidor autenticado)")
        except InvalidSignature:
            print("❌ ERRO: Assinatura RSA inválida!")
            print("   Possível ataque Man-in-the-Middle!")
            return False

        # 9. Calcula segredo compartilhado ECDHE
        shared_secret = compute_ecdhe_shared_secret(sk_C, pk_S)
        print(
            f"✓ Segredo compartilhado calculado ({len(shared_secret)} bytes)")

        # 10. Deriva chaves com HKDF
        state.key_c2s, state.key_s2c = derive_keys_hkdf(
            shared_secret, salt, state.client_id, transcript
        )
        print(f"✓ Chaves derivadas: Key_c2s e Key_s2c (16 bytes cada)")

        print(f"✅ Handshake concluído com sucesso!")
        print(f"   Sigilo perfeito garantido por ECDHE")

        return True

    except Exception as e:
        print(f"❌ ERRO no handshake: {e}")
        return False


# ============================================================================
# Envio de Mensagens
# ============================================================================

async def send_message(state, recipient_id, message):
    """
    Envia uma mensagem cifrada para outro cliente.

    Args:
        state (ClientState): Estado da conexão
        recipient_id (str): ID do destinatário
        message (str): Mensagem em texto claro
    """
    try:
        # Cifra mensagem com Key_c2s
        plaintext = message.encode('utf-8')
        packet = encrypt_message_gcm(
            state.key_c2s,
            plaintext,
            state.client_id,
            recipient_id,
            state.seq_send
        )

        state.seq_send += 1

        # Envia tamanho + pacote
        packet_len = struct.pack('!I', len(packet))
        state.writer.write(packet_len + packet)
        await state.writer.drain()

        print(f"✓ Enviado para {recipient_id}")

    except Exception as e:
        print(f"❌ ERRO ao enviar mensagem: {e}")


# ============================================================================
# Recebimento de Mensagens
# ============================================================================

async def receive_messages(state):
    """
    Loop assíncrono para receber mensagens do servidor.

    Args:
        state (ClientState): Estado da conexão
    """
    try:
        while state.connected:
            # Lê tamanho do pacote
            packet_len_bytes = await state.reader.readexactly(4)
            packet_len = struct.unpack('!I', packet_len_bytes)[0]

            # Lê pacote completo
            packet = await state.reader.readexactly(packet_len)

            # Decifra com Key_s2c
            result = decrypt_message_gcm(state.key_s2c, packet)

            if result is None:
                print("⚠️  Falha ao decifrar mensagem recebida")
                continue

            plaintext, sender_id, recipient_id, seq_no = result

            # Valida seq_no
            if seq_no <= state.seq_recv:
                print(
                    f"⚠️  REPLAY ATTACK detectado: seq_no {seq_no} <= {state.seq_recv}")
                continue

            state.seq_recv = seq_no

            # Exibe mensagem
            message = plaintext.decode('utf-8', errors='replace')
            print(f"\n📩 [{sender_id}]: {message}")
            print(f"→ ", end='', flush=True)  # Prompt para próxima entrada

    except asyncio.IncompleteReadError:
        print("\n🔌 Conexão com servidor perdida")
        state.connected = False
    except Exception as e:
        print(f"\n❌ ERRO ao receber mensagens: {e}")
        state.connected = False


# ============================================================================
# Interface de Usuário
# ============================================================================

async def user_interface(state):
    """
    Interface de linha de comando para enviar mensagens.

    Args:
        state (ClientState): Estado da conexão
    """
    print("\n" + "=" * 70)
    print("💬 INTERFACE DE MENSAGERIA")
    print("=" * 70)
    print("\nFormato: Para:Destinatário Mensagem aqui")
    print("Exemplo: Para:Bob Olá Bob, tudo bem?")
    print("\nDigite 'sair' para desconectar")
    print("=" * 70 + "\n")

    try:
        while state.connected:
            # Lê input do usuário de forma assíncrona
            user_input = await aioconsole.ainput("→ ")

            if user_input.lower() in ['sair', 'exit', 'quit']:
                print("👋 Desconectando...")
                state.connected = False
                break

            # Parse do formato "Para:Destinatário Mensagem"
            if not user_input.startswith("Para:"):
                print("⚠️  Formato inválido. Use: Para:Destinatário Mensagem")
                continue

            try:
                parts = user_input[5:].split(' ', 1)
                if len(parts) < 2:
                    print("⚠️  Mensagem vazia. Use: Para:Destinatário Mensagem")
                    continue

                recipient_id = parts[0].strip()
                message = parts[1].strip()

                if not recipient_id or not message:
                    print("⚠️  Destinatário ou mensagem vazia")
                    continue

                # Envia mensagem
                await send_message(state, recipient_id, message)

            except Exception as e:
                print(f"⚠️  Erro ao processar entrada: {e}")

    except asyncio.CancelledError:
        pass
    except Exception as e:
        print(f"❌ ERRO na interface: {e}")


# ============================================================================
# Cliente Principal
# ============================================================================

async def main(client_id):
    """
    Função principal do cliente.

    Args:
        client_id (str): ID único do cliente
    """
    print("=" * 70)
    print(f"🔐 CLIENTE DE MENSAGERIA SEGURA - {client_id}")
    print("=" * 70)

    state = ClientState(client_id)

    try:
        # Conecta ao servidor
        print(f"\n🔗 Conectando ao servidor {SERVER_HOST}:{SERVER_PORT}...")
        state.reader, state.writer = await asyncio.open_connection(
            SERVER_HOST, SERVER_PORT
        )
        print("✓ Conexão TCP estabelecida")

        # Realiza handshake
        if not await perform_handshake(state):
            print("❌ Handshake falhou. Encerrando...")
            return

        state.connected = True

        # Inicia tasks assíncronas
        recv_task = asyncio.create_task(receive_messages(state))
        ui_task = asyncio.create_task(user_interface(state))

        # Aguarda até uma das tasks terminar
        done, pending = await asyncio.wait(
            [recv_task, ui_task],
            return_when=asyncio.FIRST_COMPLETED
        )

        # Cancela tasks pendentes
        for task in pending:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    except ConnectionRefusedError:
        print(
            f"❌ ERRO: Não foi possível conectar ao servidor em {SERVER_HOST}:{SERVER_PORT}")
        print("   Verifique se o servidor está rodando")
    except Exception as e:
        print(f"❌ ERRO: {e}")
    finally:
        # Fecha conexão
        if state.writer:
            state.writer.close()
            await state.writer.wait_closed()
        print("\n👋 Cliente encerrado")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: python client.py <client_id>")
        print("\nExemplos:")
        print("  python client.py Alice")
        print("  python client.py Bob")
        print("  python client.py Charlie")
        sys.exit(1)

    client_id = sys.argv[1]

    # Valida client_id
    if not client_id or len(client_id) > 16:
        print("❌ ERRO: client_id deve ter entre 1 e 16 caracteres")
        sys.exit(1)

    try:
        asyncio.run(main(client_id))
    except KeyboardInterrupt:
        print("\n\n⏹️  Cliente encerrado pelo usuário")
    except Exception as e:
        print(f"\n❌ ERRO FATAL: {e}")
        sys.exit(1)
