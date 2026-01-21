"""
Script para gerar certificado RSA autoassinado para o servidor.

Gera:
- server.key: Chave privada RSA (2048 bits)
- server.crt: Certificado autoassinado X.509

O certificado é usado para:
1. Autenticar o servidor durante o handshake
2. Assinar a chave pública ECDHE do servidor
3. Garantir que o cliente está se conectando ao servidor correto (pinning)
"""

import os
import ipaddress
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


def generate_rsa_certificate(
    key_file="server.key",
    cert_file="server.crt",
    key_size=2048,
    validity_days=365
):
    """
    Gera um par de chave privada RSA e certificado autoassinado.

    Args:
        key_file (str): Nome do arquivo para a chave privada
        cert_file (str): Nome do arquivo para o certificado
        key_size (int): Tamanho da chave RSA em bits (padrão: 2048)
        validity_days (int): Validade do certificado em dias (padrão: 365)
    """

    print("🔐 Gerando certificado RSA autoassinado...\n")

    # 1. Gera chave privada RSA
    print(f"[1/4] Gerando chave privada RSA ({key_size} bits)...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    print("      ✓ Chave privada gerada")

    # 2. Cria o certificado autoassinado
    print("[2/4] Criando certificado X.509...")

    # Define os atributos do certificado
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "BR"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Estado"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Cidade"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME,
                           "Secure Messaging Server"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])

    # Cria o certificado
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=validity_days))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address(
                    os.getenv("SERVER_IP", "127.0.0.1"))),
            ]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256(), default_backend())
    )
    print("      ✓ Certificado criado")

    # 3. Salva a chave privada
    print(f"[3/4] Salvando chave privada em '{key_file}'...")
    with open(key_file, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
    # Define permissões seguras (somente leitura pelo proprietário)
    os.chmod(key_file, 0o600)
    print(f"      ✓ Chave privada salva (permissões: 600)")

    # 4. Salva o certificado
    print(f"[4/4] Salvando certificado em '{cert_file}'...")
    with open(cert_file, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print(f"      ✓ Certificado salvo")

    print(f"\n✅ Certificado gerado com sucesso!")
    print(f"\n📋 Informações do Certificado:")
    print(f"   - Emissor: {cert.issuer.rfc4514_string()}")
    print(f"   - Sujeito: {cert.subject.rfc4514_string()}")
    print(f"   - Número de série: {cert.serial_number}")
    print(f"   - Válido de: {cert.not_valid_before}")
    print(f"   - Válido até: {cert.not_valid_after}")
    print(
        f"   - Algoritmo de assinatura: {cert.signature_algorithm_oid._name}")

    print(f"\n⚠️  IMPORTANTE:")
    print(f"   - Mantenha '{key_file}' em segredo (nunca compartilhe)")
    print(
        f"   - Distribua '{cert_file}' para todos os clientes (certificate pinning)")
    print(f"   - Este é um certificado autoassinado (apenas para desenvolvimento/demo)")


def verify_certificate_exists(key_file="server.key", cert_file="server.crt"):
    """
    Verifica se os arquivos de certificado já existem.

    Returns:
        bool: True se ambos os arquivos existem, False caso contrário
    """
    return os.path.exists(key_file) and os.path.exists(cert_file)


if __name__ == "__main__":
    KEY_FILE = "server.key"
    CERT_FILE = "server.crt"

    # Verifica se já existem
    if verify_certificate_exists(KEY_FILE, CERT_FILE):
        print(f"⚠️  Certificado já existe!")
        print(f"   - {KEY_FILE}")
        print(f"   - {CERT_FILE}")

        response = input("\n🔄 Deseja sobrescrever? (s/N): ").strip().lower()
        if response != 's':
            print("❌ Operação cancelada.")
            exit(0)

        print("\n🗑️  Removendo arquivos existentes...")
        os.remove(KEY_FILE)
        os.remove(CERT_FILE)

    # Gera novo certificado
    generate_rsa_certificate(KEY_FILE, CERT_FILE)

    print(f"\n🚀 Agora você pode iniciar o servidor com: python server.py")
