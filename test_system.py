#!/usr/bin/env python3
"""
Script de teste para verificar todas as dependências e funcionalidades.

Execute este script para validar que:
1. Python 3.8+ está instalado
2. Todas as bibliotecas necessárias estão disponíveis
3. Certificado RSA foi gerado
4. Funções criptográficas funcionam corretamente
"""

import sys
import os


def check_python_version():
    """Verifica se a versão do Python é 3.8+"""
    print("[1/5] Verificando versão do Python...")
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 8):
        print(f"❌ Python {version.major}.{version.minor} detectado")
        print("   Requer Python 3.8 ou superior")
        return False
    print(f"✓ Python {version.major}.{version.minor}.{version.micro}")
    return True


def check_dependencies():
    """Verifica se todas as dependências estão instaladas"""
    print("\n[2/5] Verificando dependências...")

    required = [
        ('cryptography', 'cryptography'),
        ('aioconsole', 'aioconsole')
    ]

    all_ok = True
    for package, import_name in required:
        try:
            __import__(import_name)
            print(f"✓ {package}")
        except ImportError:
            print(f"❌ {package} não encontrado")
            all_ok = False

    if not all_ok:
        print("\n   Execute: pip3 install -r requirements.txt")
        return False

    return True


def check_certificates():
    """Verifica se os certificados RSA existem"""
    print("\n[3/5] Verificando certificados RSA...")

    if os.path.exists("server.key") and os.path.exists("server.crt"):
        print("✓ server.key encontrado")
        print("✓ server.crt encontrado")
        return True
    else:
        print("⚠️  Certificados não encontrados")
        print("   Execute: python3 generate_cert.py")
        return False


def test_crypto_functions():
    """Testa funções criptográficas básicas"""
    print("\n[4/5] Testando funções criptográficas...")

    try:
        from crypto_utils import (
            generate_ecdhe_keypair,
            compute_ecdhe_shared_secret,
            derive_keys_hkdf,
            encrypt_message_gcm,
            decrypt_message_gcm,
            generate_random_salt
        )

        # Teste ECDHE
        sk_a, pk_a = generate_ecdhe_keypair()
        sk_b, pk_b = generate_ecdhe_keypair()
        z_a = compute_ecdhe_shared_secret(sk_a, pk_b)
        z_b = compute_ecdhe_shared_secret(sk_b, pk_a)

        if z_a != z_b:
            print("❌ ECDHE: segredos compartilhados não coincidem")
            return False
        print("✓ ECDHE: segredo compartilhado calculado")

        # Teste HKDF
        salt = generate_random_salt()
        key_c2s, key_s2c = derive_keys_hkdf(z_a, salt, "TestClient")

        if len(key_c2s) != 16 or len(key_s2c) != 16:
            print("❌ HKDF: tamanho de chave incorreto")
            return False
        if key_c2s == key_s2c:
            print("❌ HKDF: chaves direcionais são iguais")
            return False
        print("✓ HKDF: chaves direcionais derivadas")

        # Teste AES-GCM
        plaintext = b"Mensagem de teste"
        packet = encrypt_message_gcm(key_c2s, plaintext, "Alice", "Bob", 1)
        result = decrypt_message_gcm(key_c2s, packet)

        if result is None:
            print("❌ AES-GCM: falha na decriptação")
            return False

        decrypted, sender, recipient, seq = result
        if decrypted != plaintext:
            print("❌ AES-GCM: texto decifrado não corresponde")
            return False
        print("✓ AES-GCM: criptografia/decriptografia")

        return True

    except Exception as e:
        print(f"❌ Erro nos testes: {e}")
        return False


def print_summary(results):
    """Imprime resumo dos testes"""
    print("\n" + "=" * 60)
    print("RESUMO DOS TESTES")
    print("=" * 60)

    tests = [
        ("Versão do Python", results[0]),
        ("Dependências", results[1]),
        ("Certificados RSA", results[2]),
        ("Funções Criptográficas", results[3])
    ]

    for name, result in tests:
        status = "✅ OK" if result else "❌ FALHOU"
        print(f"{name:.<50} {status}")

    print("=" * 60)

    if all(results):
        print("\n🎉 TODOS OS TESTES PASSARAM!")
        print("\nSistema pronto para uso.")
        print("\nPróximos passos:")
        print("1. Terminal 1: python3 server.py")
        print("2. Terminal 2: python3 client.py Alice")
        print("3. Terminal 3: python3 client.py Bob")
        return True
    else:
        print("\n⚠️  ALGUNS TESTES FALHARAM")
        print("\nSiga as instruções acima para corrigir os problemas.")
        return False


def main():
    """Função principal"""
    print("=" * 60)
    print("🔐 TESTE DO SISTEMA DE MENSAGERIA SEGURA")
    print("=" * 60)
    print()

    results = [
        check_python_version(),
        check_dependencies(),
        check_certificates(),
        test_crypto_functions()
    ]

    print("\n[5/5] Finalizando testes...")

    success = print_summary(results)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⏹️  Testes interrompidos pelo usuário")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ ERRO FATAL: {e}")
        sys.exit(1)
