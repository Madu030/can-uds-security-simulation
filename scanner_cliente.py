import socket
from cryptography.fernet import Fernet

# MESMA CHAVE SECRETA COMPARTILHADA
CHAVE_COMPARTILHADA = b'r8Zz3vL9pW4tY3mQ6bH5fD2sA8jG0xC1zV4bN7m_K28='
cipher = Fernet(CHAVE_COMPARTILHADA)

IP_SERVIDOR = '127.0.0.1'  # Ou o IP do Tailscale (ex: 100.64.170.81)
PORTA = 5001

def calcular_chave(seed):
    """
    Algoritmo de cálculo da chave com base no seed recebido.
    """
    return (seed * 3) + 5

def executar_scanner():
    cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print(f"[*] A ligar à ECU em {IP_SERVIDOR}:{PORTA}...")
    
    try:
        cliente.connect((IP_SERVIDOR, PORTA))
        
        # 1. Recebe o Seed cifrado da ECU
        dados_cifrados = cliente.recv(1024)
        seed_msg = cipher.decrypt(dados_cifrados).decode('utf-8')
        
        if seed_msg.startswith("SEED:"):
            seed = int(seed_msg.split(":")[1])
            print(f"[+] Seed recebido da ECU (descifrado): {seed}")

            # 2. Calcula a Chave correspondente
            chave_calculada = calcular_chave(seed)
            print(f"[*] Chave calculada: {chave_calculada}")

            # Cifra a chave antes de enviar de volta para a ECU
            envio_chave = f"KEY:{chave_calculada}"
            cliente.sendall(cipher.encrypt(envio_chave.encode('utf-8')))

            # 3. Recebe o veredito final cifrado da ECU
            resposta_cifrada = cliente.recv(1024)
            veredito = cipher.decrypt(resposta_cifrada).decode('utf-8')
            print(f"[Resposta da ECU]: {veredito}")

    except Exception as e:
        print(f"[-] Erro na comunicação segura com a ECU: {e}")
    finally:
        cliente.close()

if __name__ == "__main__":
    executar_scanner()