import socket

# Substitua pelo endereço IP do Computador Y (ECU)
IP_SERVIDOR = '127.0.0.1'  # Aponta para o próprio computador  
PORTA = 5000

def calcular_chave(seed):
    """
    O scanner legítimo (ou a ferramenta de diagnóstico) possui 
    o mesmo algoritmo matemático para responder ao desafio da ECU.
    """
    return (seed * 3) + 5

def executar_scanner():
    cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    print(f"[*] Conectando à ECU em {IP_SERVIDOR}:{PORTA}...")
    try:
        cliente.connect((IP_SERVIDOR, PORTA))
    except Exception as e:
        print(f"[X] Não foi possível conectar: {e}")
        return

    # 1. Recebe o Seed enviado pela ECU
    seed_recebido = int(cliente.recv(1024).decode('utf-8'))
    print(f"[+] Seed recebido da ECU: {seed_recebido}")
    
    # 2. Calcula a Key correspondente
    chave_calculada = calcular_chave(seed_recebido)
    print(f"[*] Chave calculada: {chave_calculada}")
    
    # 3. Envia a Key de volta para a ECU
    cliente.sendall(str(chave_calculada).encode('utf-8'))
    
    # Recebe o veredito final
    resposta = cliente.recv(1024).decode('utf-8')
    print(f"[Resposta da ECU]: {resposta}")
    
    cliente.close()

if __name__ == "__main__":
    executar_scanner()
