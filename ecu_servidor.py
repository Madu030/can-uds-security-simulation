import socket
import random
from cryptography.fernet import Fernet

# CHAVE SECRETA COMPARTILHADA (Deve ser idêntica no Cliente e no Servidor)
CHAVE_COMPARTILHADA = b'r8Zz3vL9pW4tY3mQ6bH5fD2sA8jG0xC1zV4bN7m_K28='
cipher = Fernet(CHAVE_COMPARTILHADA)

HOST = '0.0.0.0'  # Escuta em todas as interfaces
PORT = 5001     # Porta de comunicação

def calcular_chave(seed):
    """
    Simula a DLL ou algoritmo de segurança da montadora.
    A chave é o seed multiplicado por 3, mais 5.
    """
    return (seed * 3) + 5

def iniciar_servidor():
    servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    servidor.bind((HOST, PORT))
    servidor.listen(1)
    
    print(f"[*] ECU Simulada (Com Criptografia AES) aguardando conexões na porta {PORT}...")
    
    while True:
        conexao, endereco = servidor.accept()
        print(f"[+] Conexão estabelecida com o Scanner: {endereco}")
        
        try:
            # 1. Gera um Seed aleatório
            seed_gerado = random.randint(1000, 9999)
            print(f"[*] Seed gerado pela ECU (antes de cifrar): {seed_gerado}")
            
            # Cifra o seed antes de enviar pela rede
            mensagem_seed = f"SEED:{seed_gerado}"
            conexao.sendall(cipher.encrypt(mensagem_seed.encode('utf-8')))
            
            # 2. Recebe a Key cifrada de volta do cliente
            dados_cifrados = conexao.recv(1024)
            if not dados_cifrados:
                conexao.close()
                continue
                
            # Descifra a chave recebida
            dados_recebidos = cipher.decrypt(dados_cifrados).decode('utf-8')
            print(f"[Recebido da Aplicação (Cifrado na rede)] -> Descifrado: {dados_recebidos}")
            
            if dados_recebidos.startswith("KEY:"):
                chave_recebida = int(dados_recebidos.split(":")[1])
                print(f"[*] Chave numérica recebida: {chave_recebida}")
                
                # 3. Valida se a chave está correta
                chave_esperada = calcular_chave(seed_gerado)
                
                if chave_recebida == chave_esperada:
                    resposta = "AUTORIZADO: Acesso de diagnóstico concedido!"
                    print("[✓] Autenticação bem-sucedida!")
                else:
                    resposta = "NEGADO: Chave inválida!"
                    print("[X] Falha de autenticação!")
                
                # Cifra a resposta final antes de enviar
                conexao.sendall(cipher.encrypt(resposta.encode('utf-8')))
                
        except Exception as e:
            print(f"[-] Erro de descriptografia ou segurança: {e}")
            try:
                conexao.sendall(cipher.encrypt(b"ERRO: Falha de autenticacao criptografica!"))
            except:
                pass
                
        conexao.close()

if __name__ == "__main__":
    iniciar_servidor()