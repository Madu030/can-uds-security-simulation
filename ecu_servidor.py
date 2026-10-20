import socket
import random

# Configuração da rede local
HOST = '0.0.0.0'  # Escuta em todas as interfaces de rede disponíveis
PORT = 5000       # Porta de comunicação escolhida

def calcular_chave(seed):
    """
    Simula a DLL ou algoritmo de segurança da montadora.
    Neste exemplo simples, a chave é o seed multiplicado por 3, mais 5.
    No seu artigo, você pode adaptar isso para a lógica que preferir.
    """
    return (seed * 3) + 5

def iniciar_servidor():
    servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    servidor.bind((HOST, PORT))
    servidor.listen(1)
    
    print(f"[*] ECU Simulada aguardando conexões na porta {PORT}...")
    
    while True:
        conexao, endereco = servidor.accept()
        print(f"[+] Conexão estabelecida com o Scanner: {endereco}")
        
        # 1. Gera um Seed aleatório (ex: entre 1000 e 9999)
        seed_gerado = random.randint(1000, 9999)
        print(f"[*] Seed gerado pela ECU: {seed_gerado}")
        
        # Envia o seed para o cliente (convertido para string em bytes)
        conexao.sendall(str(seed_gerado).encode('utf-8'))
        
        # 2. Recebe a Key de volta do cliente
        dados_recebidos = conexao.recv(1024).decode('utf-8')
        chave_recebida = int(dados_recebidos)
        print(f"[*] Chave recebida do Scanner: {chave_recebida}")
        
        # 3. Valida se a chave está correta
        chave_esperada = calcular_chave(seed_gerado)
        
        if chave_recebida == chave_esperada:
            resposta = "AUTORIZADO: Acesso de diagnóstico concedido!"
            print("[✓] Autenticação bem-sucedida!")
        else:
            resposta = "NEGADO: Chave inválida!"
            print("[X] Falha de autenticação!")
            
        conexao.sendall(resposta.encode('utf-8'))
        conexao.close()

if __name__ == "__main__":
    iniciar_servidor()
