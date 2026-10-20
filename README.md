# Simulação de Ataque e Detecção de Intrusão em Protocolo UDS (Seed & Key)

Este repositório contém a implementação prática desenvolvida para o artigo científico sobre **Cibersegurança Automotiva e Inteligência Artificial**. 

O projeto simula a comunicação de diagnóstico automotivo entre uma ECU (Central Eletrônica do Veículo) e um Scanner de diagnóstico via rede local (TCP/IP), reproduzindo a troca de mensagens do serviço **UDS 0x27 (Security Access)**.

---

##  Estrutura do Projeto

* `ecu_servidor.py`: Simula a ECU do veículo. Aguarda conexões, gera o desafio (*seed*), valida a resposta (*key*) e gerencia a concessão de acesso.
* `scanner_cliente.py`: Simula a ferramenta de diagnóstico legítima (ou o vetor de ataque). Conecta-se à ECU, recebe a semente, calcula a chave de validação e solicita acesso.

---

##  Como Executar

### Pré-requisitos
* Python 3.x instalado.
* Dispositivos conectados na mesma rede (ou na mesma máquina via localhost).

---

### Passo 1: Iniciar a ECU (Servidor)
No terminal da máquina que atuará como ECU (ou no Terminal 1):
```bash

---

### Passo 2: Iniciar o Scanner (Cliente)
No terminal da máquina que atuará como Scanner (ou no Terminal 2):

Nota: Caso esteja executando em computadores diferentes, certifique-se de atualizar a variável IP_SERVIDOR no arquivo scanner_cliente.py com o IP local correto da máquina Servidor.
python ecu_servidor.py
