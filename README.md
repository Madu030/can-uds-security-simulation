# Simulação de Ataque, Mitigação e Detecção de Intrusão em Protocolo UDS (Seed & Key)

Este repositório contém a implementação prática desenvolvida para o artigo científico sobre **Cibersegurança Automotiva, Criptografia de Camada de Rede e Inteligência Artificial**.

O projeto simula a comunicação de diagnóstico automotivo entre uma **ECU** (Unidade de Controlo Eletrónico / Central Eletrônica do Veículo) e um **Scanner** de diagnóstico via rede TCP/IP, reproduzindo a troca de mensagens do serviço **UDS (Unified Diagnostic Services)** — especificamente o mecanismo de segurança **Seed & Key** (Serviço 0x27).

---

## Estrutura do Projeto

* **`ecu_servidor.py`**: Simula a ECU do veículo. Fica à escuta de conexões, gera o valor aleatório de *Seed*, valida a *Key* enviada e gerencia a concessão de acesso a áreas restritas.
* **`scanner_cliente.py`**: Simula uma ferramenta de diagnóstico legítima (ou o vetor de testes). Conecta-se à ECU, recebe o *seed*, calcula a chave matemática correspondente e solicita a autorização de acesso.

---

## 🔬 Cenários Analisados na Pesquisa

O objetivo prático deste repositório é demonstrar o contraste entre uma rede automotiva vulnerável e uma protegida:

1. **Cenário 1: Texto Plano (Sem Criptografia / Vulnerável)**
   * A comunicação ocorre localmente (`127.0.0.1`).
   * *Vulnerabilidade:* O tráfego de *Seed & Key* via TCP fica exposto em texto plano, permitindo que ferramentas de *sniffing* (como o Wireshark) interceptem e leiam credenciais de acesso em tempo real.
2. **Cenário 2: Túnel Criptografado (Mitigação via Tailscale / WireGuard)**
   * A comunicação é encapsulada através de uma rede privada virtual (Tailscale).
   * *Mitigação:* O protocolo WireGuard cifra o tráfego de ponta a ponta na camada de rede, tornando o conteúdo interno dos pacotes completamente ilegível para um atacante com *sniffer*.

---

## Como Executar

### Pré-requisitos
* **Python 3.x** instalado.
* **Wireshark** instalado (para captura e análise dos pacotes).
* **Tailscale** instalado (opcional, para testar o cenário de mitigação segura).

---

### Passo 1: Iniciar a ECU (Servidor)
Abra um terminal na máquina (ou aba) que atuará como servidor e execute:
```bash
python ecu_servidor.py
