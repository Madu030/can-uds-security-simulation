# Levantamento Bibliográfico Inicial: IA e Cibersegurança Automotiva

> **Documento de Trabalho para Orientação Acadêmica**  
> **Objetivo:** Mapeamento da literatura técnico-científica, delimitação do problema e fundamentação do experimento prático.  
> **Status:** Triagem bibliográfica inicial (Análise exploratória de registros e resumos).

---

## Sumário
1. [Visão Geral e Matriz do Mapeamento](#1-visão-geral-e-matriz-do-mapeamento)
2. [Síntese Transversal da Literatura](#2-síntese-transversal-da-literatura)
3. [Fichas Bibliográficas Detalhadas](#3-fichas-bibliográficas-detalhadas)
   * [Eixo 1: IA Defensiva e Detecção de Intrusão (IDS)](#eixo-1-ia-defensiva-e-detecção-de-intrusão-ids)
   * [Eixo 2: IA como Vetor Ofensivo / Testes de Segurança](#eixo-2-ia-como-vetor-ofensivo--testes-de-segurança)
4. [Alinhamento do Experimento Prático & Justificativa](#4-alinhamento-do-experimento-prático--justificativa)
5. [Pauta e Dúvidas para Reunião com Orientador](#5-pauta-e-dúvidas-para-reunião-com-orientador)
6. [Referências Metodológicas](#6-referências-metodológicas)

---

## 1. Visão Geral e Matriz do Mapeamento

A seleção abrange 10 artigos relevantes publicados entre **2023 e 2025**, divididos em dois eixos centrais de pesquisa:

| Nº | Título Abreviado | Eixo Temático | Foco Técnico | Acesso |
|:--:|:-----------------|:-------------|:-------------|:------:|
| **01** | *AI-Based IDS for In-Vehicle Networks: A Survey* | IA Defensiva | Revisão / CAN | 🔓 Aberto |
| **02** | *Deep Learning In-Vehicle Network IDS* | IA Defensiva | Deep Learning / CAN | 🔓 Aberto |
| **03** | *CAN Bus Intrusion Detection Using ML* | IA Defensiva | ML Clássico (SVM, KNN) | 🔓 Aberto |
| **04** | *Intrusion Detection System for CAN* | IA Defensiva | Análise Temporal / CAN | 🔓 Aberto |
| **05** | *ML-Based Intrusion Detection for CAN Bus* | IA Defensiva | CNN + LSTM / ICSim | 🔓 Aberto |
| **06** | *DivaCAN: Ensemble Learning for CAN IDS* | IA Defensiva | Ensemble Learning | 🔒 Restrito |
| **07** | *CANival: Multimodal Approach for CAN IDS* | IA Defensiva | Multimodal / Sinais | 🔓 Aberto |
| **08** | *Context-Aware On-Board IDS for Smart Vehicles* | IA Defensiva | Análise de Contexto | 🔓 Aberto |
| **09** | *Federated Two-Stage Transformer-Based IDS* | IA Defensiva | Transformers / FedLearned | 🔓 Aberto |
| **10** | *The Dark Side of AI: LLMs as Attack Tools* | IA Ofensiva | LLMs / HackerGPT / UDS | 🔒 Restrito |

---

## 2. Síntese Transversal da Literatura

```
                  ┌──────────────────────────────────────────────┐
                  │   CIBERSEGURANÇA AUTOMOTIVA & INTELIGÊNCIA   │
                  └──────────────────────┬───────────────────────┘
                                         │
                 ┌───────────────────────┴───────────────────────┐
                 ▼                                               ▼
  ┌─────────────────────────────┐                 ┌─────────────────────────────┐
  │     EIXO Defensivo (IDS)    │                 │    EIXO Ofensivo / Testes   │
  │  - Foco: CAN Bus & Anomalia │                 │  - Foco: LLMs / Automação   │
  │  - Falsos Positivos & Noise │                 │  - Geração de Casos de Teste│
  └──────────────┬──────────────┘                 └──────────────┬──────────────┘
                 │                                               │
                 └──────────────────────┬────────────────────────┘
                                        ▼
                  ┌──────────────────────────────────────────────┐
                  │          LACUNA / OPORTUNIDADE              │
                  │ Integração de Segurança de Rede (VPN/VPNs)   │
                  │ com Avaliação Criptográfica em Camada UDS   │
                  └──────────────────────────────────────────────┘
```

* **Predominância em Redes Internas (CAN):** A esmagadora maioria dos trabalhos foca no barramento CAN (*Controller Area Network*), analisando anomalias de frequência, id de mensagens e payload.
* **Técnicas Empregadas:** Evolução notável de algoritmos clássicos (SVM, KNN) para arquiteturas profundas (CNN, LSTM) e recentemente Transformers com Aprendizado Federado (2025).
* **Desafio Central:** Alta taxa de falsos positivos e a dependência extrema da qualidade dos conjuntos de dados (*datasets*), que muitas vezes não refletem a complexidade e criptografia das redes automotivas modernas.
* **A Emergência da IA Ofensiva:** Apenas trabalhos recentes (ex: Usman et al., 2024) investigam como Modelos de Linguagem (LLMs) e automação por IA podem ser utilizados para criar vetores de ataque ou identificar vulnerabilidades em protocolos veiculares.

---

## 3. Fichas Bibliográficas Detalhadas

### Eixo 1: IA Defensiva e Detecção de Intrusão (IDS)

#### Artigo 01: AI-Based Intrusion Detection Systems for In-Vehicle Networks: A Survey
* **Referência:** RAJAPAKSHA, S. et al. *AI-Based Intrusion Detection Systems for In-Vehicle Networks: A Survey*. ACM Computing Surveys, v. 55, n. 11, art. 237, 2023.
* **DOI:** [10.1145/3570954](https://doi.org/10.1145/3570954)
* **Link:** [Repositório RGU](https://rgu-repository.worktribe.com/output/1880289/ai-based-intrusion-detection-systems-for-in-vehicle-networks-a-survey)
* **Síntese:** Panorama completo das técnicas de IA aplicadas a redes veiculares. Mapeia tipos de ataques, datasets públicos, métricas de avaliação e discute a própria segurança dos modelos contra ataques adversariais.
* **Relevância para a Pesquisa:** Estabelece a fundamentação teórica sobre o papel defensivo da IA e orienta a escolha de métricas além da simples acurácia.

#### Artigo 02: In-vehicle network intrusion detection systems: deep learning-based approaches
* **Referência:** LUO, F. et al. *In-vehicle network intrusion detection systems: a systematic survey of deep learning-based approaches*. PeerJ Computer Science, v. 9, e1648, 2023.
* **DOI:** [10.7717/peerj-cs.1648](https://doi.org/10.7717/peerj-cs.1648)
* **Link:** [PubMed Central](https://pmc.ncbi.nlm.nih.gov/articles/PMC10703033/)
* **Síntese:** Estudo focado em Deep Learning (DL) para IDS automotivo, analisando trade-offs entre capacidade computacional embarcada e precisão de detecção.
* **Relevância para a Pesquisa:** Oferece subsídio metodológico para discutir limitações do DL e justificar por que mitigações de rede (criptografia) são necessárias antes do IDS.

#### Artigo 03: Intrusion Detection in Vehicle CAN Bus Using Machine Learning
* **Referência:** BARI, B. S.; YELAMARTHI, K.; GHAFOOR, S. *Intrusion Detection in Vehicle Controller Area Network (CAN) Bus Using Machine Learning: A Comparative Performance Study*. Sensors, v. 23, n. 7, 2023.
* **DOI:** [10.3390/s23073610](https://doi.org/10.3390/s23073610)
* **Link:** [MDPI Sensors](https://www.mdpi.com/1424-8220/23/7/3610)
* **Síntese:** Estudo comparativo direto entre SVM, Decision Trees e KNN usando múltiplos datasets automotivos reais.
* **Relevância para a Pesquisa:** Fornece referências de desempenho para algoritmos baseline tradicionais de classificação.

#### Artigo 04: Intrusion detection system for controller area network
* **Referência:** TANKSALE, V. *Intrusion detection system for controller area network*. Cybersecurity, v. 7, art. 4, 2024.
* **DOI:** [10.1186/s42400-023-00195-4](https://doi.org/10.1186/s42400-023-00195-4)
* **Link:** [Springer Link](https://link.springer.com/article/10.1186/s42400-023-00195-4)
* **Síntese:** Proposta de IDS baseada na combinação de parâmetros temporais e contexto operacional do veículo.
* **Relevância para a Pesquisa:** Contribui para a discussão sobre detecção de anomalias temporal no envio de comandos UDS/CAN.

#### Artigo 05: Machine Learning-Based Intrusion Detection for Securing In-Vehicle CAN Bus
* **Referência:** SAMIR, S. B. H. et al. *Machine Learning-Based Intrusion Detection for Securing In-Vehicle CAN Bus Communication*. SN Computer Science, v. 5, art. 1082, 2024.
* **DOI:** [10.1007/s42979-024-03465-1](https://doi.org/10.1007/s42979-024-03465-1)
* **Link:** [Repositório KAUST](https://repository.kaust.edu.sa/server/api/core/bitstreams/921c2669-b4d0-446a-ab13-9652501cdec2/content)
* **Síntese:** Avaliação de arquiteturas CNN e LSTM utilizando simulações geradas pela ferramenta open-source ICSim.
* **Relevância para a Pesquisa:** Serve como modelo de bancada de testes simulada e controlada para reprodução científica.

#### Artigo 06: DivaCAN: Detecting in-vehicle intrusion attacks using ensemble learning
* **Referência:** KHAN, M. H. et al. *DivaCAN: Detecting in-vehicle intrusion attacks on a controller area network using ensemble learning*. Computers & Security, v. 139, art. 103712, 2024.
* **DOI:** [10.1016/j.cose.2024.103712](https://doi.org/10.1016/j.cose.2024.103712)
* **Link:** [ScienceDirect](https://www.sciencedirect.com/science/article/pii/S0167404824000130)
* **Síntese:** Proposta de ensemble learning para redução de falsos positivos na identificação de ataques em redes veiculares.
* **Relevância para a Pesquisa:** Sublinha a importância da taxa de falso-positivo como métrica crítica para viabilidade de soluções em veículos.

#### Artigo 07: CANival: A multimodal approach to intrusion detection on the vehicle CAN bus
* **Referência:** KANG, H. et al. *CANival: A multimodal approach to intrusion detection on the vehicle CAN bus*. Vehicular Communications, v. 50, art. 100845, 2024.
* **DOI:** [10.1016/j.vehcom.2024.100845](https://doi.org/10.1016/j.vehcom.2024.100845)
* **Link:** [ScienceDirect](https://www.sciencedirect.com/science/article/pii/S2214209624001207)
* **Síntese:** Abordagem multimodal que combina timing de mensagens e características físicas do sinal para identificar intrusões.
* **Relevância para a Pesquisa:** Demonstra que defesas de camada única são insuficientes, suportando o argumento da defesa em profundidade.

#### Artigo 08: A context-aware on-board intrusion detection system for smart vehicles
* **Referência:** MICALE, D. et al. *A context-aware on-board intrusion detection system for smart vehicles*. Int. J. Inf. Sec., v. 23, 2024.
* **DOI:** [10.1007/s10207-024-00821-3](https://doi.org/10.1007/s10207-024-00821-3)
* **Link:** [Springer Link](https://link.springer.com/article/10.1007/s10207-024-00821-3)
* **Síntese:** Desenvolve IDS sensível ao estado/contexto de condução do veículo para evitar alarmes falsos em manobras atípicas.
* **Relevância para a Pesquisa:** Fundamenta os limites de ambientes simulados versus a dinâmica real de funcionamento dos veículos.

#### Artigo 09: Federated two-stage transformer-based network for intrusion detection
* **Referência:** ZHANG, Y. et al. *Federated two-stage transformer-based network for intrusion detection in non-IID data of CAN*. Cybersecurity, v. 8, art. 29, 2025.
* **DOI:** [10.1186/s42400-024-00329-2](https://doi.org/10.1186/s42400-024-00329-2)
* **Link:** [Springer Link](https://link.springer.com/article/10.1186/s42400-024-00329-2)
* **Síntese:** Aplicação de Aprendizado Federado com Transformers para detecção de intrusão sem violar a privacidade de dados veiculares descentralizados.
* **Relevância para a Pesquisa:** Demonstra o estado da arte (2025) e a sofisticação crescente das abordagens puramente defensivas baseadas em software.

---

### Eixo 2: IA como Vetor Ofensivo / Testes de Segurança

#### Artigo 10: The Dark Side of AI: LLMs as Tools for Cyber Attacks on Vehicle Systems
* **Referência:** USMAN, Y. et al. *The Dark Side of AI: Large Language Models as Tools for Cyber Attacks on Vehicle Systems*. In: IEEE UEMCON, 2024.
* **DOI:** [10.1109/UEMCON62879.2024.10754676](https://doi.org/10.1109/UEMCON62879.2024.10754676)
* **Link:** [IEEE Xplore](https://ieeexplore.ieee.org/document/10754676/)
* **Síntese:** Examina a utilização de LLMs especializados (ex: HackerGPT) para auxílio na exploração e geração de cenários de ataque contra sistemas automotivos (CAN, Bluetooth e UDS).
* **Relevância para a Pesquisa:** **Artigo-chave de conexão.** Sustenta a discussão da IA no papel ofensivo/testes e destaca a necessidade de mitigações de rede resilientes para conter tais explorações.

---

## 4. Alinhamento do Experimento Prático & Justificativa

  **Ponto de Atenção para Validação Acadêmica**
>
> A literatura correlata foca majoritariamente em **redes CAN puras e ataques no barramento**. Nosso experimento prático atua na camada de aplicação/diagnóstico (**UDS - Seed & Key via TCP**) e na camada de mitigação por criptografia de rede (**Tailscale / WireGuard**).

### Justificativa de Enquadramento
1. **Representatividade de Diagnóstico Distribuído:** Veículos modernos (EVs e SDVs - *Software-Defined Vehicles*) utilizam DoIP (*Diagnostics over IP*) para comunicação UDS via rede TCP/IP, tornando a abstração por sockets perfeitamente alinhada à realidade de mercado.
2. **Defesa em Profundidade:** Enquanto os artigos (01 a 09) tratam de **detecção reativa (IDS)**, o experimento prático foca em **prevenção proativa de interceptação (Criptografia de Rede)**.
3. **Mapeamento Prático do Experimento:**
   * **Cenário A (Vulnerável):** Tráfego UDS em texto plano no *loopback* (`127.0.0.1`), demonstrando a exposição do *Seed* e *Key* a *sniffers* de rede (Wireshark).
   * **Cenário B (Protegido):** Encapuslamento por túnel VPN WireGuard (`Tailscale`), garantindo a confidencialidade do handshake de diagnóstico UDS contra leitura indevida.


---

## 5. Referências Metodológicas

Para sustentação da construção científica e rigor metodológico:

* **POPPER, Karl.** *A lógica da pesquisa científica*. São Paulo: Cultrix, 2013. *(Suporte para a falsifiabilidade das hipóteses de mitigação de segurança)*.
* **SEVERINO, Antônio Joaquim.** *Metodologia do trabalho científico*. 24. ed. São Paulo: Cortez, 2017. *(Estruturação do relatório final e condução da revisão bibliográfica)*.
