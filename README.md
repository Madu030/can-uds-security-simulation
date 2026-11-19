## Artigo científico

O artigo completo deste projeto está disponível em:
(https://docs.google.com/document/d/16vbgCa-OnJbbGAQP6PJKmqucJkxPfO-PTWZb8clTsrg/edit?usp=sharing)

# Simulação de Cibersegurança Automotiva — UDS 0x27 + E2EE + IA (IDS e Fuzzer)

Simulação acadêmica e reprodutível de segurança em redes automotivas sobre o
protocolo **UDS / ISO 14229 (SecurityAccess, serviço 0x27)**, combinando:

- **Seed & Key** (desafio-resposta com algoritmo proprietário secreto, estilo OEM);
- **Criptografia de ponta a ponta (E2EE)** na camada de aplicação com **AES-Fernet**;
- **Segurança de rede** opcional via **Tailscale/WireGuard** (perímetro);
- **IA defensiva** — IDS híbrido (regras ISO 14229 + *Isolation Forest*);
- **IA ofensiva** — *fuzzer* generativo/evolutivo guiado por *bandit*.

Isto estende o protótipo original (`ecu_servidor.py` ↔ `scanner_cliente.py`, porta
5001) com os dois módulos de IA que faltavam e com um arcabouço de experimentos
que gera as métricas e figuras do artigo.

> **Uso restrito a este ambiente simulado, de sua propriedade.** A ECU, as falhas
> e os ataques são sintéticos, para pesquisa e ensino. Não aponte estas
> ferramentas a veículos, ECUs ou redes reais.

---

## 1. Arquitetura

```
 scanner_cliente.py            rede TCP:5001                 ecu_servidor.py
 fuzzer_ia.py        ──────────────────────────────────▶    ┌──────────────┐
 (técnico / atacante)      quadro = [4B tamanho][token]      │  Canal E2EE  │  protocolo.py
                           token = Fernet(AES-128-CBC+HMAC)  │  (decifra)   │
                                                             ├──────────────┤
                                                             │     IDS      │  ids.py
                                                             │ regras + ML  │
                                                             ├──────────────┤
                                                             │   ECU UDS    │  ecu_core.py
                                                             │  (ISO 14229) │
                                                             └──────────────┘
```

| Arquivo | Papel |
|---|---|
| `protocolo.py` | Transporte TCP com enquadramento + E2EE AES-Fernet (desligável). |
| `ecu_core.py` | Lógica UDS pura (0x10/11/14/22/27/2E/31/3E), NRCs, Seed & Key (algoritmo secreto `SEGREDO_CHAVE` + XOR/rotações/mistura), bugs plantados. |
| `ids.py` | IDS híbrido: 4 regras de assinatura + *Isolation Forest* (anomalia). |
| `fuzzer_ia.py` | *Fuzzer* IA: modelo gerativo de Markov + *bandit* UCB1 + corpus evolutivo + modo evasivo. |
| `trafego.py` | Perfis de tráfego (oficina legítima / ataques) e simulador com relógio virtual. |
| `ecu_servidor.py` | Servidor da ECU na rede (porta 5001) com E2EE + IDS. |
| `scanner_cliente.py` | Ferramenta de diagnóstico e cenários de ataque pela rede. |
| `experimentos.py` | Roda os 3 experimentos e gera `resultados/` (JSON, tabelas, figuras). |

---

## 2. Como executar

### 2.1 Demonstração pela rede (two terminais)

```bash
# Terminal 1 — ECU (E2EE + IDS ligados). Na 1ª vez treina o IDS (~10 s).
python src/ecu_servidor.py

# Terminal 2 — sessão de diagnóstico legítima
python src/scanner_cliente.py
#   >> 10 03  << 50 03...     (sessão estendida)
#   >> 27 01  << 67 01 <seed> (requestSeed)
#   >> 27 02 <key> << 67 02   (AUTORIZADO)
```

Modo interativo (digite requisições em hexa; `key` resolve o último seed):

```bash
python src/scanner_cliente.py --modo interativo
```

### 2.2 Linha de base em texto claro (para o Wireshark)

```bash
python src/ecu_servidor.py  --sem-cripto --sem-ids
python src/scanner_cliente.py --sem-cripto
```

### 2.3 Ataques e defesa

```bash
python src/scanner_cliente.py --modo forca-bruta   # IDS bloqueia e derruba a conexão
python src/scanner_cliente.py --modo sem-chave      # tokens forjados: regra R2 do IDS
python src/fuzzer_ia.py --modo ia --n 2000          # fuzzer IA (use --vulneravel na ECU)
python src/fuzzer_ia.py --modo ia --evasivo --n 500 # fuzzer que tenta driblar o IDS
```

ECU vulnerável (com as falhas plantadas, para o fuzzer encontrar):

```bash
python src/ecu_servidor.py --vulneravel --sem-ids
```

> Pela rede, o *fuzzer* acha as falhas rasas (BUG-1/BUG-2). A falha profunda
> (BUG-3) exige a instrumentação de cobertura, disponível no modo experimento
> (`experimentos.py`), não no modo rede.

### 2.4 Reproduzir todos os resultados do artigo

```bash
python src/experimentos.py       # ~3–5 min; grava resultados/ (figuras + tabelas)
```

Dependências: `pip install cryptography scikit-learn numpy matplotlib`.

---

## 3. Captura de evidências no Wireshark (passo a passo)

Objetivo: comprovar que a E2EE elimina o *sniffing* em texto claro na porta 5001.

1. Abra o Wireshark e capture na interface **Loopback / lo** (ou `adapter for
   loopback`). Filtro de exibição: `tcp.port == 5001`.
2. **Caso A — vulnerável (texto claro):** rode a seção 2.2 e uma sessão legítima.
   Clique num pacote → *Follow → TCP Stream*. Você verá os bytes UDS legíveis
   (`10 03`, `27 01`, o *seed*, `27 02`, a *key*, e o VIN `9BWZZZ...` em ASCII).
   **Print 1:** o *stream* com SEED/KEY/VIN expostos.
3. **Caso B — protegido (E2EE):** rode a seção 2.1 (com cripto) e repita a sessão.
   No mesmo *Follow TCP Stream* o conteúdo agora é o token Fernet (base64/binário,
   começando por `gAAAAA...`), sem nenhum campo UDS reconhecível.
   **Print 2:** o mesmo fluxo, agora ilegível.
4. **Print 3 (opcional):** rode `scanner_cliente.py --modo sem-chave` e mostre no
   log da ECU as mensagens *"token inválido … descartado"* — um atacante dentro da
   rede, sem a chave AES, não consegue injetar comandos (HMAC do Fernet rejeita).

Dica para o artigo: coloque os Prints 1 e 2 lado a lado (mesma requisição `27 01`),
legendando os offsets onde o *seed* aparece em claro (A) e some sob a cifra (B).

---

## 4. Falhas plantadas na ECU (`--vulneravel`)

Servem como *verdade de referência* para avaliar o fuzzer. As duas imitam classes
de falha reais em implementações de UDS:

- **BUG-1 — leitura fora do limite no parser de `0x22`** (lista de DIDs de tamanho
  ímpar). Falha de *parsing* rasa.
- **BUG-2 — estouro de buffer no `optionRecord` de `0x31`**, analisado **antes** da
  verificação de SecurityAccess (falha rasa, pré-autenticação). É o análogo direto da
  **CVE-2026-54413** (leitura fora do limite no `Handle_0x27_SecurityAccess` da
  biblioteca `iso14229`, por falta de checagem de tamanho antes de indexar o
  *buffer*), o que ancora a simulação em um caso do mundo real de 2026.
- **BUG-3 — falha PROFUNDA atrás de um portão de bytes mágicos.** Uma rotina de
  fábrica não documentada (RID `0x0A55` + assinatura `DE AD`) só é alcançada quando
  os bytes mágicos são reconstruídos na ordem exata; além dela há um estouro. A
  comparação é desenrolada, de modo que cada byte correto abre uma linha de código
  nova. Mutar às cegas não acumula esse progresso — por isso **só o fuzzer guiado por
  cobertura (greybox) a encontra**; o aleatório e a mutação cega, não.

---

## 5. O IDS híbrido (IA defensiva)

**Camada de regras (assinaturas, ISO 14229 / ISO 21434):** R1 força bruta no
`27 02` por janela de tempo; R2 falhas repetidas de decifragem/HMAC; R3 qualquer
travamento provocado por um cliente; R4 inundação acima da taxa física.

**Camada de ML (anomalia, não supervisionada):** *Isolation Forest* treinado **só**
com tráfego legítimo de oficina, sobre 13 atributos por janela deslizante (taxa,
regularidade dos intervalos, frações de NRCs, diversidade de SIDs, entropia dos
bytes, etc.). Por nunca ver ataques no treino, detecta ataques inéditos; um alerta
exige 2 janelas anômalas consecutivas (reduz falsos positivos).

**Por que a camada de ML é indispensável (dia-zero):** o perfil
`perfil_exfiltracao_furtiva` é uma **exfiltração furtiva** — o atacante autentica
normalmente e drena dados lendo DIDs de forma lenta e robótica. Não é força bruta,
nem inundação, nem token adulterado, nem causa travamento, então **nenhuma das
quatro regras dispara** (detecção 0%). O que o denuncia é estatístico — a cadência
regular e a monotonia das operações —, e **só a camada de ML o detecta** (ver
resultados).

Identidade do cliente = IP de origem; ao alertar, o IDS bloqueia o cliente por
60 s e registra em `alertas_ids.csv`.

---

## 6. O fuzzer guiado por IA (IA ofensiva)

- **Guiado por cobertura (greybox, estilo AFL):** a ECU é instrumentada e cada
  requisição que abre **código novo** vira fronteira e é priorizada. Um estágio
  **determinístico** varre, posição a posição, cada byte do cabeçalho por todos os
  256 valores — é o que quebra "bytes mágicos" sem conhecê-los (cada byte do portão
  cai em ≤256 tentativas). Este é o mecanismo que encontra o BUG-3.
- **Gerativo:** modelo de Markov de ordem 2 sobre *bytes*, re-treinado com o material
  recente — gera mensagens plausíveis, porém inéditas (fase de exploração).
- **Adaptativo:** *bandit* UCB1 escolhe o operador de mutação na exploração,
  recompensado por **cobertura nova** e por **crashes**.
- **Evasivo (adversarial):** controla ritmo e tráfego de cobertura conforme o
  retorno "fui bloqueado?", para medir o custo imposto pelo IDS.

Comparado contra linhas de base `aleatorio` e `mutacao` (mutação cega).

---

## 7. Resultados (resumo — ver `resultados/`)

- **Falhas rasas (BUG-1/2):** mutação cega e IA acham as duas; o aleatório fica em
  ~60 linhas e nunca acha a BUG-1. Na BUG-2, a mutação cega é até mais rápida — a IA
  "paga" por buscar em profundidade.
- **Falha profunda (BUG-3):** **só o fuzzer IA (greybox) a encontra** (maioria das
  execuções); aleatório e mutação cega **nunca** (0/8). É o ganho que justifica a IA
  ofensiva — ela vence onde o método simples trava.
- **Detecção furtiva (dia-zero):** as regras **não detectam** a exfiltração furtiva
  (0%); **só a camada de ML** a pega (100%), a ~0,8% de falsos positivos. É o ganho
  que justifica a IA defensiva.
- **Adversarial:** contra o IDS híbrido com bloqueio, o fuzzer evasivo é estrangulado
  de ~13 para <0,1 teste/min — o IDS eleva drasticamente o custo do ataque.

---

## 8. Referências principais

1. RAJAPAKSHA, S. et al. *AI-Based Intrusion Detection Systems for In-Vehicle Networks: A Survey.* ACM Computing Surveys, v. 55, n. 11, 2023. doi:10.1145/3570954.
2. LUO, F. et al. *In-vehicle network intrusion detection systems: a systematic survey of deep learning-based approaches.* PeerJ Computer Science, v. 9, e1648, 2023.
3. BARI, B. S.; YELAMARTHI, K.; GHAFOOR, S. *Intrusion Detection in Vehicle CAN Bus Using Machine Learning.* Sensors, v. 23, n. 7, 3610, 2023.
4. TANKSALE, V. *Intrusion detection system for controller area network.* Cybersecurity, v. 7, art. 4, 2024.
5. SAMIR, S. B. H. et al. *ML-Based Intrusion Detection for Securing In-Vehicle CAN Bus Communication.* SN Computer Science, v. 5, art. 1082, 2024.
6. KHAN, M. H. et al. *DivaCAN: Detecting in-vehicle intrusion attacks using ensemble learning.* Computers & Security, v. 139, 103712, 2024.
7. KANG, H. et al. *CANival: A multimodal approach to intrusion detection on the vehicle CAN bus.* Vehicular Communications, v. 50, 100845, 2024.
8. MICALE, D. et al. *A context-aware on-board intrusion detection system for smart vehicles.* Int. J. Inf. Sec., v. 23, 2024.
9. ZHANG, Y. et al. *Federated two-stage transformer-based network for intrusion detection in non-IID data of CAN.* Cybersecurity, v. 8, art. 29, 2025.
10. USMAN, Y. et al. *The Dark Side of AI: LLMs as Tools for Cyber Attacks on Vehicle Systems.* IEEE UEMCON, 2024.
11. ISO 14229-1:2020 — *Road vehicles — Unified Diagnostic Services (UDS) — Part 1.*
12. ISO/SAE 21434:2021 — *Road vehicles — Cybersecurity engineering.*
