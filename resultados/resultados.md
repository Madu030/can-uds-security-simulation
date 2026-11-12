# Resultados dos experimentos

Repetições por cenário: 12 (evasão: 10).

## 1. IDS — taxa de detecção (sessões) / requisições até o 1º alerta (mediana)

| Ataque | Só regras | Só ML | Híbrido |
|---|---|---|---|
| Força bruta (rápida) | 0% / – req | 100% / 7.0 req | 100% / 7.0 req |
| Força bruta (lenta/evasiva) | 100% / 25.0 req | 100% / 7.0 req | 100% / 7.0 req |
| Varredura de serviços | 100% / 10.0 req | 100% / 7.0 req | 100% / 7.0 req |
| Varredura de DIDs | 100% / 10.0 req | 100% / 7.0 req | 100% / 7.0 req |
| Tokens forjados (sem chave) | 100% / 3.0 req | 100% / 7.0 req | 100% / 3.0 req |
| Exfiltração furtiva (dia-zero) | 0% / – req | 100% / 7.0 req | 100% / 7.0 req |
| Fuzzing IA (agressivo) | 100% / 10.0 req | 100% / 7.0 req | 100% / 7.0 req |
| Fuzzing mutação (1 req/s) | 100% / 75.0 req | 100% / 7.0 req | 100% / 7.0 req |
| **Falsos positivos (por evento)** | 0.00% | 1.85% | 1.85% |
| **Oficinas legítimas com ≥1 alerta** | 0.0% | 26.4% | 26.4% |

## 2. Fuzzer — cobertura e descoberta de falhas (ECU vulnerável)

BUG-1/BUG-2 = falhas rasas; BUG-3 = falha profunda atrás de um portão de bytes mágicos.

| Estratégia | Linhas (média) | BUG-1 (achado/mediana) | BUG-2 | BUG-3 (profunda) |
|---|---|---|---|---|
| Aleatório (blackbox) | 62.5 | 0/8 / – | 8/8 / 602 | 0/8 / – |
| Mutação cega (blackbox) | 112.6 | 8/8 / 53 | 8/8 / 169 | 0/8 / – |
| IA (greybox, guiado por cobertura) | 111.5 | 8/8 / 448 | 8/8 / 271 | 6/8 / 12704 |

## 3. Adversarial — fuzzer agressivo x evasivo contra o IDS com bloqueio

| Cenário | Testes entregues | Minutos | Testes/min | Alertas | Bugs distintos |
|---|---|---|---|---|---|
| Só regras vs fuzzer agressivo | 300 | 18.3 | 16.44 | 16.8 | 0.7 |
| Só regras vs fuzzer evasivo | 300 | 1.9 | 157.86 | 1.2 | 0.6 |
| Híbrido vs fuzzer agressivo | 55.8 | 359.7 | 0.16 | 333 | 0.2 |
| Híbrido vs fuzzer evasivo | 37.8 | 359.7 | 0.11 | 196 | 0.1 |
