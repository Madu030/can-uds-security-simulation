"""
experimentos.py - Gera todas as métricas e figuras do artigo (reprodutível).

  python experimentos.py            # ~1-2 min; resultados em ./resultados/

Experimento 1 - IDS: detecção por tipo de ataque e ablação (regras x ML x híbrido)
Experimento 2 - Fuzzer: cobertura real de código da ECU e falhas encontradas
                (aleatório x mutação cega x IA)
Experimento 3 - Adversarial: fuzzer agressivo x fuzzer evasivo contra o IDS
"""
import json
import os
import random
import statistics as st
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

import ecu_core
from ecu_core import ECU, FalhaECU
from fuzzer_ia import FuzzerIA, perfil_fuzzer_evasivo
from ids import IDS
from trafego import (Simulador, gerar_trafego_normal, perfil_exfiltracao_furtiva,
                     perfil_forca_bruta, perfil_forca_bruta_lenta, perfil_fuzzer,
                     perfil_sem_chave, perfil_varredura_dids, perfil_varredura_servicos,
                     sessoes_normais)

SAIDA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "resultados")
N_REP = 12        # repetições por cenário (IDS, evasão)
N_REP_FZ = 8     # repetições do fuzzer (instrumentação por cobertura é mais cara)
CORES = ["#2a78d6", "#eb6834", "#1baf7a"]        # paleta categórica validada (azul, laranja, água)
TINTA, TINTA2, GRADE = "#0b0b0b", "#52514e", "#e4e3df"

plt.rcParams.update({
    "font.size": 10, "axes.edgecolor": TINTA2, "axes.labelcolor": TINTA,
    "xtick.color": TINTA2, "ytick.color": TINTA2, "axes.spines.top": False,
    "axes.spines.right": False, "axes.grid": True, "grid.color": GRADE,
    "grid.linewidth": 0.6, "figure.dpi": 150, "savefig.bbox": "tight",
})

ATAQUES = {
    "Força bruta (rápida)": lambda r: perfil_forca_bruta(r),
    "Força bruta (lenta/evasiva)": lambda r: perfil_forca_bruta_lenta(r),
    "Varredura de serviços": lambda r: perfil_varredura_servicos(r),
    "Varredura de DIDs": lambda r: perfil_varredura_dids(r),
    "Tokens forjados (sem chave)": lambda r: perfil_sem_chave(r),
    "Exfiltração furtiva (dia-zero)": lambda r: perfil_exfiltracao_furtiva(r),
    "Fuzzing IA (agressivo)": lambda r: perfil_fuzzer(FuzzerIA("ia", r.randint(0, 9999)), 500),
    "Fuzzing mutação (1 req/s)": lambda r: perfil_fuzzer(FuzzerIA("mutacao", r.randint(0, 9999)), 300, atraso=1.0),
}
CONFIGS = {"Só regras": dict(usar_ml=False), "Só ML": dict(usar_regras=False), "Híbrido": {}}


def treinar_base():
    return gerar_trafego_normal(semente=1, n_clientes=20, sessoes_por_cliente=30)


# ===================================================================== EXP 1
def exp_ids(normais):
    res = {}
    for nome_cfg, kw in CONFIGS.items():
        ids = IDS(bloquear=False, **kw)
        ids.treinar(normais)
        res[nome_cfg] = {}
        fp_ev = n_ev = fp_cli = n_cli = 0
        for ataque, fab in ATAQUES.items():
            det, lat_req, lat_t, tpr = 0, [], [], []
            for rep in range(N_REP):
                rng = random.Random(1000 + rep)
                ids.resetar_clientes()
                ses = sessoes_normais(rng, 6, 5)
                ses.append((rng.uniform(30, 200), "atacante", 1, fab(rng)))
                sim = Simulador(lambda: ECU(vulneravel=True, rng=random.Random(rng.random())), ids)
                regs = sim.executar(ses)
                at = [(e, a) for e, r, a, _ in regs if r == 1]
                idx = next((i for i, (e, a) in enumerate(at) if a), None)
                if idx is not None:
                    det += 1
                    lat_req.append(idx + 1)
                    lat_t.append(at[idx][0].t - at[0][0].t)
                tpr.append(sum(1 for _, a in at if a) / len(at))
                normais_ev = [(e, a) for e, r, a, _ in regs if r == 0]
                fp_ev += sum(1 for _, a in normais_ev if a); n_ev += len(normais_ev)
                clis = {e.cliente for e, _ in normais_ev}
                n_cli += len(clis); fp_cli += len({e.cliente for e, a in normais_ev if a})
            res[nome_cfg][ataque] = {
                "taxa_deteccao": det / N_REP,
                "req_ate_deteccao_mediana": st.median(lat_req) if lat_req else None,
                "seg_ate_deteccao_mediana": round(st.median(lat_t), 2) if lat_t else None,
                "tpr_por_evento": round(st.mean(tpr), 4),
            }
        res[nome_cfg]["_falsos_positivos"] = {
            "fpr_por_evento": round(fp_ev / n_ev, 4),
            "frac_clientes_legitimos_com_alerta": round(fp_cli / n_cli, 4),
            "eventos_legitimos_avaliados": n_ev,
        }
    return res


def fig_ids(res):
    ataques = list(ATAQUES)
    fig, ax = plt.subplots(figsize=(8, 4.2))
    y = np.arange(len(ataques))
    h = 0.26
    for i, (cfg, cor) in enumerate(zip(CONFIGS, CORES)):
        v = [res[cfg][a]["tpr_por_evento"] * 100 for a in ataques]
        ax.barh(y + (i - 1) * h, v, h - 0.04, color=cor, label=cfg)
    ax.set_yticks(y, ataques)
    ax.invert_yaxis()
    ax.set_xlim(0, 100)
    ax.set_xlabel("Requisições maliciosas sinalizadas (%)")
    ax.grid(axis="y", visible=False)
    fpr = " | ".join(f"{c}: {res[c]['_falsos_positivos']['fpr_por_evento'] * 100:.2f}%" for c in CONFIGS)
    ax.set_title(f"Detecção por tipo de ataque e componente do IDS\nFalsos positivos (por evento) — {fpr}",
                 fontsize=10, color=TINTA, loc="left")
    ax.legend(frameon=False, loc="lower right")
    fig.savefig(os.path.join(SAIDA, "fig1_ids_deteccao.png"))
    plt.close(fig)


# ===================================================================== EXP 2
ARQ_ECU = os.path.abspath(ecu_core.__file__)


def _rodar_fuzzer(modo, semente, n):
    """Harness de fuzzing GUIADO POR COBERTURA (greybox): instrumenta a ECU com
    settrace e, a cada requisição, informa ao fuzzer quantas linhas NOVAS foram
    cobertas. Só o modo 'ia' consome esse sinal; 'aleatorio' e 'mutacao' são
    blackbox (ignoram a cobertura). A cobertura é medida para os três, para a curva."""
    coberto, linhas_turno = set(), []

    def rastro_local(frame, ev, arg):
        if ev == "line":
            linhas_turno.append(frame.f_lineno)
        return rastro_local

    def rastro(frame, ev, arg):
        return rastro_local if frame.f_code.co_filename == ARQ_ECU else None

    guiado = (modo == "ia")
    fz = FuzzerIA(modo, semente)
    ecu = ECU(vulneravel=True, rng=random.Random(semente))
    curva, primeiro = [], {}
    passo = max(1, n // 60)
    for _ in range(n):
        req = fz.proximo()
        linhas_turno.clear()
        sys.settrace(rastro)
        crash = False
        try:
            resp = ecu.processar(req, 0.0)
        except FalhaECU as ex:
            crash, resp = True, b""
            primeiro.setdefault(str(ex)[:5], fz.n_testes + 1)
            ecu.reiniciar()
        sys.settrace(None)
        novas = len(set(linhas_turno) - coberto)
        coberto |= set(linhas_turno)
        fz.feedback(req, resp, crash=crash, cobertura_nova=(novas if guiado else 0))
        if fz.n_testes % passo == 0:
            curva.append((fz.n_testes, len(coberto)))
    return curva, primeiro, len(coberto)


def exp_fuzzer(n=18000):
    bugs = ("BUG-1", "BUG-2", "BUG-3")
    res, curvas = {}, {}
    for modo in ("aleatorio", "mutacao", "ia"):
        cs, achados, cobs = [], {b: [] for b in bugs}, []
        for s in range(N_REP_FZ):
            c, prim, cob = _rodar_fuzzer(modo, s, n)
            cs.append(c); cobs.append(cob)
            for b in bugs:
                achados[b].append(prim.get(b))
        curvas[modo] = cs
        res[modo] = {"linhas_cobertas_final_media": round(float(np.mean(cobs)), 1)}
        for b in bugs:
            ok = [x for x in achados[b] if x is not None]
            res[modo][b] = {"encontrado_em": f"{len(ok)}/{N_REP_FZ}",
                            "testes_ate_encontrar_mediana": int(st.median(ok)) if ok else None}
    return res, curvas


def fig_fuzzer(curvas):
    nomes = {"aleatorio": "Aleatório (blackbox)", "mutacao": "Mutação cega (blackbox)",
             "ia": "IA — greybox guiado por cobertura"}
    fig, ax = plt.subplots(figsize=(7, 3.8))
    for (modo, reps), cor in zip(curvas.items(), CORES):
        L = min(len(c) for c in reps)
        x = np.array([reps[0][i][0] for i in range(L)])
        M = np.array([[c[i][1] for i in range(L)] for c in reps])
        m, lo, hi = M.mean(0), np.percentile(M, 10, 0), np.percentile(M, 90, 0)
        ax.fill_between(x, lo, hi, color=cor, alpha=0.15, linewidth=0)
        ax.plot(x, m, color=cor, lw=2, label=nomes[modo])
    ax.set_xscale("log")
    ax.set_xlabel("Casos de teste enviados (escala log)")
    ax.set_ylabel("Linhas da ECU executadas")
    ax.set_title(f"Cobertura de código da ECU por estratégia de fuzzing (média e faixa P10–P90, {N_REP_FZ} execuções)",
                 fontsize=10, color=TINTA, loc="left")
    ax.legend(frameon=False, loc="upper left")
    fig.savefig(os.path.join(SAIDA, "fig2_fuzzer_cobertura.png"))
    plt.close(fig)


# ===================================================================== EXP 3
def exp_evasao(normais, n_testes=300, t_max=6 * 3600):
    res = {}
    for nome_cfg, kw in (("Só regras", dict(usar_ml=False)), ("Híbrido", {})):
        ids = IDS(bloquear=True, **kw)
        ids.treinar(normais)
        for estrategia in ("agressivo", "evasivo"):
            entregues, duracoes, alertas, bugs = [], [], [], []
            for rep in range(10):
                ids.resetar_clientes()
                fz = FuzzerIA("ia", rep)
                if estrategia == "agressivo":
                    def gen(fz=fz):
                        # agressivo: reconecta e insiste após cada bloqueio
                        from trafego import BLOQUEADO, CRASH
                        while fz.n_testes < n_testes:
                            req = fz.proximo()
                            resp = yield 0.01, req
                            if resp is BLOQUEADO:
                                yield 65.0, b"\x3E\x00"
                                continue
                            fz.feedback(req, resp, crash=resp is CRASH)
                    g = gen()
                else:
                    g = perfil_fuzzer_evasivo(fz, n_testes)
                sim = Simulador(lambda: ECU(vulneravel=True, rng=random.Random(rep)), ids)
                regs = sim.executar([(0, "atacante", 1, g)], t_max=t_max)
                at = [e for e, r, a, b in regs if r == 1]
                entregues.append(fz.n_testes)
                duracoes.append((at[-1].t - at[0].t) / 60 if at else 0)
                alertas.append(len(ids.alertas))
                bugs.append(len({c[3][:5] for c in sim.crashes}))
            res[f"{nome_cfg} vs fuzzer {estrategia}"] = {
                "testes_entregues_media": round(st.mean(entregues), 1),
                "minutos_simulados_media": round(st.mean(duracoes), 1),
                "testes_por_minuto": round(st.mean(entregues) / max(st.mean(duracoes), 1e-9), 2),
                "alertas_media": round(st.mean(alertas), 1),
                "bugs_distintos_media": round(st.mean(bugs), 2),
            }
    return res


# ====================================================================== main
def tabela_md(res_ids, res_fz, res_ev):
    L = ["# Resultados dos experimentos\n", f"Repetições por cenário: {N_REP} (evasão: 10).\n",
         "## 1. IDS — taxa de detecção (sessões) / requisições até o 1º alerta (mediana)\n",
         "| Ataque | " + " | ".join(CONFIGS) + " |", "|---|" + "---|" * len(CONFIGS)]
    for a in ATAQUES:
        cel = []
        for c in CONFIGS:
            r = res_ids[c][a]
            cel.append(f"{r['taxa_deteccao'] * 100:.0f}% / {r['req_ate_deteccao_mediana'] or '–'} req")
        L.append(f"| {a} | " + " | ".join(cel) + " |")
    L.append("| **Falsos positivos (por evento)** | " + " | ".join(
        f"{res_ids[c]['_falsos_positivos']['fpr_por_evento'] * 100:.2f}%" for c in CONFIGS) + " |")
    L.append("| **Oficinas legítimas com ≥1 alerta** | " + " | ".join(
        f"{res_ids[c]['_falsos_positivos']['frac_clientes_legitimos_com_alerta'] * 100:.1f}%" for c in CONFIGS) + " |")
    nomes_fz = {"aleatorio": "Aleatório (blackbox)", "mutacao": "Mutação cega (blackbox)",
                "ia": "IA (greybox, guiado por cobertura)"}
    L += ["\n## 2. Fuzzer — cobertura e descoberta de falhas (ECU vulnerável)\n",
          "BUG-1/BUG-2 = falhas rasas; BUG-3 = falha profunda atrás de um portão de bytes mágicos.\n",
          "| Estratégia | Linhas (média) | BUG-1 (achado/mediana) | BUG-2 | BUG-3 (profunda) |",
          "|---|---|---|---|---|"]
    for m, r in res_fz.items():
        def cel(b):
            x = r[b]
            return f"{x['encontrado_em']} / {x['testes_ate_encontrar_mediana'] or '–'}"
        L.append(f"| {nomes_fz[m]} | {r['linhas_cobertas_final_media']} | "
                 f"{cel('BUG-1')} | {cel('BUG-2')} | {cel('BUG-3')} |")
    L += ["\n## 3. Adversarial — fuzzer agressivo x evasivo contra o IDS com bloqueio\n",
          "| Cenário | Testes entregues | Minutos | Testes/min | Alertas | Bugs distintos |", "|---|---|---|---|---|---|"]
    for k, r in res_ev.items():
        L.append(f"| {k} | {r['testes_entregues_media']} | {r['minutos_simulados_media']} | "
                 f"{r['testes_por_minuto']} | {r['alertas_media']} | {r['bugs_distintos_media']} |")
    return "\n".join(L) + "\n"


def main():
    os.makedirs(SAIDA, exist_ok=True)
    print("Gerando tráfego legítimo de treino...")
    normais = treinar_base()
    print(f"  {len(normais)} eventos legítimos")
    print("Exp. 1: IDS..."); r1 = exp_ids(normais); fig_ids(r1)
    print("Exp. 2: fuzzer..."); r2, curvas = exp_fuzzer(); fig_fuzzer(curvas)
    print("Exp. 3: evasão..."); r3 = exp_evasao(normais)
    with open(os.path.join(SAIDA, "resultados.json"), "w", encoding="utf-8") as f:
        json.dump({"ids": r1, "fuzzer": r2, "evasao": r3}, f, ensure_ascii=False, indent=2)
    md = tabela_md(r1, r2, r3)
    with open(os.path.join(SAIDA, "resultados.md"), "w", encoding="utf-8") as f:
        f.write(md)
    print(md)


if __name__ == "__main__":
    main()
