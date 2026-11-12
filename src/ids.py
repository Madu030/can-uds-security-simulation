"""
ids.py - IDS híbrido embarcado na ECU (IA defensiva).

Duas camadas complementares:
  1. REGRAS (assinaturas, alinhadas à ISO 14229 / ISO 21434):
       R1 força bruta persistente  - muitas tentativas de sendKey (27 02) na janela temporal
       R2 adulteração de cifra     - falhas de decifragem/HMAC Fernet repetidas
       R3 travamento da ECU        - qualquer crash provocado por um cliente
       R4 inundação                - taxa de requisições acima do limite físico do protocolo
  2. APRENDIZADO DE MÁQUINA (anomalia, não supervisionado):
       Isolation Forest treinado SOMENTE com tráfego legítimo de oficina.
       Cada requisição gera um vetor de 13 atributos calculados sobre a janela
       deslizante das últimas N requisições do mesmo cliente.

Como só tráfego normal é usado no treino, o modelo detecta ataques nunca vistos
(fuzzing, enumeração), o que é a principal vantagem da abordagem não supervisionada.
"""
import math
import pickle
from collections import defaultdict, deque
from dataclasses import dataclass, field

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

NOMES_ATRIBUTOS = [
    "log_taxa_req",          # log(1 + requisições/s)
    "iat_medio",             # intervalo médio entre requisições (s)
    "iat_cv",                # coef. de variação do intervalo (regularidade de robô)
    "frac_negativas",        # fração de respostas 7F
    "frac_falha_seguranca",  # NRC 35/36/37/33
    "frac_nao_suportado",    # NRC 11/12/7F  -> enumeração de serviços
    "frac_formato_invalido", # NRC 13/31     -> payloads malformados
    "frac_sids_distintos",   # diversidade de serviços
    "comp_medio",            # tamanho médio da requisição
    "comp_desvio",           # desvio do tamanho
    "entropia_media",        # entropia de Shannon dos bytes
    "frac_falha_cripto",     # tokens Fernet inválidos
    "frac_send_key",         # proporção de 27 02
]


@dataclass
class Evento:
    t: float
    cliente: str
    req: bytes
    resp: bytes
    falha_cripto: bool = False
    crash: bool = False


@dataclass
class Alerta:
    t: float
    cliente: str
    origem: str              # "regra" ou "ml"
    motivo: str
    score: float = 0.0


@dataclass
class _EstadoCliente:
    janela: deque
    historico_t: deque = field(default_factory=lambda: deque(maxlen=500))
    bloqueado_ate: float = 0.0
    seq_anomala: int = 0


def _entropia(b: bytes) -> float:
    if not b:
        return 0.0
    cont = np.bincount(np.frombuffer(b, dtype=np.uint8), minlength=256)
    p = cont[cont > 0] / len(b)
    return float(-(p * np.log2(p)).sum())


def extrair_atributos(janela) -> np.ndarray:
    ev = list(janela)
    n = len(ev)
    ts = np.array([e.t for e in ev])
    iats = np.diff(ts) if n > 1 else np.array([1.0])
    dur = max(ts[-1] - ts[0], 1e-3)
    taxa = (n - 1) / dur if n > 1 else 0.0
    iat_m = float(iats.mean())
    iat_cv = float(iats.std() / iat_m) if iat_m > 1e-6 else 0.0

    neg = seg = nsup = fmt = cripto = sk = 0
    sids, comps, ents = set(), [], []
    for e in ev:
        if e.falha_cripto:
            cripto += 1
            comps.append(0); ents.append(0.0)
            continue
        r = e.resp
        if len(r) >= 3 and r[0] == 0x7F:
            neg += 1
            nrc = r[2]
            seg += nrc in (0x33, 0x35, 0x36, 0x37)
            nsup += nrc in (0x11, 0x12, 0x7F)
            fmt += nrc in (0x13, 0x31)
        if e.req:
            sids.add(e.req[0])
            sk += len(e.req) >= 2 and e.req[0] == 0x27 and e.req[1] == 0x02
        comps.append(len(e.req))
        ents.append(_entropia(e.req))
    return np.array([
        math.log1p(taxa), iat_m, iat_cv,
        neg / n, seg / n, nsup / n, fmt / n,
        len(sids) / n, float(np.mean(comps)), float(np.std(comps)),
        float(np.mean(ents)), cripto / n, sk / n,
    ])


class IDS:
    def __init__(self, tam_janela: int = 20, min_janela: int = 6,
                 tempo_bloqueio: float = 60.0, percentil_limiar: float = 99.5,
                 # parâmetros das regras
                 r1_max_send_key: int = 6, r1_janela_s: float = 120.0,
                 r2_max_falhas_cripto: int = 3, r4_max_taxa: float = 25.0,
                 ml_confirmacoes: int = 2,
                 usar_regras: bool = True, usar_ml: bool = True,
                 bloquear: bool = True, semente: int = 42):
        self.tam_janela, self.min_janela = tam_janela, min_janela
        self.tempo_bloqueio = tempo_bloqueio
        self.percentil_limiar = percentil_limiar
        self.r1_max_send_key, self.r1_janela_s = r1_max_send_key, r1_janela_s
        self.r2_max_falhas_cripto, self.r4_max_taxa = r2_max_falhas_cripto, r4_max_taxa
        self.usar_regras, self.usar_ml, self.bloquear = usar_regras, usar_ml, bloquear
        self.ml_confirmacoes = ml_confirmacoes   # janelas anômalas consecutivas p/ alertar
        self.scaler = StandardScaler()
        self.modelo = IsolationForest(n_estimators=120, contamination="auto",
                                      random_state=semente)
        self.limiar = None
        self.treinado = False
        self.clientes: dict[str, _EstadoCliente] = {}
        self.alertas: list[Alerta] = []

    # ------------------------------------------------------------ treinamento
    def vetores_de(self, eventos) -> np.ndarray:
        """Converte uma sequência de eventos (vários clientes) em vetores de janela."""
        janelas = defaultdict(lambda: deque(maxlen=self.tam_janela))
        X = []
        for e in eventos:
            j = janelas[e.cliente]
            j.append(e)
            if len(j) >= self.min_janela:
                X.append(extrair_atributos(j))
        return np.array(X)

    def treinar(self, eventos_normais) -> None:
        X = self.vetores_de(eventos_normais)
        Xs = self.scaler.fit_transform(X)
        self.modelo.fit(Xs)
        scores = -self.modelo.score_samples(Xs)       # maior = mais anômalo
        self.limiar = float(np.percentile(scores, self.percentil_limiar))
        self.treinado = True

    def score(self, janela) -> float:
        x = self.scaler.transform(extrair_atributos(janela).reshape(1, -1))
        return float(-self.modelo.score_samples(x)[0])

    # --------------------------------------------------------------- operação
    def _estado(self, cliente) -> _EstadoCliente:
        if cliente not in self.clientes:
            self.clientes[cliente] = _EstadoCliente(deque(maxlen=self.tam_janela))
        return self.clientes[cliente]

    def esta_bloqueado(self, cliente: str, agora: float) -> bool:
        return self.bloquear and agora < self._estado(cliente).bloqueado_ate

    def _regras(self, est: _EstadoCliente, e: Evento) -> str | None:
        if e.crash:
            return "R3 requisição provocou travamento da ECU"
        jan = list(est.janela)
        if sum(x.falha_cripto for x in jan) >= self.r2_max_falhas_cripto:
            return "R2 falhas repetidas de decifragem/HMAC (token adulterado ou sem chave)"
        sk = [t for t in est.historico_t if e.t - t <= self.r1_janela_s]
        if len(sk) >= self.r1_max_send_key:
            return f"R1 força bruta: {len(sk)} tentativas de sendKey em {self.r1_janela_s:.0f}s"
        if len(jan) >= 10:
            dur = max(jan[-1].t - jan[0].t, 1e-3)
            if (len(jan) - 1) / dur > self.r4_max_taxa:
                return "R4 inundação: taxa de requisições acima do limite"
        return None

    def observar(self, e: Evento) -> Alerta | None:
        est = self._estado(e.cliente)
        est.janela.append(e)
        if len(e.req) >= 2 and e.req[0] == 0x27 and e.req[1] == 0x02:
            est.historico_t.append(e.t)

        alerta = None
        if self.usar_regras:
            motivo = self._regras(est, e)
            if motivo:
                alerta = Alerta(e.t, e.cliente, "regra", motivo)
        if alerta is None and self.usar_ml and self.treinado and len(est.janela) >= self.min_janela:
            s = self.score(est.janela)
            est.seq_anomala = est.seq_anomala + 1 if s > self.limiar else 0
            if est.seq_anomala >= self.ml_confirmacoes:
                alerta = Alerta(e.t, e.cliente, "ml",
                                f"anomalia Isolation Forest (score {s:.3f} > {self.limiar:.3f})", s)
        if alerta:
            self.alertas.append(alerta)
            if self.bloquear:
                est.bloqueado_ate = e.t + self.tempo_bloqueio
        return alerta

    def explicar(self, cliente: str) -> dict:
        """Atributos atuais do cliente (útil para justificar um alerta no artigo)."""
        est = self._estado(cliente)
        if not est.janela:
            return {}
        return dict(zip(NOMES_ATRIBUTOS, map(float, extrair_atributos(est.janela))))

    def resetar_clientes(self) -> None:
        self.clientes.clear()
        self.alertas.clear()

    # ------------------------------------------------------------ persistência
    def salvar(self, caminho: str) -> None:
        with open(caminho, "wb") as f:
            pickle.dump({"scaler": self.scaler, "modelo": self.modelo,
                         "limiar": self.limiar}, f)

    def carregar(self, caminho: str) -> None:
        with open(caminho, "rb") as f:
            d = pickle.load(f)
        self.scaler, self.modelo, self.limiar = d["scaler"], d["modelo"], d["limiar"]
        self.treinado = True
