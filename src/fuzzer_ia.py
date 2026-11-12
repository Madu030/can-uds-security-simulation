"""
fuzzer_ia.py - Fuzzer guiado por IA para testar a resiliência da ECU e do IDS
(IA ofensiva, uso exclusivo em ambiente de teste próprio).

Três estratégias, para comparação no artigo:
  aleatorio : bytes aleatórios (linha de base "fuzzer burro")
  mutacao   : mutações clássicas sobre um corpus fixo de requisições UDS válidas
  ia        : (a) modelo GERATIVO de Markov de ordem 2 sobre bytes, treinado com
                  requisições válidas e re-treinado com as entradas "interessantes";
              (b) seleção ADAPTATIVA de operadores por bandit multibraço UCB1,
                  recompensada por novidade de resposta (proxy de cobertura) e crashes;
              (c) corpus evolutivo (estilo AFL): entradas que geram respostas
                  novas são mantidas e mutadas.
  + modo evasivo (adversarial contra o IDS): controla ritmo e tráfego de
    cobertura com base no retorno "fui bloqueado?".

Uso pela rede (contra ecu_servidor.py):
  python fuzzer_ia.py --modo ia --n 2000
  python fuzzer_ia.py --modo ia --evasivo --n 500
"""
import argparse
import math
import random
import socket
import time
from collections import defaultdict

CORPUS_SEMENTE = [
    b"\x10\x01", b"\x10\x03", b"\x11\x01", b"\x14\xFF\xFF\xFF",
    b"\x22\xF1\x90", b"\x22\xF1\x8C\xF1\x90", b"\x27\x01", b"\x27\x02\x00\x00\x00\x00",
    b"\x2E\xF1\x95SW 0420", b"\x31\x01\xFF\x00", b"\x31\x01\x02\x03\x01", b"\x3E\x00",
]
SIDS_UDS = [0x10, 0x11, 0x14, 0x19, 0x22, 0x23, 0x27, 0x28, 0x2E, 0x2F, 0x31,
            0x34, 0x35, 0x36, 0x37, 0x3D, 0x3E, 0x85, 0x87]
VALORES_LIMITE = [0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF]
INICIO, FIM = 256, 257
MAX_LEN = 32


# ================================================================ modelo gerativo
class MarkovBytes:
    """Modelo de linguagem n-grama sobre bytes: aprende a 'gramática' implícita
    das requisições UDS e gera novas mensagens plausíveis (porém inéditas)."""

    def __init__(self, ordem=2, epsilon=0.08):
        self.ordem, self.epsilon = ordem, epsilon
        self.cont = defaultdict(lambda: defaultdict(int))

    def treinar(self, corpus):
        self.cont.clear()
        for seq in corpus:
            toks = [INICIO] * self.ordem + list(seq) + [FIM]
            for i in range(self.ordem, len(toks)):
                self.cont[tuple(toks[i - self.ordem:i])][toks[i]] += 1

    def gerar(self, rng: random.Random) -> bytes:
        ctx, saida = [INICIO] * self.ordem, []
        while len(saida) < MAX_LEN:
            dist = self.cont.get(tuple(ctx))
            if not dist or rng.random() < self.epsilon:      # exploração
                prox = rng.randrange(256) if rng.random() < 0.9 else FIM
            else:
                toks, pesos = zip(*dist.items())
                prox = rng.choices(toks, pesos)[0]
            if prox == FIM:
                break
            saida.append(prox)
            ctx = ctx[1:] + [prox]
        return bytes(saida) or b"\x3E"


# ======================================================================= bandit
class BanditUCB1:
    def __init__(self, bracos, c=1.0):
        self.bracos, self.c = list(bracos), c
        self.n = {b: 0 for b in self.bracos}
        self.soma = {b: 0.0 for b in self.bracos}
        self.t = 0

    def escolher(self, rng):
        self.t += 1
        nao_testados = [b for b in self.bracos if self.n[b] == 0]
        if nao_testados:
            return rng.choice(nao_testados)
        return max(self.bracos, key=lambda b: self.soma[b] / self.n[b]
                   + self.c * math.sqrt(2 * math.log(self.t) / self.n[b]))

    def atualizar(self, braco, recompensa):
        self.n[braco] += 1
        self.soma[braco] += recompensa


# ======================================================================= fuzzer
class FuzzerIA:
    OPERADORES = ["gerativo", "bitflip", "byte_aleatorio", "varrer_byte", "valor_limite",
                  "inserir", "remover", "estender_bloco", "truncar", "splice", "trocar_sid"]

    @staticmethod
    def _pos(r, b):
        """Posição a mutar, com forte viés para o cabeçalho (primeiros bytes): é
        onde ficam SID/subfunção/identificadores, as regiões sensíveis do protocolo."""
        if len(b) <= 1:
            return 0
        return min(int(r.expovariate(0.35)), len(b) - 1)

    def __init__(self, modo="ia", semente=0):
        assert modo in ("aleatorio", "mutacao", "ia")
        self.modo = modo
        self.rng = random.Random(semente)
        self.corpus = list(CORPUS_SEMENTE)
        self.energia = [1.0] * len(self.corpus)   # "power schedule": entradas produtivas são mais mutadas
        self._ultima_base = None
        self._tem_cobertura = False               # vira True quando o harness fornece cobertura
        self._cursor_val = 0                       # contador da varredura determinística de bytes
        # cursores determinísticos (estilo AFL): FRONTEIRA (fp/fv) varre a entrada
        # mais recente que abriu código; SEMENTES (si/sp/sv) varre o corpus-semente.
        self.fp, self.fv = 2, 0
        self.si, self.sp, self.sv = 0, 2, 0
        self._det_sub = "semente"
        self._sweep_gasto = 0
        self._frontier = None
        self.markov = MarkovBytes()
        self.markov.treinar(self.corpus)
        self.bandit = BanditUCB1(self.OPERADORES)
        self.assinaturas = set()
        self.crashes = []            # (n_teste, req)
        self.n_testes = 0
        self.historico_cobertura = []
        self._ultimo_op = None

    # ----------------------------------------------------------- operadores
    def _mutar(self, op, base: bytes) -> bytes:
        r, b = self.rng, bytearray(base)
        if op == "gerativo":
            return self.markov.gerar(r)
        if op == "bitflip" and b:
            i = r.randrange(len(b)); b[i] ^= 1 << r.randrange(8)
        elif op == "byte_aleatorio" and b:
            b[self._pos(r, b)] = r.randrange(256)
        elif op == "varrer_byte" and b:
            # varredura determinística de valores numa posição do cabeçalho:
            # é o que, em greybox clássico, resolve "bytes mágicos" sem conhecê-los
            b[self._pos(r, b)] = self._cursor_val & 0xFF
            self._cursor_val += 1
        elif op == "valor_limite" and b:
            b[self._pos(r, b)] = r.choice(VALORES_LIMITE)
        elif op == "inserir":
            b.insert(r.randrange(len(b) + 1), r.randrange(256))
        elif op == "remover" and len(b) > 1:
            del b[r.randrange(len(b))]
        elif op == "estender_bloco" and b:
            i = r.randrange(len(b)); j = min(len(b), i + r.randint(1, 4))
            b[j:j] = b[i:j] * r.randint(1, 4)
        elif op == "truncar" and len(b) > 1:
            b = b[:r.randrange(1, len(b))]
        elif op == "splice":
            outro = r.choice(self.corpus)
            b = b[:r.randrange(len(b) + 1)] + outro[r.randrange(len(outro) + 1):]
        elif op == "trocar_sid" and b:
            b[0] = r.choice(SIDS_UDS)
        return bytes(b[:MAX_LEN]) or b"\x00"

    def proximo(self) -> bytes:
        if self.modo == "aleatorio":
            self._ultimo_op = None
            return bytes(self.rng.randrange(256) for _ in range(self.rng.randint(1, 16)))
        if self.modo == "mutacao":
            # mutação cega: opera sobre o corpus-semente fixo, sem modelo gerativo,
            # sem varredura guiada e SEM memória de progresso (baseline blackbox)
            op = self.rng.choice([o for o in self.OPERADORES if o not in ("gerativo", "varrer_byte")])
            self._ultimo_op = op
            return self._mutar(op, self.rng.choice(CORPUS_SEMENTE))
        # --- modo IA (greybox, estilo AFL) ---
        # 60% do orçamento: estágio DETERMINÍSTICO sobre a FILA de sementes que
        # abriram cobertura (varre cada posição do cabeçalho por todos os 256
        # valores). É o que quebra "bytes mágicos" sem conhecê-los: cada byte do
        # portão cai em <=256 tentativas. A fila é percorrida priorizando a
        # semente mais recente (segue a cadeia do portão em profundidade).
        # 40%: exploração estocástica (bandit + gerativo) para achar novas regiões.
        if self.rng.random() < 0.65:
            self._ultimo_op = "det"
            self._ultima_base = None
            # Dois sub-estágios determinísticos:
            #  (a) FRONTEIRA (DFS): varre a entrada mais profunda que abriu código,
            #      posição a posição -> escala o portão byte a byte;
            #  (b) SEMENTES: varre o corpus-semente fixo, POR POSIÇÃO (uma posição
            #      em todas as sementes, depois a próxima) -> acha a ENTRADA do portão.
            # Sem fronteira, concentra na busca da entrada; com fronteira, escala.
            if self._frontier is not None and self.rng.random() < 0.7:
                self._det_sub = "frontier"
                self._sweep_gasto += 1
                if self._sweep_gasto > 12 * 256:            # fronteira esgotada: aposenta
                    self._frontier = None
                b = bytearray(self._frontier or CORPUS_SEMENTE[self.si])
                if len(b) < 13:
                    b += bytes(13 - len(b))
                b[self.fp] = self.fv
                self.fv += 1
                if self.fv > 255:
                    self.fv = 0
                    self.fp = self.fp + 1 if self.fp < 8 else 2
            else:
                self._det_sub = "semente"
                b = bytearray(CORPUS_SEMENTE[self.si])
                if len(b) < 13:
                    b += bytes(13 - len(b))
                b[self.sp] = self.sv
                self.sv += 1
                if self.sv > 255:                           # ordem POR POSIÇÃO:
                    self.sv = 0
                    self.si += 1                            # ...todas as sementes nesta posição...
                    if self.si >= len(CORPUS_SEMENTE):
                        self.si = 0
                        self.sp = self.sp + 1 if self.sp < 5 else 2   # ...depois a próxima posição
            return bytes(b)
        self._det_sub = "exploracao"
        op = self.bandit.escolher(self.rng)
        self._ultimo_op = op
        idx = self.rng.choices(range(len(self.corpus)), self.energia)[0]
        self._ultima_base = idx
        return self._mutar(op, self.corpus[idx])

    @staticmethod
    def assinatura(req: bytes, resp: bytes, crash: bool):
        sid = req[0] if req else -1
        if crash:
            return ("CRASH", sid)
        if not resp:
            return (sid, "SEM_RESPOSTA")
        if resp[0] == 0x7F and len(resp) >= 3:
            return (sid, "NEG", resp[2])
        return (sid, "POS", req[1] if len(req) > 1 else -1, min(len(resp), 24))

    def feedback(self, req, resp, crash=False, bloqueado=False, cobertura_nova=0):
        """cobertura_nova: nº de linhas da ECU cobertas pela 1ª vez por esta
        requisição (quando o harness instrumenta a ECU). É o sinal de um fuzzer
        guiado por cobertura (greybox): toda entrada que abre código novo é
        guardada e priorizada, exatamente o que permite escalar portões profundos."""
        self.n_testes += 1
        if bloqueado:
            recompensa = 0.0
        else:
            sig = self.assinatura(req, resp, crash)
            novo = sig not in self.assinaturas
            self.assinaturas.add(sig)
            # serviço inexistente (NRC 0x11) é uma novidade "rasa": pouca recompensa
            rasa = len(sig) == 3 and sig[1] == "NEG" and sig[2] == 0x11
            recompensa = (10.0 if crash and novo else 0.0) + (0.1 if rasa else 1.0) * novo
            recompensa += 5.0 * cobertura_nova            # cobertura nova domina o sinal
            if crash:
                self.crashes.append((self.n_testes, bytes(req)))
            abriu_codigo = cobertura_nova > 0
            if self.modo == "ia":
                # Greybox (estilo AFL): só entram no corpus as entradas que abrem
                # CÓDIGO novo. Com instrumentação, a cobertura é o critério; sem
                # ela, cai para novidade de resposta.
                interessante = abriu_codigo or (not self._tem_cobertura and novo and not rasa)
                if interessante:
                    self.corpus.append(bytes(req))
                    self.energia.append(1e5 * (1 + cobertura_nova) if abriu_codigo else 3.0)
                    if abriu_codigo:
                        self._tem_cobertura = True
                    if len(self.corpus) % 12 == 0:
                        self.markov.treinar(self.corpus[-60:])    # re-treino no material recente
                # A fronteira avança quando o código novo veio de mutar a própria
                # fronteira (filho mais profundo) ou de uma entrada recém-descoberta,
                # após o aquecimento (cobertura do protocolo normal já saturada).
                if (abriu_codigo and self.n_testes > 1000
                        and (self._frontier is None or self._det_sub == "frontier")):
                    self._frontier = bytes(req)
                    self.fp, self.fv, self._sweep_gasto = 2, 0, 0
        if self._ultimo_op in self.bandit.bracos and self.modo == "ia":
            self.bandit.atualizar(self._ultimo_op, recompensa)
        self.historico_cobertura.append(len(self.assinaturas))
        return recompensa


# ======================================================= controlador evasivo
class ControladorEvasivo:
    """Atacante adaptativo contra o IDS: aprende o ritmo/disfarce que não gera
    bloqueio. Sinal de recompensa: ser ou não bloqueado."""

    COBERTURA = [b"\x3E\x00", b"\x22\xF1\x90", b"\x22\xF1\x95", b"\x22\xF1\x8C"]

    def __init__(self, rng, atraso_inicial=0.05):
        self.rng = rng
        self.atraso = atraso_inicial
        self.p_cobertura = 0.0
        self.sequencia_ok = 0
        self.bloqueios = 0

    def proximo_atraso(self):
        return self.rng.lognormvariate(math.log(self.atraso), 0.6)   # jitter "humano"

    def usar_cobertura(self):
        return self.rng.random() < self.p_cobertura

    def registrar(self, bloqueado):
        if bloqueado:
            self.bloqueios += 1
            self.atraso = min(self.atraso * 2.5, 20.0)
            self.p_cobertura = min(self.p_cobertura + 0.2, 0.85)
            self.sequencia_ok = 0
        else:
            self.sequencia_ok += 1
            if self.sequencia_ok >= 40:                   # testa ir mais rápido
                self.atraso = max(self.atraso * 0.85, 0.05)
                self.sequencia_ok = 0


def perfil_fuzzer_evasivo(fuzzer: FuzzerIA, n=500, tempo_espera_bloqueio=65.0):
    """Perfil para o Simulador: o fuzzer só conta testes realmente entregues."""
    from trafego import BLOQUEADO, CRASH
    ctl = ControladorEvasivo(fuzzer.rng)
    fuzzer.controlador = ctl
    entregues = 0
    yield 0.0, b"\x10\x03"
    while entregues < n:
        if ctl.usar_cobertura():
            resp = yield ctl.proximo_atraso(), ctl.rng.choice(ctl.COBERTURA)
            bloq = resp is BLOQUEADO
        else:
            req = fuzzer.proximo()
            resp = yield ctl.proximo_atraso(), req
            bloq = resp is BLOQUEADO
            if not bloq:
                entregues += 1
                fuzzer.feedback(req, resp, crash=resp is CRASH)
        ctl.registrar(bloq)
        if bloq:
            yield tempo_espera_bloqueio, b"\x3E\x00"      # espera o bloqueio expirar


# ================================================================ modo rede
def _conectar(host, porta, chave):
    from protocolo import Canal
    s = socket.create_connection((host, porta), timeout=3)
    return Canal(s, chave)


def main():
    from protocolo import HOST_PADRAO, PORTA_PADRAO, carregar_chave, hexa
    ap = argparse.ArgumentParser(description="Fuzzer UDS guiado por IA (rede)")
    ap.add_argument("--host", default=HOST_PADRAO)
    ap.add_argument("--porta", type=int, default=PORTA_PADRAO)
    ap.add_argument("--modo", choices=["aleatorio", "mutacao", "ia"], default="ia")
    ap.add_argument("--n", type=int, default=1000)
    ap.add_argument("--atraso", type=float, default=0.01)
    ap.add_argument("--evasivo", action="store_true", help="adapta ritmo para driblar o IDS")
    ap.add_argument("--sem-cripto", action="store_true")
    ap.add_argument("--semente", type=int, default=0)
    a = ap.parse_args()

    chave = None if a.sem_cripto else carregar_chave()
    fz = FuzzerIA(a.modo, a.semente)
    ctl = ControladorEvasivo(fz.rng, a.atraso) if a.evasivo else None
    canal, bloqueios, t0 = None, 0, time.time()
    print(f"[Fuzzer] modo={a.modo} evasivo={a.evasivo} alvo={a.host}:{a.porta}")
    while fz.n_testes < a.n:
        if canal is None:
            try:
                canal = _conectar(a.host, a.porta, chave)
                canal.enviar(b"\x10\x03"); canal.receber()
            except (OSError, ConnectionError) as ex:
                print(f"[Fuzzer] sem conexão ({ex}); aguardando..."); time.sleep(2)
                canal = None
                continue
        cobertura = ctl and ctl.usar_cobertura()
        req = ctl.COBERTURA[0] if cobertura else fz.proximo()
        time.sleep(ctl.proximo_atraso() if ctl else a.atraso)
        try:
            canal.enviar(req)
            resp = canal.receber()
            caiu = False
        except (OSError, ConnectionError):
            resp, caiu = b"", True
        if caiu:
            canal.fechar(); canal = None
            # distinguir crash x bloqueio: tenta reconectar imediatamente
            try:
                teste = _conectar(a.host, a.porta, chave)
                teste.enviar(b"\x3E\x00"); teste.receber(); teste.fechar()
                bloqueado = False          # ECU responde -> foi crash + reboot
            except (OSError, ConnectionError):
                bloqueado = True           # IDS recusa o cliente
            if bloqueado:
                bloqueios += 1
                print(f"[Fuzzer] conexão recusada: BLOQUEADO pelo IDS (total {bloqueios}); última entrada: {hexa(req)}")
                if ctl:
                    ctl.registrar(True)
                    time.sleep(5)
                    continue
                break
            print(f"[Fuzzer] *** CRASH com {hexa(req)} ***")
            fz.feedback(req, b"", crash=True)
            continue
        if ctl:
            ctl.registrar(False)
        if not cobertura:
            fz.feedback(req, resp)
        if fz.n_testes % 100 == 0:
            print(f"[Fuzzer] {fz.n_testes} testes | {len(fz.assinaturas)} respostas distintas "
                  f"| {len(fz.crashes)} crashes | {time.time() - t0:.0f}s")
    print(f"\n[Fuzzer] Fim: {fz.n_testes} testes, {len(fz.assinaturas)} comportamentos distintos, "
          f"{len(fz.crashes)} crashes, {bloqueios} bloqueios.")
    for n, req in fz.crashes:
        print(f"   crash no teste {n}: {hexa(req)}")


if __name__ == "__main__":
    main()
