"""
trafego.py - Perfis de tráfego (legítimo e de ataque) + simulador com relógio virtual.

Cada perfil é um gerador Python que produz (atraso_s, requisicao) e recebe de volta
a resposta da ECU. Assim o mesmo perfil roda:
  * no Simulador (relógio virtual, milhares de sessões em segundos, reprodutível), ou
  * pela rede real, via scanner_cliente.py / fuzzer_ia.py.

Requisições especiais:
  FALHA_CRIPTO -> o cliente envia um token Fernet inválido (atacante sem a chave)
"""
import heapq
import random

from ecu_core import ECU, FalhaECU, algoritmo_chave
from ids import IDS, Evento

FALHA_CRIPTO = object()


class _Sinal(bytes):
    """Resposta especial que se comporta como b'' para perfis que não a conhecem."""


CRASH = _Sinal(b"")        # a requisição derrubou a ECU (no modo rede: conexão caiu)
BLOQUEADO = _Sinal(b"")    # o IDS descartou a requisição/derrubou a conexão
DIDS_CONHECIDOS = [0xF190, 0xF18C, 0xF187, 0xF195]


def _did(d):
    return bytes([0x22, d >> 8, d & 0xFF])


def _negativa(resp, nrc=None):
    return len(resp) >= 3 and resp[0] == 0x7F and (nrc is None or resp[2] == nrc)


# ============================================================ perfil legítimo
def perfil_tecnico(rng: random.Random, n_operacoes=None):
    """Sessão de oficina: entra em sessão estendida, autentica, lê/grava dados,
    mantém a sessão com TesterPresent e eventualmente reinicia a ECU."""
    pensar = lambda: rng.lognormvariate(-0.3, 0.6)        # ~0.8 s, cauda longa (humano)
    yield 0.0, b"\x10\x03"
    # autenticação; 5 % de chance de o técnico errar o algoritmo uma vez
    for tentativa in range(3):
        resp = yield pensar(), b"\x27\x01"
        if not resp.startswith(b"\x67\x01") or len(resp) != 6:
            yield 12.0, b"\x3E\x00"
            continue
        seed = int.from_bytes(resp[2:6], "big")
        chave = algoritmo_chave(seed)
        if tentativa == 0 and rng.random() < 0.05:
            chave ^= 0x1
        resp = yield pensar(), b"\x27\x02" + chave.to_bytes(4, "big")
        if resp == b"\x67\x02":
            break
    for _ in range(n_operacoes or rng.randint(4, 14)):
        op = rng.random()
        if op < 0.45:
            # 3 % de chance de consultar um DID que esta ECU não possui (normal em oficina)
            d = rng.choice(DIDS_CONHECIDOS) if rng.random() > 0.03 else rng.choice([0xF1A0, 0xF40D])
            yield pensar(), _did(d)
        elif op < 0.70:
            yield rng.uniform(1.5, 2.5), b"\x3E\x00"
        elif op < 0.80:
            yield pensar(), b"\x2E\xF1\x95" + b"SW 0" + str(rng.randint(400, 499)).encode()
        elif op < 0.90:
            yield pensar(), b"\x31\x01\x02\x03"
        else:
            yield pensar(), b"\x14\xFF\xFF\xFF"
    if rng.random() < 0.3:
        yield pensar(), b"\x11\x01"


# ============================================================ perfis de ataque
def perfil_forca_bruta(rng, n=200, atraso=0.05):
    """Força bruta clássica no 27 02 (chave aleatória), o mais rápido possível."""
    yield 0.0, b"\x10\x03"
    for _ in range(n):
        resp = yield atraso, b"\x27\x01"
        if _negativa(resp, 0x37):
            continue
        yield atraso, b"\x27\x02" + rng.getrandbits(32).to_bytes(4, "big")


def perfil_forca_bruta_lenta(rng, n=60):
    """Força bruta 'paciente': respeita o atraso da ECU e intercala TesterPresent
    para parecer uma sessão normal (tentativa de evasão)."""
    yield 0.0, b"\x10\x03"
    for _ in range(n):
        resp = yield rng.uniform(3, 6), b"\x27\x01"
        if _negativa(resp, 0x37):
            yield 10.0, b"\x3E\x00"
            continue
        resp = yield rng.uniform(1, 3), b"\x27\x02" + rng.getrandbits(32).to_bytes(4, "big")
        yield rng.uniform(1.5, 2.5), b"\x3E\x00"
        yield rng.uniform(0.5, 1.5), _did(rng.choice(DIDS_CONHECIDOS))


def perfil_varredura_servicos(rng, atraso=0.02):
    """Enumeração de serviços: testa todos os SIDs 0x00..0xFF (reconhecimento)."""
    for sid in range(0x100):
        yield atraso, bytes([sid, 0x00])


def perfil_varredura_dids(rng, atraso=0.02, n=300):
    """Enumeração de identificadores de dados 0x22 xx xx."""
    base = rng.randint(0, 0xFFFF - n)
    for d in range(base, base + n):
        yield atraso, _did(d)


def perfil_sem_chave(rng, n=40, atraso=0.1):
    """Atacante na rede (ex.: dentro da VPN) sem a chave Fernet: injeta/repete tokens."""
    for _ in range(n):
        yield atraso, FALHA_CRIPTO


def perfil_exfiltracao_furtiva(rng, n=120):
    """Ataque de DIA-ZERO: exfiltração furtiva de dados (ZERO regra do IDS cobre).

    O atacante autentica normalmente (tem a chave e o algoritmo) e então drena
    dados do veículo lendo DIDs de forma lenta e METÓDICA. Como não é força bruta,
    nem inundação, nem token adulterado, nem causa travamento, NENHUMA das quatro
    regras de assinatura dispara. O que o denuncia é estatístico: a cadência é
    robótica (intervalos quase constantes) e a atividade é monótona (quase só
    0x22), ao contrário da oficina humana (ritmo irregular e operações variadas).
    Só a camada de ML (anomalia) tem chance de pegá-lo."""
    yield 0.0, b"\x10\x03"
    resp = yield 1.0, b"\x27\x01"
    if resp.startswith(b"\x67\x01") and len(resp) == 6:
        seed = int.from_bytes(resp[2:6], "big")
        yield 1.0, b"\x27\x02" + algoritmo_chave(seed).to_bytes(4, "big")
    # drenagem lenta e regular: varre uma faixa de DIDs com cadência quase fixa
    base = rng.randint(0xF180, 0xF1F0)
    for i in range(n):
        yield 1.8 + rng.uniform(-0.05, 0.05), _did(base + i)   # jitter mínimo (robótico)


def perfil_fuzzer(fuzzer, n=1000, atraso=0.01):
    """Adapta um FuzzerIA (fuzzer_ia.py) ao formato de perfil (modo agressivo)."""
    for _ in range(n):
        req = fuzzer.proximo()
        resp = yield atraso, req
        fuzzer.feedback(req, resp, crash=resp is CRASH, bloqueado=resp is BLOQUEADO)


# =================================================================== simulador
class Simulador:
    """Executa vários perfis concorrentes contra uma ECU (+ IDS opcional) usando
    um relógio virtual. Registra cada evento com rótulo de verdade (ataque/normal)."""

    def __init__(self, fabrica_ecu, ids: IDS | None = None):
        """fabrica_ecu: callable que cria uma ECU. Cada cliente fala com a sua
        própria instância (cada oficina/atacante conectado a um veículo)."""
        self.fabrica_ecu, self.ids = fabrica_ecu, ids
        self.ecus = {}
        self.registros = []   # (Evento, rotulo, alerta, bloqueado)
        self.crashes = []

    def executar(self, sessoes, t_max=1e9):
        """sessoes: lista de (t_inicio, cliente, rotulo, gerador)."""
        fila, cont = [], 0
        for t0, cli, rot, gen in sessoes:
            try:
                atraso, req = next(gen)
            except StopIteration:
                continue
            heapq.heappush(fila, (t0 + atraso, cont, cli, rot, gen, req)); cont += 1
        while fila:
            t, _, cli, rot, gen, req = heapq.heappop(fila)
            if t > t_max:
                break
            resp, crash, falha_cripto, bloqueado, alerta = b"", False, False, False, None
            if self.ids and self.ids.esta_bloqueado(cli, t):
                bloqueado = True              # IDS derruba a requisição antes da ECU
            else:
                if req is FALHA_CRIPTO:
                    falha_cripto, req = True, b""
                else:
                    if cli not in self.ecus:
                        self.ecus[cli] = self.fabrica_ecu()
                    ecu = self.ecus[cli]
                    try:
                        resp = ecu.processar(req, t)
                    except FalhaECU as ex:
                        crash = True
                        self.crashes.append((t, cli, req, str(ex)))
                        ecu.reiniciar()       # watchdog reinicia a ECU
                ev = Evento(t, cli, req, resp, falha_cripto, crash)
                if self.ids:
                    alerta = self.ids.observar(ev)
                self.registros.append((ev, rot, alerta, False))
            resp_gen = CRASH if crash else (BLOQUEADO if bloqueado else resp)
            if bloqueado:
                self.registros.append((Evento(t, cli, b"" if req is FALHA_CRIPTO else req, b""),
                                       rot, None, True))
            try:
                atraso, prox = gen.send(resp_gen)
            except StopIteration:
                continue
            heapq.heappush(fila, (t + atraso, cont, cli, rot, gen, prox)); cont += 1
        return self.registros


def encadear(geradores, intervalos):
    """Concatena várias sessões de um mesmo cliente, com pausas entre elas."""
    for gen, pausa in zip(geradores, intervalos):
        try:
            atraso, req = next(gen)
        except StopIteration:
            continue
        resp = yield atraso + pausa, req
        while True:
            try:
                atraso, req = gen.send(resp)
            except StopIteration:
                break
            resp = yield atraso, req


def sessoes_normais(rng: random.Random, n_clientes=6, sessoes_por_cliente=10, prefixo="oficina"):
    """Lista de sessões (formato do Simulador) com tráfego legítimo de várias oficinas."""
    out = []
    for c in range(n_clientes):
        gens = [perfil_tecnico(random.Random(rng.random())) for _ in range(sessoes_por_cliente)]
        pausas = [rng.uniform(5, 120) for _ in gens]
        out.append((rng.uniform(0, 60), f"{prefixo}-{c}", 0, encadear(gens, pausas)))
    return out


def gerar_trafego_normal(semente=0, n_clientes=6, sessoes_por_cliente=10):
    rng = random.Random(semente)
    sim = Simulador(lambda: ECU(rng=random.Random(rng.random())))
    regs = sim.executar(sessoes_normais(rng, n_clientes, sessoes_por_cliente))
    return [r[0] for r in regs]
