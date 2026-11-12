"""
ecu_core.py - Lógica UDS (ISO 14229-1) da ECU simulada, independente de rede.

Serviços implementados:
  0x10 DiagnosticSessionControl   0x11 ECUReset          0x14 ClearDiagnosticInformation
  0x22 ReadDataByIdentifier       0x27 SecurityAccess    0x2E WriteDataByIdentifier
  0x31 RoutineControl             0x3E TesterPresent

Proteções do próprio padrão: contador de tentativas inválidas (NRC 0x36) e atraso
obrigatório após bloqueio (NRC 0x37).

Modo vulnerável (vulneravel=True): planta duas falhas realistas para que o fuzzer
tenha algo a encontrar. Elas são documentadas no README e servem como "verdade
de referência" na avaliação do fuzzer:
  BUG-1  0x22 com lista de DIDs de tamanho ímpar -> leitura fora do limite
  BUG-2  0x31 com optionRecord > 8 bytes, analisado ANTES da verificação de
         SecurityAccess -> estouro de buffer pré-autenticação
"""
import random

# Códigos de resposta negativa (NRC)
NRC = {
    0x10: "generalReject",
    0x11: "serviceNotSupported",
    0x12: "subFunctionNotSupported",
    0x13: "incorrectMessageLengthOrInvalidFormat",
    0x22: "conditionsNotCorrect",
    0x24: "requestSequenceError",
    0x31: "requestOutOfRange",
    0x33: "securityAccessDenied",
    0x35: "invalidKey",
    0x36: "exceededNumberOfAttempts",
    0x37: "requiredTimeDelayNotExpired",
    0x7F: "serviceNotSupportedInActiveSession",
}

SESSAO_PADRAO, SESSAO_PROG, SESSAO_ESTENDIDA = 0x01, 0x02, 0x03


# Constante secreta do algoritmo (na prática, embutida no firmware da ECU e no
# scanner autorizado). Expô-la equivale a extrair o segredo do firmware.
SEGREDO_CHAVE = 0xA5B41C37


def _rotl32(v: int, n: int) -> int:
    v &= 0xFFFFFFFF
    return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF


def algoritmo_chave(seed: int) -> int:
    """Algoritmo Seed & Key proprietário (estilo OEM): mistura o seed com uma
    constante secreta por XOR, rotações e um passo multiplicativo (constante de
    Fibonacci de 32 bits). É determinístico e idêntico nos dois lados, mas não é
    invertível por álgebra simples a partir de um único par (seed, key) observado
    — ao contrário de uma relação linear como (seed*3)+5."""
    k = (seed ^ SEGREDO_CHAVE) & 0xFFFFFFFF
    k = _rotl32(k, 7)
    k = (k + 0x7F4A7C15) & 0xFFFFFFFF
    k ^= _rotl32(k, 13)
    k = (k * 0x9E3779B1) & 0xFFFFFFFF   # 2^32 / phi (mistura difusa)
    k ^= (k >> 16)
    return k & 0xFFFFFFFF


class FalhaECU(Exception):
    """Representa um travamento (crash) da ECU causado por entrada malformada."""


def negativa(sid: int, nrc: int) -> bytes:
    return bytes([0x7F, sid, nrc])


class ECU:
    def __init__(self, vulneravel: bool = False, max_tentativas: int = 3,
                 atraso_bloqueio: float = 10.0, rng: random.Random | None = None):
        self.vulneravel = vulneravel
        self.max_tentativas = max_tentativas
        self.atraso_bloqueio = atraso_bloqueio
        self.rng = rng or random.SystemRandom()
        self.dids = {
            0xF190: b"9BWZZZ377VT004251",   # VIN
            0xF18C: b"ECU-SN-000123",       # número de série
            0xF187: b"5Q0-907-530-AB",      # part number
            0xF195: b"SW 0420",             # versão de software
        }
        self.tentativas_falhas = 0
        self.bloqueado_ate = 0.0
        self.reiniciar()

    # ------------------------------------------------------------------ estado
    def reiniciar(self) -> None:
        """Reset lógico (ECUReset ou reboot após crash). O contador de
        tentativas e o atraso sobrevivem ao reset, como recomenda a norma."""
        self.sessao = SESSAO_PADRAO
        self.desbloqueada = False
        self.seed_pendente: int | None = None

    # ---------------------------------------------------------------- serviço
    def processar(self, req: bytes, agora: float) -> bytes:
        """Processa uma requisição e devolve a resposta (b'' = sem resposta)."""
        if not req:
            return negativa(0x00, 0x13)
        sid = req[0]
        tratador = {
            0x10: self._sessao, 0x11: self._reset, 0x14: self._limpar_dtc,
            0x22: self._ler_did, 0x27: self._security_access,
            0x2E: self._escrever_did, 0x31: self._rotina, 0x3E: self._tester_present,
        }.get(sid)
        if tratador is None:
            return negativa(sid, 0x11)
        return tratador(req, agora)

    def _sessao(self, req, agora):
        if len(req) != 2:
            return negativa(0x10, 0x13)
        sub = req[1] & 0x7F
        if sub not in (SESSAO_PADRAO, SESSAO_PROG, SESSAO_ESTENDIDA):
            return negativa(0x10, 0x12)
        self.sessao = sub
        self.desbloqueada = False          # trocar de sessão revoga o acesso
        self.seed_pendente = None
        return bytes([0x50, sub, 0x00, 0x32, 0x01, 0xF4])   # P2 = 50 ms, P2* = 5 s

    def _reset(self, req, agora):
        if len(req) != 2:
            return negativa(0x11, 0x13)
        sub = req[1] & 0x7F
        if sub not in (0x01, 0x03):
            return negativa(0x11, 0x12)
        self.reiniciar()
        return bytes([0x51, sub])

    def _limpar_dtc(self, req, agora):
        if len(req) != 4:
            return negativa(0x14, 0x13)
        if req[1:] != b"\xFF\xFF\xFF":
            return negativa(0x14, 0x31)
        return b"\x54"

    def _ler_did(self, req, agora):
        if len(req) < 3:
            return negativa(0x22, 0x13)
        if not self.vulneravel and (len(req) - 1) % 2 != 0:
            return negativa(0x22, 0x13)
        resposta = bytearray([0x62])
        try:
            for i in range(1, len(req), 2):
                if i + 1 >= len(req):          # BUG-1: o código "C" leria além do buffer
                    raise IndexError
                did = (req[i] << 8) | req[i + 1]
                if did not in self.dids:
                    return negativa(0x22, 0x31)
                resposta += req[i:i + 2] + self.dids[did]
        except IndexError:
            raise FalhaECU("BUG-1: leitura fora do limite no parser de DIDs (0x22)")
        return bytes(resposta)

    def _security_access(self, req, agora):
        if len(req) < 2:
            return negativa(0x27, 0x13)
        if self.sessao != SESSAO_ESTENDIDA:
            return negativa(0x27, 0x7F)
        sub = req[1]
        if sub == 0x01:                                   # requestSeed
            if len(req) != 2:
                return negativa(0x27, 0x13)
            if agora < self.bloqueado_ate:
                return negativa(0x27, 0x37)
            if self.desbloqueada:
                return b"\x67\x01\x00\x00\x00\x00"        # já desbloqueada: seed zero
            self.seed_pendente = self.rng.randint(1, 0xFFFFFFFF)
            return b"\x67\x01" + self.seed_pendente.to_bytes(4, "big")
        if sub == 0x02:                                   # sendKey
            if len(req) != 6:
                return negativa(0x27, 0x13)
            if agora < self.bloqueado_ate:
                return negativa(0x27, 0x37)
            if self.seed_pendente is None:
                return negativa(0x27, 0x24)
            chave = int.from_bytes(req[2:6], "big")
            esperado = algoritmo_chave(self.seed_pendente)
            self.seed_pendente = None                     # seed de uso único
            if chave == esperado:
                self.desbloqueada = True
                self.tentativas_falhas = 0
                return b"\x67\x02"
            self.tentativas_falhas += 1
            if self.tentativas_falhas >= self.max_tentativas:
                self.bloqueado_ate = agora + self.atraso_bloqueio
                self.tentativas_falhas = 0
                return negativa(0x27, 0x36)
            return negativa(0x27, 0x35)
        return negativa(0x27, 0x12)

    def _escrever_did(self, req, agora):
        if len(req) < 4:
            return negativa(0x2E, 0x13)
        if not self.desbloqueada:
            return negativa(0x2E, 0x33)
        did = (req[1] << 8) | req[2]
        if did not in self.dids:
            return negativa(0x2E, 0x31)
        self.dids[did] = bytes(req[3:])
        return bytes([0x6E, req[1], req[2]])

    # Sequência "mágica" (RID 0x0A55 + assinatura DE AD BE EF) que abre uma rotina
    # de fábrica não documentada e vulnerável. Um portão profundo: só é alcançado
    # quem reconstrói os 6 bytes na ordem certa, byte a byte.
    SEGREDO_ROTINA = bytes([0x0A, 0x55, 0xDE, 0xAD])

    def _rotina(self, req, agora):
        if len(req) < 4:
            return negativa(0x31, 0x13)
        registro = req[4:]

        # --- Porta profunda (BUG-3), pré-autenticação ---------------------------
        # O corpo a partir do RID é comparado com a sequência secreta byte a byte.
        # A comparação é DESENROLADA: cada byte correto executa uma linha nova
        # (um ramo mais profundo). Assim, cada acerto gera COBERTURA DE CÓDIGO
        # nova. Mutar às cegas não acumula esse progresso; um fuzzer guiado por
        # cobertura (greybox) escala o gradiente, byte a byte, até o estouro.
        if self.vulneravel and req[2] == 0x0A:
            corpo = req[2:]
            prog = 1                                       # 0x0A (byte alto do RID secreto)
            if len(corpo) > 1 and corpo[1] == 0x55:
                prog = 2                                   # RID 0x0A55 completo: entrou na rotina
                if len(corpo) > 2 and corpo[2] == 0xDE:
                    prog = 3
                    if len(corpo) > 3 and corpo[3] == 0xAD:
                        prog = 4                           # portão mágico 0A55DEAD inteiro
                        if len(corpo) > 8:
                            raise FalhaECU("BUG-3: estouro na rotina de fábrica 0x0A55 após o portão mágico 0A55DEAD")
            return bytes([0x71, 0x0A]) + bytes([0xAA]) * prog   # eco de progresso

        if len(registro) > 8:
            if self.vulneravel:   # BUG-2 (raso): memcpy para buffer de 8 bytes antes da auth
                raise FalhaECU("BUG-2: estouro de buffer no optionRecord (0x31) pré-autenticação")
            return negativa(0x31, 0x13)
        if req[1] not in (0x01, 0x02, 0x03):
            return negativa(0x31, 0x12)
        if not self.desbloqueada:
            return negativa(0x31, 0x33)
        rid = (req[2] << 8) | req[3]
        if rid not in (0xFF00, 0x0203):                   # apagar memória / checar pré-condições
            return negativa(0x31, 0x31)
        return bytes([0x71, req[1], req[2], req[3], 0x00])

    def _tester_present(self, req, agora):
        if len(req) != 2:
            return negativa(0x3E, 0x13)
        if req[1] == 0x80:                                # suppressPosRspMsgIndicationBit
            return b""
        if req[1] != 0x00:
            return negativa(0x3E, 0x12)
        return b"\x7E\x00"


def descrever_resposta(resp: bytes) -> str:
    if not resp:
        return "(sem resposta)"
    if resp[0] == 0x7F and len(resp) >= 3:
        return f"NEGATIVA sid=0x{resp[1]:02X} NRC=0x{resp[2]:02X} ({NRC.get(resp[2], '?')})"
    return f"POSITIVA sid=0x{resp[0] - 0x40:02X}"
