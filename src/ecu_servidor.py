"""
ecu_servidor.py - ECU simulada acessível por TCP (porta 5001), com:
  * E2EE AES-Fernet na camada de aplicação (desligável com --sem-cripto)
  * IDS híbrido (regras + Isolation Forest) monitorando cada requisição (--sem-ids)
  * modo vulnerável com falhas plantadas para o fuzzer (--vulneravel)

Exemplos:
  python ecu_servidor.py                      # configuração completa
  python ecu_servidor.py --sem-cripto         # linha de base em texto claro (Wireshark)
  python ecu_servidor.py --vulneravel --sem-ids
"""
import argparse
import csv
import os
import socket
import threading
import time
from datetime import datetime

from ecu_core import ECU, FalhaECU, descrever_resposta
from ids import IDS, Evento
from protocolo import (HOST_PADRAO, PORTA_PADRAO, Canal, InvalidToken,
                       carregar_chave, hexa)

DIR = os.path.dirname(os.path.abspath(__file__))
ARQ_MODELO = os.path.join(DIR, "ids_modelo.pkl")
ARQ_LOG_ALERTAS = os.path.join(DIR, "alertas_ids.csv")


def log(msg):
    print(f"[{datetime.now():%H:%M:%S}] {msg}", flush=True)


def preparar_ids() -> IDS:
    ids = IDS(bloquear=True)
    if os.path.exists(ARQ_MODELO):
        ids.carregar(ARQ_MODELO)
        log(f"[IDS] modelo carregado de {os.path.basename(ARQ_MODELO)} (limiar {ids.limiar:.3f})")
    else:
        from trafego import gerar_trafego_normal
        log("[IDS] treinando Isolation Forest com tráfego legítimo simulado...")
        ids.treinar(gerar_trafego_normal(semente=1, n_clientes=20, sessoes_por_cliente=30))
        ids.salvar(ARQ_MODELO)
        log(f"[IDS] modelo salvo (limiar {ids.limiar:.3f})")
    return ids


class ServidorECU:
    def __init__(self, host, porta, chave, ids, vulneravel):
        self.host, self.porta, self.chave, self.ids = host, porta, chave, ids
        self.ecu = ECU(vulneravel=vulneravel)
        self.trava = threading.Lock()
        if ids and not os.path.exists(ARQ_LOG_ALERTAS):
            with open(ARQ_LOG_ALERTAS, "w", newline="") as f:
                csv.writer(f).writerow(["data_hora", "cliente", "origem", "motivo", "score"])

    def _registrar_alerta(self, a):
        log(f"[IDS] *** ALERTA ({a.origem}) cliente={a.cliente}: {a.motivo} -> bloqueado por "
            f"{self.ids.tempo_bloqueio:.0f}s")
        with open(ARQ_LOG_ALERTAS, "a", newline="") as f:
            csv.writer(f).writerow([datetime.now().isoformat(timespec="seconds"),
                                    a.cliente, a.origem, a.motivo, f"{a.score:.3f}"])

    def _observar(self, ev):
        if not self.ids:
            return False
        alerta = self.ids.observar(ev)
        if alerta:
            self._registrar_alerta(alerta)
        return self.ids.esta_bloqueado(ev.cliente, ev.t)

    def atender(self, sock, endereco):
        cliente = endereco[0]                       # identidade = IP de origem
        canal = Canal(sock, self.chave)
        if self.ids and self.ids.esta_bloqueado(cliente, time.monotonic()):
            log(f"[IDS] conexão recusada de {cliente} (bloqueado)")
            canal.fechar()
            return
        log(f"[ECU] scanner conectado: {endereco[0]}:{endereco[1]}")
        try:
            while True:
                try:
                    req = canal.receber()
                except InvalidToken:
                    log(f"[ECU] token inválido de {cliente}: falha de decifragem/HMAC (descartado)")
                    with self.trava:
                        if self._observar(Evento(time.monotonic(), cliente, b"", b"", falha_cripto=True)):
                            break
                    continue
                with self.trava:
                    agora = time.monotonic()
                    if self.ids and self.ids.esta_bloqueado(cliente, agora):
                        break
                    try:
                        resp = self.ecu.processar(req, agora)
                    except FalhaECU as ex:
                        log(f"[ECU] !!! CRASH provocado por {hexa(req)} -> {ex}. Watchdog reiniciando ECU.")
                        self.ecu.reiniciar()
                        self._observar(Evento(agora, cliente, req, b"", crash=True))
                        break                       # ECU "caiu": conexão perdida
                    log(f"[ECU] {cliente} >> {hexa(req):<24} << {hexa(resp):<24} {descrever_resposta(resp)}")
                    if self._observar(Evento(agora, cliente, req, resp)):
                        break
                if resp:
                    canal.enviar(resp)
                else:
                    canal.enviar(b"")               # mantém o protocolo requisição/resposta
        except (ConnectionError, OSError):
            pass
        finally:
            canal.fechar()
            log(f"[ECU] conexão encerrada: {endereco[0]}:{endereco[1]}")

    def iniciar(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.host, self.porta))
        srv.listen()
        log(f"[ECU] aguardando scanner em {self.host}:{self.porta} | "
            f"cripto={'AES-Fernet' if self.chave else 'DESLIGADA (texto claro)'} | "
            f"IDS={'ligado' if self.ids else 'desligado'} | vulneravel={self.ecu.vulneravel}")
        try:
            while True:
                s, end = srv.accept()
                threading.Thread(target=self.atender, args=(s, end), daemon=True).start()
        except KeyboardInterrupt:
            log("[ECU] encerrando.")
        finally:
            srv.close()


def main():
    ap = argparse.ArgumentParser(description="ECU UDS simulada")
    ap.add_argument("--host", default=HOST_PADRAO, help="use 0.0.0.0 ou o IP do Tailscale para acesso remoto")
    ap.add_argument("--porta", type=int, default=PORTA_PADRAO)
    ap.add_argument("--sem-cripto", action="store_true")
    ap.add_argument("--sem-ids", action="store_true")
    ap.add_argument("--vulneravel", action="store_true")
    ap.add_argument("--retreinar", action="store_true", help="apaga e re-treina o modelo do IDS")
    a = ap.parse_args()
    if a.retreinar and os.path.exists(ARQ_MODELO):
        os.remove(ARQ_MODELO)
    chave = None if a.sem_cripto else carregar_chave()
    ids = None if a.sem_ids else preparar_ids()
    ServidorECU(a.host, a.porta, chave, ids, a.vulneravel).iniciar()


if __name__ == "__main__":
    main()
