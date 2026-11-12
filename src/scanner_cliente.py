"""
scanner_cliente.py - Ferramenta de diagnóstico (técnico/oficina) e cenários de ataque.

Modos:
  sessao       (padrão) sessão legítima: 10 03 -> 27 01 -> 27 02 -> leituras
  interativo   digite requisições UDS em hexadecimal (ex.: 22 F1 90)
  chave-errada envia chaves incorretas (demonstra NRC 35/36/37 e o IDS)
  forca-bruta  força bruta rápida no 27 02
  varredura    enumeração de todos os SIDs 0x00-0xFF
  sem-chave    atacante sem a chave AES injeta tokens forjados

Exemplos:
  python scanner_cliente.py
  python scanner_cliente.py --modo forca-bruta
  python scanner_cliente.py --host 100.x.y.z     # IP da ECU no Tailscale
"""
import argparse
import os
import random
import time

from ecu_core import algoritmo_chave, descrever_resposta
from protocolo import HOST_PADRAO, PORTA_PADRAO, Canal, carregar_chave, de_hexa, hexa
import socket


class Scanner:
    def __init__(self, host, porta, chave):
        self.canal = Canal(socket.create_connection((host, porta), timeout=5), chave)

    def pedir(self, req: bytes, rotulo: str = "") -> bytes:
        self.canal.enviar(req)
        resp = self.canal.receber()
        print(f"  >> {hexa(req):<26} << {hexa(resp):<26} {descrever_resposta(resp)} {rotulo}")
        return resp

    def fechar(self):
        self.canal.fechar()


def sessao_legitima(sc: Scanner, chave_correta=True):
    pausa = lambda: time.sleep(random.uniform(0.4, 1.2))
    sc.pedir(b"\x10\x03", "(sessão estendida)"); pausa()
    resp = sc.pedir(b"\x27\x01", "(requestSeed)")
    if not resp.startswith(b"\x67\x01"):
        print("[Scanner] ECU recusou o pedido de seed."); return False
    seed = int.from_bytes(resp[2:6], "big")
    chave = algoritmo_chave(seed) if chave_correta else random.getrandbits(32)
    print(f"[Scanner] seed=0x{seed:08X} -> key=algoritmo_secreto(seed)=0x{chave:08X}"); pausa()
    resp = sc.pedir(b"\x27\x02" + chave.to_bytes(4, "big"), "(sendKey)")
    if resp != b"\x67\x02":
        print("[Scanner] NEGADO: chave inválida."); return False
    print("\n[Resposta da ECU]: AUTORIZADO: Acesso de diagnóstico concedido!\n"); pausa()
    vin = sc.pedir(b"\x22\xF1\x90", "(ler VIN)")
    print(f"[Scanner] VIN = {vin[3:].decode(errors='replace')}"); pausa()
    sc.pedir(b"\x22\xF1\x95", "(versão de SW)"); pausa()
    sc.pedir(b"\x3E\x00", "(TesterPresent)")
    return True


def main():
    ap = argparse.ArgumentParser(description="Scanner de diagnóstico UDS")
    ap.add_argument("--host", default=HOST_PADRAO)
    ap.add_argument("--porta", type=int, default=PORTA_PADRAO)
    ap.add_argument("--modo", default="sessao",
                    choices=["sessao", "interativo", "chave-errada", "forca-bruta", "varredura", "sem-chave"])
    ap.add_argument("--sem-cripto", action="store_true")
    a = ap.parse_args()
    chave = None if a.sem_cripto else carregar_chave()
    print(f"[Scanner] conectando a {a.host}:{a.porta} (cripto={'AES-Fernet' if chave else 'NENHUMA'})")
    sc = Scanner(a.host, a.porta, chave)
    try:
        if a.modo == "sessao":
            sessao_legitima(sc)
        elif a.modo == "chave-errada":
            for i in range(5):
                print(f"\n[Scanner] tentativa {i + 1} com chave errada")
                sessao_legitima(sc, chave_correta=False)
        elif a.modo == "interativo":
            print("Digite requisições em hexa (ex.: 10 03 | 27 01 | 22 F1 90). 'sair' encerra.")
            print("Atalho: 'key' calcula e envia a chave para o último seed recebido.")
            ultimo_seed = None
            while True:
                linha = input("UDS> ").strip()
                if linha.lower() in ("sair", "exit", "q"):
                    break
                try:
                    if linha.lower() == "key" and ultimo_seed is not None:
                        req = b"\x27\x02" + algoritmo_chave(ultimo_seed).to_bytes(4, "big")
                    else:
                        req = de_hexa(linha)
                except ValueError:
                    print("  hexadecimal inválido"); continue
                resp = sc.pedir(req)
                if resp.startswith(b"\x67\x01") and len(resp) == 6:
                    ultimo_seed = int.from_bytes(resp[2:], "big")
        elif a.modo == "forca-bruta":
            sc.pedir(b"\x10\x03")
            for i in range(300):
                r = sc.pedir(b"\x27\x01")
                if r[:1] == b"\x7F":
                    time.sleep(0.05); continue
                sc.pedir(b"\x27\x02" + random.getrandbits(32).to_bytes(4, "big"), f"(tentativa {i})")
        elif a.modo == "varredura":
            for sid in range(0x100):
                sc.pedir(bytes([sid, 0x00]))
                time.sleep(0.01)
        elif a.modo == "sem-chave":
            for i in range(10):
                print(f"  >> token forjado #{i + 1} (sem conhecer a chave AES)")
                sc.canal.enviar_bruto(b"gAAAAA" + os.urandom(80))
                time.sleep(0.3)
            print("[Scanner] Fim. Verifique o log da ECU: tokens descartados pelo HMAC.")
    except (ConnectionError, OSError) as ex:
        print(f"\n[Scanner] conexão encerrada pela ECU ({ex.__class__.__name__}) "
              f"- provável bloqueio pelo IDS.")
    finally:
        sc.fechar()


if __name__ == "__main__":
    main()
