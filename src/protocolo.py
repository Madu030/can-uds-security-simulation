"""
protocolo.py - Camada de transporte comum entre ECU e Scanner.

Cada mensagem UDS (bytes binários, ex.: 27 01) é:
  1. cifrada com AES-128-CBC + HMAC-SHA256 (Fernet)  -> E2EE na camada de aplicação
  2. enviada por TCP com um prefixo de 4 bytes indicando o tamanho do quadro

Com --sem-cripto o payload vai em claro (linha de base para o print do Wireshark).
"""
import os
import socket
import struct

from cryptography.fernet import Fernet, InvalidToken

HOST_PADRAO = "127.0.0.1"
PORTA_PADRAO = 5001
TAMANHO_MAX_QUADRO = 64 * 1024

_DIR = os.path.dirname(os.path.abspath(__file__))
ARQ_CHAVE = os.path.join(_DIR, "chave_secreta.key")


def carregar_chave(caminho: str = ARQ_CHAVE) -> bytes:
    """Lê a chave simétrica compartilhada; gera uma nova se não existir."""
    if not os.path.exists(caminho):
        with open(caminho, "wb") as f:
            f.write(Fernet.generate_key())
    with open(caminho, "rb") as f:
        return f.read().strip()


class Canal:
    """Envolve um socket TCP com enquadramento + cifragem opcional."""

    def __init__(self, sock: socket.socket, chave: bytes | None):
        self.sock = sock
        self.fernet = Fernet(chave) if chave else None

    # ---------- enquadramento ----------
    def _enviar_quadro(self, dados: bytes) -> None:
        self.sock.sendall(struct.pack(">I", len(dados)) + dados)

    def _receber_exato(self, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            parte = self.sock.recv(n - len(buf))
            if not parte:
                raise ConnectionError("conexão encerrada pelo outro lado")
            buf += parte
        return buf

    def _receber_quadro(self) -> bytes:
        (tam,) = struct.unpack(">I", self._receber_exato(4))
        if tam > TAMANHO_MAX_QUADRO:
            raise ConnectionError(f"quadro grande demais ({tam} bytes)")
        return self._receber_exato(tam)

    # ---------- API pública ----------
    def enviar(self, payload: bytes) -> None:
        dados = self.fernet.encrypt(payload) if self.fernet else payload
        self._enviar_quadro(dados)

    def enviar_bruto(self, dados: bytes) -> None:
        """Envia bytes sem cifrar (usado para simular um atacante sem a chave)."""
        self._enviar_quadro(dados)

    def receber(self) -> bytes:
        """Devolve o payload em claro. Lança InvalidToken se a cifra/HMAC falhar."""
        dados = self._receber_quadro()
        return self.fernet.decrypt(dados) if self.fernet else dados

    def fechar(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


def hexa(b: bytes) -> str:
    return " ".join(f"{x:02X}" for x in b) if b else "(vazio)"


def de_hexa(s: str) -> bytes:
    return bytes.fromhex(s.replace(" ", ""))


__all__ = ["Canal", "carregar_chave", "hexa", "de_hexa", "InvalidToken",
           "HOST_PADRAO", "PORTA_PADRAO"]
