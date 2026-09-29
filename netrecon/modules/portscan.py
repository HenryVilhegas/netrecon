"""
Módulo de Port Scanning do NetRecon.

Escaneia portas TCP de um alvo usando sockets da biblioteca padrão e
threads para concorrência (rápido). Em portas abertas, tenta pegar o
banner do serviço para ajudar na identificação.

Uso responsável: eu só uso isso em redes/sistemas com autorização
explícita (meus próprios, labs, TryHackMe, HackTheBox).
"""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass


# Aqui eu mapeio numero da porta -> nome do servico que costuma rodar ali.
# Uso como "palpite" quando nao consigo pegar o banner.
SERVICOS_COMUNS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
}


@dataclass
class Porta:
    """Representa uma porta aberta encontrada no alvo."""

    numero: int
    servico: str = "desconhecido"
    banner: str = ""

    def __str__(self) -> str:
        banner = self.banner.replace("\n", " ").replace("\r", " ")
        banner = banner[:60] if banner else "-"
        return f"{self.numero:<7} {self.servico:<12} {banner}"


def _pegar_banner(s: socket.socket, timeout: float = 1.0) -> str:
    """
    Tento ler o "banner" que alguns servicos mandam quando conecto
    (tipo a versao do SSH ou do servidor web). Uso o socket JA conectado.
    Se nao vier nada, devolvo string vazia (sem drama).
    """
    try:
        s.settimeout(timeout)
        # Alguns servicos (tipo HTTP) so respondem depois que eu mando algo.
        # Entao provoco mandando uma requisicao HEAD generica.
        try:
            s.send(b"HEAD / HTTP/1.0\r\n\r\n")
        except OSError:
            pass  # se nao der pra mandar, tudo bem, sigo tentando ler
        dados = s.recv(1024)
        # Os dados vem em bytes; converto pra texto ignorando lixo.
        return dados.decode(errors="ignore").strip()
    except OSError:
        # Deu timeout ou o servico nao manda banner. Normal.
        return ""


def testar_porta(ip: str, porta: int, timeout: float = 1.0) -> Porta | None:
    """
    Testo UMA porta. Se estiver aberta, devolvo um objeto Porta.
    Se estiver fechada/filtrada, devolvo None.
    """
    # Crio o socket: AF_INET = IPv4, SOCK_STREAM = TCP.
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)

    # connect_ex NAO estoura erro: devolve um numero.
    # 0 = conectou = porta ABERTA. Qualquer outro = fechada.
    resultado = s.connect_ex((ip, porta))

    if resultado == 0:
        banner = _pegar_banner(s, timeout)
        servico = SERVICOS_COMUNS.get(porta, "desconhecido")
        s.close()  # sempre fecho o que abro
        return Porta(numero=porta, servico=servico, banner=banner)

    s.close()
    return None


def scan_ports(
    ip: str,
    porta_inicio: int = 1,
    porta_fim: int = 1024,
    max_threads: int = 100,
    timeout: float = 1.0,
    on_open=None,
) -> list[Porta]:
    """
    Escaneio um intervalo de portas do alvo usando VARIAS threads ao mesmo tempo.
    Sem threads seria uma porta por vez (lento). Com threads, testo varias juntas.

    Args:
        ip: endereço IP do alvo (já resolvido).
        porta_inicio: primeira porta do intervalo.
        porta_fim: última porta do intervalo.
        max_threads: número máximo de threads simultâneas.
        timeout: timeout por porta em segundos.
        on_open: callback opcional chamado a cada porta aberta (para feedback ao vivo).

    Returns:
        Lista de Porta abertas, ordenada pelo número da porta.
    """
    portas = range(porta_inicio, porta_fim + 1)
    abertas: list[Porta] = []

    # Limito as threads ao numero de portas pra nao criar workers ociosos.
    workers = max(1, min(max_threads, porta_fim - porta_inicio + 1))

    # O ThreadPoolExecutor gerencia as threads pra mim.
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futuros = {
            executor.submit(testar_porta, ip, p, timeout): p for p in portas
        }
        # Conforme cada tarefa termina, pego o resultado.
        for futuro in as_completed(futuros):
            res = futuro.result()
            if res is not None:
                abertas.append(res)
                if on_open is not None:
                    on_open(res)

    # As threads terminam fora de ordem, entao ordeno pelo numero da porta.
    abertas.sort(key=lambda p: p.numero)
    return abertas


if __name__ == "__main__":
    # Teste rápido manual do módulo.
    import sys

    alvo = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    ip = socket.gethostbyname(alvo)
    print(f"[*] Escaneando {ip} (portas 1-1024)...\n")
    resultado = scan_ports(
        ip,
        on_open=lambda p: print(f"[+] Porta {p.numero} ABERTA ({p.servico})"),
    )
    print(f"\n[+] {len(resultado)} porta(s) aberta(s).")
