"""
Módulo de Host Discovery do NetRecon.

Descobre hosts ativos em uma faixa de rede usando ping (ICMP via subprocess).
Escolhemos ping por subprocess em vez de raw sockets/scapy para:
  - Funcionar no Windows sem privilégios de administrador
  - Não exigir instalação do Npcap
  - Manter a dependência apenas na biblioteca padrão

Uso responsável: utilize SOMENTE em redes que você possui ou tem
permissão explícita para testar (labs, TryHackMe, HackTheBox, rede própria).
"""

from __future__ import annotations

import ipaddress
import locale
import platform
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field


# Detecta o sistema operacional uma única vez no import.
_IS_WINDOWS = platform.system().lower() == "windows"


@dataclass
class Host:
    """Representa um host descoberto na rede."""

    ip: str
    is_alive: bool = False
    hostname: str | None = None
    # Tempo de resposta em milissegundos, quando disponível.
    latency_ms: float | None = field(default=None)

    def __str__(self) -> str:
        nome = self.hostname or "desconhecido"
        lat = f"{self.latency_ms:.1f} ms" if self.latency_ms is not None else "-"
        return f"{self.ip:<15} {nome:<25} {lat}"


def _build_ping_command(ip: str, timeout_ms: int) -> list[str]:
    """
    Monta o comando de ping adequado ao SO atual.

    Usamos lista de argumentos (não string) para evitar injeção de comando:
    o IP nunca é interpretado pelo shell.
    """
    if _IS_WINDOWS:
        # -n 1: envia 1 pacote | -w: timeout em milissegundos
        return ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    # Linux/macOS: -c 1: 1 pacote | -W: timeout em segundos
    timeout_s = max(1, timeout_ms // 1000)
    return ["ping", "-c", "1", "-W", str(timeout_s), ip]


def _parse_latency(output: str) -> float | None:
    """Extrai a latência (ms) da saída do ping, se presente."""
    # Windows: "tempo=12ms" / "time=12ms" ; Unix: "time=12.3 ms"
    lower = output.lower()
    for marcador in ("time=", "tempo=", "time<", "tempo<"):
        idx = lower.find(marcador)
        if idx == -1:
            continue
        trecho = lower[idx + len(marcador):]
        numero = ""
        for ch in trecho:
            if ch.isdigit() or ch == ".":
                numero += ch
            elif numero:
                break
        if numero:
            try:
                return float(numero)
            except ValueError:
                return None
    return None


def ping_host(ip: str, timeout_ms: int = 1000) -> Host:
    """
    Faz ping em um único host e retorna um objeto Host.

    Args:
        ip: endereço IP a verificar.
        timeout_ms: tempo máximo de espera pela resposta em milissegundos.

    Returns:
        Host com is_alive indicando se respondeu ao ping.
    """
    host = Host(ip=ip)
    cmd = _build_ping_command(ip, timeout_ms)
    try:
        # Capturamos bytes brutos (sem text=True) porque o ping do Windows
        # em locales não-ingleses (ex: pt-BR) emite a saída em code pages
        # como cp850/cp1252, não UTF-8. Decodificar como UTF-8 resultaria
        # em string vazia/corrompida. Decodificamos manualmente com o
        # encoding preferido do console e ignoramos erros residuais.
        resultado = subprocess.run(
            cmd,
            capture_output=True,
            timeout=(timeout_ms / 1000) + 2,
        )
    except (subprocess.TimeoutExpired, OSError):
        return host

    stdout_texto = _decode_console(resultado.stdout)

    # No Windows, o ping pode retornar 0 mesmo com "host inacessível",
    # então checamos também o conteúdo da saída.
    saida = stdout_texto.lower()
    respondeu = resultado.returncode == 0 and not (
        "unreachable" in saida
        or "inacess" in saida
        or "esgotado" in saida
        or "timed out" in saida
        or "100% loss" in saida
        or "100% packet loss" in saida
    )

    if respondeu:
        host.is_alive = True
        host.latency_ms = _parse_latency(stdout_texto)
        host.hostname = _resolve_hostname(ip)

    return host


def _decode_console(dados: bytes) -> str:
    """
    Decodifica bytes da saída de um comando de console.

    No Windows em português, o ping usa cp850/cp1252 em vez de UTF-8.
    Tentamos a codificação preferida do sistema e, em último caso,
    decodificamos ignorando bytes inválidos para nunca perder a saída.
    """
    if not dados:
        return ""
    for enc in (locale.getpreferredencoding(False), "cp850", "utf-8"):
        try:
            return dados.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return dados.decode("utf-8", errors="ignore")


def _resolve_hostname(ip: str) -> str | None:
    """Tenta resolver o hostname via DNS reverso. Retorna None se falhar."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return None


def expand_targets(target: str) -> list[str]:
    """
    Expande um alvo em uma lista de IPs.

    Aceita:
        - CIDR: "192.168.1.0/24"
        - IP único: "192.168.1.10"
        - Faixa simples: "192.168.1.1-20"

    Raises:
        ValueError: se o formato do alvo for inválido.
    """
    target = target.strip()

    # Faixa com hífen: 192.168.1.1-20
    if "-" in target and "/" not in target:
        base, _, fim = target.rpartition(".")
        inicio_fim = fim.split("-")
        if len(inicio_fim) == 2:
            inicio, ultimo = inicio_fim
            try:
                return [
                    f"{base}.{n}"
                    for n in range(int(inicio), int(ultimo) + 1)
                ]
            except ValueError as exc:
                raise ValueError(f"Faixa inválida: {target}") from exc

    # CIDR ou IP único
    try:
        rede = ipaddress.ip_network(target, strict=False)
    except ValueError as exc:
        raise ValueError(f"Alvo inválido: {target}") from exc

    if rede.num_addresses == 1:
        return [str(rede.network_address)]

    # .hosts() já exclui endereço de rede e broadcast automaticamente.
    return [str(ip) for ip in rede.hosts()]


def discover_hosts(
    target: str,
    timeout_ms: int = 1000,
    max_threads: int = 100,
    only_alive: bool = True,
) -> list[Host]:
    """
    Descobre hosts ativos em uma faixa de rede.

    Args:
        target: faixa CIDR, IP único ou faixa com hífen.
        timeout_ms: timeout do ping por host.
        max_threads: número máximo de pings concorrentes.
        only_alive: se True, retorna apenas hosts que responderam.

    Returns:
        Lista de Host, ordenada por IP.
    """
    ips = expand_targets(target)
    resultados: list[Host] = []

    # Limita threads ao número de alvos para não criar workers ociosos.
    workers = max(1, min(max_threads, len(ips)))

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futuros = {
            executor.submit(ping_host, ip, timeout_ms): ip for ip in ips
        }
        for futuro in as_completed(futuros):
            host = futuro.result()
            if host.is_alive or not only_alive:
                resultados.append(host)

    # Ordena por IP de forma numérica correta.
    resultados.sort(key=lambda h: ipaddress.ip_address(h.ip))
    return resultados


if __name__ == "__main__":
    # Teste rápido manual do módulo.
    import sys

    # Garante que caracteres acentuados no cabeçalho não travem a saída
    # em consoles Windows configurados com code page legada.
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

    alvo = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    print(f"[*] Descobrindo hosts em: {alvo}\n")
    ativos = discover_hosts(alvo)
    print(f"{'IP':<15} {'HOSTNAME':<25} LATÊNCIA")
    print("-" * 55)
    for h in ativos:
        print(h)
    print(f"\n[+] {len(ativos)} host(s) ativo(s) encontrado(s).")
