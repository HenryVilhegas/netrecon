"""
Módulo de Relatório do NetRecon.

Aqui eu gero um relatório em Markdown com o resultado do recon.
Funciona tanto para host discovery quanto para port scan — passo o que
eu tiver e ele monta as seções correspondentes.
"""

from __future__ import annotations

import datetime
from pathlib import Path


def _linha_tabela_hosts(host) -> str:
    """Monto uma linha da tabela de hosts."""
    nome = host.hostname or "desconhecido"
    lat = f"{host.latency_ms:.1f} ms" if host.latency_ms is not None else "-"
    return f"| {host.ip} | {nome} | {lat} |"


def _linha_tabela_portas(porta) -> str:
    """Monto uma linha da tabela de portas (limpo o banner pra caber)."""
    banner = porta.banner.replace("\n", " ").replace("\r", " ")
    banner = banner.replace("|", "/")[:80] if banner else "-"
    return f"| {porta.numero} | {porta.servico} | {banner} |"


def gerar_relatorio(
    alvo: str,
    hosts=None,
    portas=None,
    caminho: str = "relatorio_netrecon.md",
) -> str:
    """
    Gero o relatório em Markdown e salvo em disco.

    Args:
        alvo: alvo escaneado (string original informada pelo usuário).
        hosts: lista de Host (host discovery), ou None.
        portas: lista de Porta (port scan), ou None.
        caminho: arquivo de saída.

    Returns:
        O caminho onde o relatório foi salvo.
    """
    agora = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    linhas: list[str] = []

    linhas.append("# Relatório NetRecon\n")
    linhas.append(f"- **Alvo:** {alvo}")
    linhas.append(f"- **Data/hora:** {agora}")

    # Seção de hosts (só aparece se eu tiver feito discovery).
    if hosts is not None:
        linhas.append(f"- **Hosts ativos encontrados:** {len(hosts)}\n")
        linhas.append("## Hosts ativos\n")
        if hosts:
            linhas.append("| IP | Hostname | Latência |")
            linhas.append("|----|----------|---------:|")
            linhas.extend(_linha_tabela_hosts(h) for h in hosts)
        else:
            linhas.append("Nenhum host ativo encontrado.")
        linhas.append("")

    # Seção de portas (só aparece se eu tiver feito port scan).
    if portas is not None:
        linhas.append(f"- **Portas abertas encontradas:** {len(portas)}\n")
        linhas.append("## Portas abertas\n")
        if portas:
            linhas.append("| Porta | Serviço | Banner |")
            linhas.append("|------:|---------|--------|")
            linhas.extend(_linha_tabela_portas(p) for p in portas)
        else:
            linhas.append("Nenhuma porta aberta encontrada no intervalo escaneado.")
        linhas.append("")

    linhas.append("\n---\n")
    linhas.append("> Gerado por NetRecon. Uso autorizado apenas.")

    conteudo = "\n".join(linhas)
    destino = Path(caminho)
    destino.write_text(conteudo, encoding="utf-8")
    return str(destino)
