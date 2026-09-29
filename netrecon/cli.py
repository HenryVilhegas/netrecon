"""
CLI unificado do NetRecon.

Aqui eu monto a interface de linha de comando com dois subcomandos:
  - discover : descobre hosts ativos numa faixa de rede (ping)
  - scan     : escaneia portas TCP de um alvo (com banner grabbing)

Uso:
  python -m netrecon discover 192.168.0.0/24
  python -m netrecon scan 127.0.0.1 -i 1 -f 1024
"""

from __future__ import annotations

import argparse
import socket
import sys

from .modules import discovery, portscan, report


def _banner_inicial() -> None:
    # Banner ASCII pra dar cara de ferramenta de verdade.
    banner = r"""
 _   _      _   ____                      
| \ | | ___| |_|  _ \ ___  ___ ___  _ __  
|  \| |/ _ \ __| |_) / _ \/ __/ _ \| '_ \ 
| |\  |  __/ |_|  _ <  __/ (_| (_) | | | |
|_| \_|\___|\__|_| \_\___|\___\___/|_| |_|
"""
    print(banner)
    print("      scanner de rede & recon  |  by Henry Silva")
    print("   >> use SOMENTE com autorizacao explicita <<")
    print("=" * 55)


def cmd_discover(args: argparse.Namespace) -> None:
    """Subcomando discover: descobre hosts ativos na rede."""
    _banner_inicial()
    print(f"[*] Descobrindo hosts em: {args.alvo}\n")
    try:
        hosts = discovery.discover_hosts(
            args.alvo,
            timeout_ms=args.timeout,
            max_threads=args.threads,
            only_alive=not args.todos,
        )
    except ValueError as exc:
        print(f"[!] {exc}")
        return

    print(f"{'IP':<15} {'HOSTNAME':<25} LATENCIA")
    print("-" * 55)
    for h in hosts:
        print(h)
    print(f"\n[+] {len(hosts)} host(s) ativo(s) encontrado(s).")

    if args.output:
        caminho = report.gerar_relatorio(args.alvo, hosts=hosts, caminho=args.output)
        print(f"[*] Relatorio salvo em: {caminho}")


def cmd_scan(args: argparse.Namespace) -> None:
    """Subcomando scan: escaneia portas TCP de um alvo."""
    _banner_inicial()

    # Resolvo hostname -> IP (ex: 'localhost' vira '127.0.0.1').
    try:
        ip = socket.gethostbyname(args.alvo)
    except socket.gaierror:
        print(f"[!] Nao consegui resolver o alvo: {args.alvo}")
        return

    print(f"[*] Escaneando {ip} nas portas {args.inicio}-{args.fim} "
          f"com {args.threads} threads...\n")

    portas = portscan.scan_ports(
        ip,
        porta_inicio=args.inicio,
        porta_fim=args.fim,
        max_threads=args.threads,
        timeout=args.timeout,
        on_open=lambda p: print(f"[+] Porta {p.numero:>5} ABERTA  ({p.servico})"),
    )

    print(f"\n[*] Scan concluido. {len(portas)} porta(s) aberta(s).")

    if args.output:
        caminho = report.gerar_relatorio(args.alvo, portas=portas, caminho=args.output)
        print(f"[*] Relatorio salvo em: {caminho}")


def build_parser() -> argparse.ArgumentParser:
    """Monto o parser com os subcomandos."""
    parser = argparse.ArgumentParser(
        prog="netrecon",
        description="NetRecon - scanner de rede e recon automatizado.",
    )
    subparsers = parser.add_subparsers(dest="comando", required=True)

    # --- subcomando: discover ---
    p_disc = subparsers.add_parser(
        "discover", help="descobre hosts ativos numa faixa de rede (ping)"
    )
    p_disc.add_argument("alvo", help="CIDR, IP ou faixa (ex: 192.168.0.0/24)")
    p_disc.add_argument("-t", "--threads", type=int, default=100,
                        help="Numero de threads (padrao: 100)")
    p_disc.add_argument("--timeout", type=int, default=1000,
                        help="Timeout do ping por host em ms (padrao: 1000)")
    p_disc.add_argument("--todos", action="store_true",
                        help="Mostra tambem hosts que nao responderam")
    p_disc.add_argument("-o", "--output",
                        help="Salva relatorio Markdown no arquivo indicado")
    p_disc.set_defaults(func=cmd_discover)

    # --- subcomando: scan ---
    p_scan = subparsers.add_parser(
        "scan", help="escaneia portas TCP de um alvo (com banner grabbing)"
    )
    p_scan.add_argument("alvo", help="IP ou hostname do alvo (ex: 127.0.0.1)")
    p_scan.add_argument("-i", "--inicio", type=int, default=1,
                        help="Porta inicial (padrao: 1)")
    p_scan.add_argument("-f", "--fim", type=int, default=1024,
                        help="Porta final (padrao: 1024)")
    p_scan.add_argument("-t", "--threads", type=int, default=100,
                        help="Numero de threads (padrao: 100)")
    p_scan.add_argument("--timeout", type=float, default=1.0,
                        help="Timeout por porta em segundos (padrao: 1.0)")
    p_scan.add_argument("-o", "--output",
                        help="Salva relatorio Markdown no arquivo indicado")
    p_scan.set_defaults(func=cmd_scan)

    return parser


def main(argv: list[str] | None = None) -> int:
    # Garanto que acentos no cabecalho nao travem consoles Windows legados.
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
