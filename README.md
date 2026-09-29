# NetRecon

Scanner de rede e recon automatizado, escrito em **Python puro** (só biblioteca padrão).
Feito como projeto de estudo/portfólio nas áreas de pentest e redes.

Em vez de "só chamar o nmap", aqui a lógica é escrita na mão: sockets TCP para o
port scan, ping para host discovery, threads para ganhar velocidade e geração de
relatório em Markdown.

## Aviso de uso responsável

Esta ferramenta deve ser usada **somente** em redes e sistemas para os quais você
tem **autorização explícita** (seus próprios equipamentos, laboratórios, TryHackMe,
HackTheBox, etc.). Escanear alvos de terceiros sem permissão é ilegal (no Brasil,
Lei 12.737/2012). Use com responsabilidade.

## Funcionalidades

- **Host discovery** — descobre hosts ativos numa faixa de rede via ping (aceita CIDR, IP único ou faixa)
- **Port scanning TCP** concorrente (threads) — rápido
- **Banner grabbing** — identifica o serviço que roda na porta
- **Detecção de serviços comuns** por número de porta
- **Relatório automático** em Markdown
- Interface de linha de comando com subcomandos (`argparse`)

## Requisitos

- Python 3.8+ (testado no 3.14)
- Nenhuma dependência externa (usa só a biblioteca padrão)

## Estrutura do projeto

```
netrecon/
├── netrecon/
│   ├── __init__.py
│   ├── __main__.py          # permite rodar com "python -m netrecon"
│   ├── cli.py               # CLI unificado (subcomandos discover e scan)
│   └── modules/
│       ├── __init__.py
│       ├── discovery.py     # host discovery (ping)
│       ├── portscan.py      # port scan TCP + banner grabbing
│       └── report.py        # geração de relatório Markdown
├── README.md
└── .gitignore
```

## Uso

A ferramenta roda como módulo, com dois subcomandos: `discover` e `scan`.

### Host discovery

```bash
# Descobrir hosts ativos numa rede /24
python -m netrecon discover 192.168.0.0/24

# IP único ou faixa com hífen
python -m netrecon discover 192.168.0.10
python -m netrecon discover 192.168.0.1-50

# Salvar relatório em Markdown
python -m netrecon discover 192.168.0.0/24 -o reports/hosts.md
```

### Port scan

```bash
# Scan básico (portas 1-1024) em localhost
python -m netrecon scan 127.0.0.1

# Escolher intervalo de portas e número de threads
python -m netrecon scan 192.168.0.10 -i 1 -f 65535 -t 300

# Salvar relatório
python -m netrecon scan scanme.nmap.org -o reports/scan.md
```

### Ver todas as opções

```bash
python -m netrecon --help
python -m netrecon discover --help
python -m netrecon scan --help
```

### Argumentos do `scan`

| Argumento | Descrição | Padrão |
|-----------|-----------|--------|
| `alvo` | IP ou hostname do alvo | (obrigatório) |
| `-i, --inicio` | Porta inicial | 1 |
| `-f, --fim` | Porta final | 1024 |
| `-t, --threads` | Número de threads | 100 |
| `--timeout` | Timeout por porta (segundos) | 1.0 |
| `-o, --output` | Arquivo de saída do relatório | (não salva se omitido) |

### Argumentos do `discover`

| Argumento | Descrição | Padrão |
|-----------|-----------|--------|
| `alvo` | CIDR, IP ou faixa com hífen | (obrigatório) |
| `-t, --threads` | Número de threads | 100 |
| `--timeout` | Timeout do ping por host (ms) | 1000 |
| `--todos` | Mostra também hosts que não responderam | (desligado) |
| `-o, --output` | Arquivo de saída do relatório | (não salva se omitido) |

## Exemplo de saída

```
=======================================================
 NetRecon - eu uso SOMENTE com autorizacao explicita
=======================================================
[*] Escaneando 127.0.0.1 nas portas 1-1024 com 200 threads...

[+] Porta   135 ABERTA  (MSRPC)
[+] Porta   445 ABERTA  (SMB)

[*] Scan concluido. 2 porta(s) aberta(s).
[*] Relatorio salvo em: reports\scan.md
```

## Como funciona (resumo técnico)

**Port scan:**
1. Para cada porta, abre um socket TCP (`socket.AF_INET`, `socket.SOCK_STREAM`).
2. Usa `connect_ex` (retorna `0` se a porta aceita conexão) em vez de `connect`,
   evitando ter que tratar exceções para cada porta fechada.
3. Distribui as portas entre várias threads com `ThreadPoolExecutor`.
4. Em portas abertas, tenta ler o banner do serviço.

**Host discovery:**
1. Expande o alvo (CIDR/IP/faixa) em uma lista de IPs.
2. Faz ping em cada IP em paralelo (via `subprocess`, sem exigir privilégios de admin).
3. Trata a codificação da saída do ping em Windows pt-BR (cp850/cp1252).
4. Resolve o hostname via DNS reverso quando possível.

## Roadmap (próximos passos)

- [ ] Exportar relatório também em HTML
- [ ] Detecção de versão mais robusta por serviço
- [ ] Integração discover + scan num único fluxo (descobrir hosts e já escanear os ativos)

## Licença

Uso educacional. Sinta-se livre para estudar e adaptar.
