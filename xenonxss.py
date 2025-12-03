#!/usr/bin/env python3
"""
XenonXSS 2024 – varredura rápida e direta XSS.
"""

import argparse
import json
import sys
import io
import threading
from XenonXSS.core import Core
from XenonXSS.crawler import Crawler
from XenonXSS.utils.logger import Log
from XenonXSS.utils.session import build_session
from XenonXSS.utils.payloads import pick_payload
from contextlib import redirect_stdout

# =============================================================
# ARTES
# =============================================================
cli_art = """
\033[38;5;51m

                                       .&@#.  .#@@.
                      *&&((&@(       @/            *@
                   @            &( ,&  &@@@@/        &/
                 @                &@  @@@@@@@@        @.
                @.         #@@/    @  @@@@@@@/        @,      #@@
                @        @@@@@@@@  &&                %%/(%%&#//(#...
                /%       @@@@@@@@ *#(@*            ,@/(((//(/(/(((//(@.
            .@(..#@,       %@@#  &/////#@@*.  .*&@#////////////////(/&@.
            (&%((///(@(.     *&#(//(/////((//(/(((///(/(/(/(/(/(///////((%@
        (@#//((/////((//(/(////(///////////////////////////////////@#/(/&@.
       @&@@////(/(/(/(/(/(/(/(/(/(/(/(/(/(/(/(/(/(/(/(/(/(/((///(@%//////(#@
  %@@%(////////////////////////////((//(@@@#///@@%#///((&@@@@@@#////////(#&&(
   @@&(///(//(/(/(//((/(///(///(//@//&@@@@@@@@@@@@@@@@@@@@@@@@(////(/(////#@@@/
    @#/(&&(////(///((@///%@(##%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@///////////%@@@&.
   @#(/(#%@@&(//#&@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@///(/(/(/(//@.
   @#/(//(//(//@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@////(/////(//@.
   ,@&///(/(/(///%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#(///(/(///#/&@
     @&((//////////@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%///////////%&,
      #@/(/(/(/(////@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@((/(/(/(/(/((@.
       &(/////////////@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#////////////((&
      .@(%@(///(/(/(////%@@@@@@@@@@@@@@@@@@@@@@@@@@@@&/(/(/(/(///(//#@%@.
       .**.@/(/////////////(@@@@@@@@@@@@@@@@@@@@@@(///////////////(@/
            @%((///(/(/(/(/////(/#&@@@@@@@@%((///(///(/(///((/(@/@&.
             ,&@@(//////////////(////(((//((//(((////////////@(.
                ,@@(/////////////(/(/(/(/(/(/(/(/(///((&%%@%,
                  .%@@(@@@#&@&(/////////////////////&@*
                          ,*, ,@@@@@@@@&&&&@@%/, ..
\033[0m

\033[37m
         ##################################################################
         [!][!][!]   XenonXSS Cross-site Scripting by @kaonashig  [!][!][!]
         [+]    Tamper with care. Results may include surprise popups.  [+]
         ##################################################################

                      > https://github.com/kaonashig/XenonXSS

\033[0m
"""

final_art = """
\033[96m
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⡼⠶⢶⣶⡓⡒⠲⢤⣀⡀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡠⠔⠛⠿⣟⣛⣻⠿⠋⠋⢲⣯⣙⣆⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⡠⠊⠀⠀⢀⣀⣤⡤⠤⠤⠤⢤⣈⠑⠻⠟⢣⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⣰⠁⠀⠀⠀⠘⠀⠀⠀⠀⠙⠛⠒⠦⠝⢦⠀⢸⡄⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠃⢠⠃⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠘⢆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡸⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠈⠢⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡰⠃⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣲⣤⣤⠔⢾⡀⠀⠀⠀⢀⣠⠞⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣀⡤⠶⠛⠉⠉⠀⠀⠉⢹⢿⡉⠉⠉⠉⠀⠀⠀⠀⠀F-YEAH! check it out...
⠀⠀⠀⠀⢠⠞⠁⠀⠀⠀⠀⠀⠀⠀⠀⢸⡄⠳⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢠⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣇⠀⠘⢦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⢠⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡄⠀⠀⠙⠦⣄⡀⠀⠀⠀⠀⠀⠀
⢀⣴⣿⢤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣷⠀⠀⠀⠀⠀⠉⠛⠲⢤⣄⡀⠀
⡞⣯⢳⡀⠙⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡆⠀⠀⠀⠀⠀⠀⠀⠀⢸⢻⣆
⠃⠈⠀⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢷⠀⠀⠀⠀⠀⠀⠀⠀⠈⠘⠘
\033[0m
"""

hyperscan_art = """
\033[1;31m
⣿⣿⣿⣿⣿⣿⣿⣿⡿⠟⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠻⢿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⠟⠁⠀⠀⠀⠀⠀ TARGET COMPROMISED ⠀⠀⠀⠈⠻⣿⣿⣿⣿⣿⣿
  Vulnerabilidade crítica confirmada! Encerrando HyperScan...
\033[0m
"""

# =============================================================
# CLASSE DUPLICADORA DE SAÍDA
# =============================================================
class Tee(io.StringIO):
    def __init__(self):
        super().__init__()
        self._stdout = sys.__stdout__
    def write(self, data):
        self._stdout.write(data)
        super().write(data)
    def flush(self):
        self._stdout.flush()
        super().flush()

# =============================================================
# ARGUMENTOS
# =============================================================
def build_args():
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-u", metavar="", help="URL alvo (ex: http://teste.com.br)")
    parser.add_argument("--depth", type=int, default=2)
    parser.add_argument("--method", type=int, choices=[0,1,2], default=2)
    parser.add_argument("--single", metavar="", help="Testa uma única URL (sem crawler)")
    parser.add_argument("--custom", metavar="", help="Payload custom (<script>alert(1)</script>)")
    parser.add_argument("--proxy", metavar="", help='Proxy: {"http":"http://127.0.0.1:8080"}')
    parser.add_argument("--ua", metavar="", default=None)
    parser.add_argument("--cookie", metavar="", default='{"PHPSESSID":"1"}')
    parser.add_argument("-o", "--output", metavar="", help="Salvar relatório em arquivo")
    parser.add_argument("--hyper", action="store_true", help="Ativa o HyperScan (encerra em XSS crítico)")
    return parser.parse_args()

# =============================================================
# IMPRESSÃO DE RESULTADOS
# =============================================================
def print_summary(vulns, output_file=None):
    print(final_art)
    print("\033[38;5;213m═══════════════════════════════════════════════════════════\033[0m")
    print("\033[1;36m                 RELATÓRIO FINAL DE VULNERABILIDADES        \033[0m")
    print("\033[38;5;213m═══════════════════════════════════════════════════════════\033[0m\n")

    content = []
    if not vulns:
        msg = "[-] Nenhuma vulnerabilidade confirmada."
        print("\033[1;31m" + msg + "\033[0m")
        content.append(msg)
    else:
        for v in vulns:
            print(f"\033[1;32m[+] URL Vulnerável:\033[0m {v['url']}")
            print(f"\033[1;33m    Método:\033[0m {v['method']}")
            print(f"\033[1;36m    Payload:\033[0m {v['payload']}\n")
            content.append(f"[+] URL Vulnerável: {v['url']}\n    Método: {v['method']}\n    Payload: {v['payload']}\n")

    print("\033[38;5;213m═══════════════════════════════════════════════════════════\033[0m")
    print("\033[1;32mScan finalizado com sucesso! Confira os resultados acima.\033[0m\n")

    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write("Relatório XenonXSS\n\n")
            f.write("\n".join(content))
        print(f"\033[1;34m[+] Relatório salvo em:\033[0m {output_file}")

# =============================================================
# EXECUÇÃO PRINCIPAL
# =============================================================
def main():
    args = build_args()
    print(cli_art)
    Log.info("Iniciando XenonXSS...")

    payload = pick_payload(args.custom)
    sess = build_session(args.proxy, args.ua, json.loads(args.cookie))
    stop_flag = threading.Event()
    buffer = Tee()
    sys.stdout = buffer

    try:
        if args.hyper:
            Log.info("HyperScan ativado — interromperá ao detectar vulnerabilidade crítica!")
            for result in Core.run(url=args.u, sess=sess, payload=payload, methods=args.method):
                print(result)
                if "CRITICAL" in result or "Detecção crítica" in result:
                    print(hyperscan_art)
                    stop_flag.set()
                    break
        elif args.single:
            Core.run(url=args.single, sess=sess, payload=payload, methods=args.method)
        elif args.u:
            Core.run(url=args.u, sess=sess, payload=payload, methods=args.method)
            Crawler.crawl(base=args.u, depth=args.depth, proxy=args.proxy,
                          headers=args.ua, level=payload,
                          method=args.method, cookie=args.cookie)
        else:
            print("Use -u ou --single para iniciar.")
            return

    except KeyboardInterrupt:
        print("\n\033[1;31m[!] Scan interrompido pelo usuário.\033[0m\n")
        stop_flag.set()

    finally:
        sys.stdout = sys.__stdout__
        output = buffer.getvalue()
        vulns = []
        for line in output.splitlines():
            if "Detected XSS" in line or "Possível vulnerabilidade XSS" in line:
                vulns.append({
                    "url": line.split("at ")[-1].strip(),
                    "method": "GET",
                    "payload": payload
                })
        print_summary(vulns, args.output)

if __name__ == "__main__":
    main()
