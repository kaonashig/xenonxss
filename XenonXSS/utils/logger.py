# XenonXSS/utils/Log.py
import sys

class Log:
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    PURPLE = "\033[95m"
    PINK = "\033[35m"
    NEON = "\033[38;5;213m"  # neon magenta
    LIGHT_BLUE = "\033[38;5;51m"  # neon azul claro
    RESET = "\033[0m"
    BOLD = "\033[1m"
    BRIGHT_GREEN = "\033[92m"
    NEON_GREEN = "\033[38;5;82m"
    FOSFORECENT = "\033[38;5;226m"
    BRANCO = "\033[37m"

    @staticmethod
    def banner():
        print(f"""
{Log.NEON}{Log.BOLD}
╔═╗╔═╗╔╗ ╔═╗╔╗╔  ╔═╗╔═╗╔═╗
║ ╦║╣ ╠╩╗║ ║║║║──║  ╠═╣╚═╗
╚═╝╚═╝╚═╝╚═╝╝╚╝  ╚═╝╩ ╩╚═╝
{Log.LIGHT_BLUE}        XENON XSS SCANNER
{Log.RESET}
        """)

    @staticmethod
    def info(msg):
        print(f"{Log.NEON}[INFO]{Log.RESET} {msg}")

    @staticmethod
    def warning(msg):
        print(f"{Log.FOSFORECENT}[WARN]{Log.RESET} {msg}")

    @staticmethod
    def high(msg):
        print(f"{Log.NEON_GREEN}[HIT!]{Log.RESET} {Log.BOLD}{msg}{Log.RESET}")

    @staticmethod
    def error(msg):
        print(f"{Log.PINK}[ERROR]{Log.RESET} {msg}")

    @staticmethod
    def success(msg):
        print(f"{Log.CYAN}[OK]{Log.RESET} {msg}")
