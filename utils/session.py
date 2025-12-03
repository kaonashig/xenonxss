import requests

def build_session(headers=None, proxies=None, timeout=10):
    """
    Cria e retorna uma sessão HTTP configurada.
    Pode receber headers e proxies opcionais.
    """
    session = requests.Session()
    session.headers.update({
        "User-Agent": "XenonXSS/1.0 (compatible; Mozilla/5.0)"
    })
    if headers:
        session.headers.update(headers)
    if proxies:
        session.proxies.update(proxies)
    session.timeout = timeout
    return session
PY
