import json
import requests

def build_session(proxy_json: str | None, ua: str | None, cookies: dict):
    """
    Cria e retorna uma requests.Session configurada.
    proxy_json: string JSON com proxies (ex: '{"http":"http://127.0.0.1:8080"}') ou None
    ua: user-agent desejado (ou None para padrão)
    cookies: dict com cookies já carregados
    """
    sess = requests.Session()
    sess.headers.update({"User-Agent": ua or "XenonXSS/1.0"})
    # proxies
    try:
        if proxy_json:
            sess.proxies.update(json.loads(proxy_json))
    except Exception:
        # se proxy_json já for dict, tenta aplicar direto
        try:
            sess.proxies.update(proxy_json)
        except Exception:
            pass
    # cookies
    try:
        if cookies:
            sess.cookies.update(cookies)
    except Exception:
        pass

    # desabilitar warnings SSL
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        sess.verify = False
    except Exception:
        pass

    return sess
