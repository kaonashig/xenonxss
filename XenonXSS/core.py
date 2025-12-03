import os
import sys
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from XenonXSS.utils.logger import Log
from XenonXSS.utils.session import build_session

# Caminho padrão para salvar resultados simples
XSS_TEXT = os.path.join(os.getcwd(), "xss.txt")

class Core:
    @staticmethod
    def run(url: str, sess, payload: str, methods: int):
        try:
            Core(url, sess, payload, methods).main()
        except KeyboardInterrupt:
            sys.stdout = sys.__stdout__
            print("\n\033[1;31m[!] Scan interrompido pelo usuário.\033[0m\n")
            sys.exit(0)
        except Exception as e:
            Log.warning(f"[Core.run] Erro inesperado: {e}")

    def __init__(self, url, sess, payload, methods):
        self.url = url
        self.session = sess
        self.payload = payload
        self.method = methods
        self.body = ""

    # ------------------------------
    def post_method(self):
        try:
            bsObj = BeautifulSoup(self.body, "html.parser")
            forms = bsObj.find_all("form", method=True)
            for form in forms:
                try:
                    action = form.get("action", self.url)
                    if form.get("method", "").lower().strip() != "post":
                        continue

                    Log.warning("Formulário com método POST encontrado: " + urljoin(self.url, action))
                    Log.info("Coletando campos de formulário...")

                    keys = {}
                    for key in form.find_all(["input", "textarea"]):
                        name = key.get("name")
                        if not name:
                            continue
                        typ = key.get("type", "").lower()
                        value = "" if typ == "submit" else self.payload
                        Log.info(f"Campo: {name} → {value}")
                        keys[name] = value

                    if not keys:
                        Log.info("Nenhum campo válido encontrado no formulário POST, ignorando.")
                        continue

                    Log.info("Enviando payload (POST)...")
                    try:
                        req = self.session.post(urljoin(self.url, action), data=keys)
                        if self.payload in req.text:
                            Log.high("Detected XSS (POST) at " + urljoin(self.url, req.url))
                            with open(XSS_TEXT, "a") as f:
                                f.write(str(req.url) + "\n\n")
                            Log.high("Post data: " + str(keys))
                        else:
                            Log.info("POST enviado, mas não refletiu payload (não confirmado).")
                    except KeyboardInterrupt:
                        raise
                    except Exception as e:
                        Log.warning("Falha no POST: " + str(e))
                except KeyboardInterrupt:
                    raise
                except Exception as e:
                    Log.warning("Erro interno no loop do POST: " + str(e))
        except KeyboardInterrupt:
            raise
        except Exception as e:
            Log.warning("Erro interno no post_method: " + str(e))

    # ------------------------------
    def get_method_form(self):
        try:
            bsObj = BeautifulSoup(self.body, "html.parser")
            forms = bsObj.find_all("form", method=True)
            for form in forms:
                try:
                    action = form.get("action", self.url)
                    if form.get("method", "").lower().strip() != "get":
                        continue

                    Log.warning("Formulário com método GET encontrado: " + urljoin(self.url, action))
                    Log.info("Coletando campos de formulário...")

                    keys = {}
                    for key in form.find_all(["input", "textarea"]):
                        name = key.get("name")
                        if not name:
                            continue
                        typ = key.get("type", "").lower()
                        value = "" if typ == "submit" else self.payload
                        Log.info(f"Campo: {name} → {value}")
                        keys[name] = value

                    if not keys:
                        Log.info("Nenhum campo válido encontrado no formulário GET, ignorando.")
                        continue

                    Log.info("Enviando payload (GET - formulário)...")
                    try:
                        req = self.session.get(urljoin(self.url, action), params=keys)
                        if self.payload in req.text:
                            Log.high("Detected XSS (GET) at " + urljoin(self.url, req.url))
                            with open(XSS_TEXT, "a") as f:
                                f.write(str(req.url) + "\n\n")
                            Log.high("GET data: " + str(keys))
                        else:
                            Log.info("GET enviado, mas não refletiu payload (não confirmado).")
                    except KeyboardInterrupt:
                        raise
                    except Exception as e:
                        Log.warning("Falha no GET(form): " + str(e))
                except KeyboardInterrupt:
                    raise
                except Exception as e:
                    Log.warning("Erro interno no loop do GET(form): " + str(e))
        except KeyboardInterrupt:
            raise
        except Exception as e:
            Log.warning("Erro interno no get_method_form: " + str(e))

    # ------------------------------
    def get_method(self):
        try:
            bsObj = BeautifulSoup(self.body, "html.parser")
            links = bsObj.find_all("a", href=True)
            for a in links:
                try:
                    href = a["href"]
                    if href.startswith(("mailto:", "tel:", "javascript:")):
                        Log.info("Ignorando link não-HTTP: " + href)
                        continue

                    base = urljoin(self.url, href)
                    query = urlparse(base).query
                    if query:
                        Log.warning("Link com query encontrado: " + query + " (possível ponto XSS)")
                        try:
                            if "=" in query:
                                qp = query.replace(query[query.find("=")+1:], self.payload, 1)
                                test = base.replace(query, qp, 1)
                            else:
                                test = base
                            query_all = base.replace(query, urlencode({x: self.payload for x in parse_qs(query)}))
                        except Exception:
                            test = base
                            query_all = base

                        Log.info("Testando URL (GET): " + test)
                        try:
                            _respon = self.session.get(test, verify=False)
                            if self.payload in _respon.text or self.payload in self.session.get(query_all).text:
                                Log.high("Detected XSS (GET) at " + _respon.url)
                                with open(XSS_TEXT, "a") as f:
                                    f.write(str(_respon.url) + "\n\n")
                            else:
                                Log.info("Payload GET não refletido (não confirmado).")
                        except KeyboardInterrupt:
                            raise
                        except Exception as e:
                            Log.warning("Falha ao testar GET link: " + str(e))
                except KeyboardInterrupt:
                    raise
                except Exception as e:
                    Log.warning("Erro interno no loop do GET link: " + str(e))
        except KeyboardInterrupt:
            raise
        except Exception as e:
            Log.warning("Erro interno no get_method: " + str(e))

    # ------------------------------
    def main(self):
        print("")
        Log.info("*" * 15)
        Log.info("Verificando conexão com: " + self.url)
        try:
            ctr = self.session.get(self.url)
            self.body = ctr.text
        except KeyboardInterrupt:
            raise
        except Exception as e:
            Log.high("Erro interno: " + str(e))
            return

        if getattr(ctr, "status_code", 500) > 400:
            Log.info("Falha na conexão: " + str(getattr(ctr, "status_code", 0)))
            return
        else:
            Log.info("Conexão estabelecida com sucesso! (" + str(ctr.status_code) + ")")

        try:
            if self.method >= 2:
                self.post_method()
                self.get_method()
                self.get_method_form()
            elif self.method == 1:
                self.post_method()
            elif self.method == 0:
                self.get_method()
                self.get_method_form()
        except KeyboardInterrupt:
            sys.stdout = sys.__stdout__
            print("\n\033[1;31m[!] Scan interrompido pelo usuário.\033[0m\n")
            sys.exit(0)
        except Exception as e:
            Log.warning("Erro durante execução principal: " + str(e))
