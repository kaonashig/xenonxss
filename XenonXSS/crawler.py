import requests
from XenonXSS.utils.logger import Log
from XenonXSS.utils.session import build_session
from XenonXSS.core import Core
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from multiprocessing import Process

class Crawler:
    visited = []

    @classmethod
    def getLinks(cls, base, proxy, headers, cookie):
        lst = []
        conn = build_session(proxy, headers, cookie)
        try:
            text = conn.get(base).text
        except Exception as e:
            Log.warning("Crawler GET failed: " + str(e))
            return lst
        isi = BeautifulSoup(text, "html.parser")

        for obj in isi.find_all("a", href=True):
            url = obj["href"]
            full = urljoin(base, url)
            if full in cls.visited:
                continue
            if url.startswith("mailto:") or url.startswith("javascript:") or url.startswith("tel:"):
                continue
            # if link is same base or relative
            if full.startswith(base) or "://" not in url:
                lst.append(full)
                cls.visited.append(full)
        return lst

    @classmethod
    def crawl(cls, base, depth, proxy, headers, level, method, cookie):
        urls = cls.getLinks(base, proxy, headers, cookie)
        for url in urls:
            if url.startswith("https://") or url.startswith("http://"):
                Log.info("Spawning core for: " + url)
                p = Process(target=Core.run, args=(url, build_session(proxy, headers, cookie), level, method))
                p.start()
                p.join()
                if depth != 0:
                    cls.crawl(url, depth-1, proxy, headers, level, method, cookie)
                else:
                    break
