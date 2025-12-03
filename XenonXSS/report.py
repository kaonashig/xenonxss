import json
import datetime
import os

_OUT_DIR = os.path.join(os.path.dirname(__file__), "../output")
os.makedirs(_OUT_DIR, exist_ok=True)

def save_find(url: str, method: str, params: dict):
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    f = os.path.join(_OUT_DIR, f"xenon_{stamp}.json")
    data = {"time": str(datetime.datetime.now()), "url": url, "method": method, "params": params}
    with open(f, "w") as fh:
        json.dump(data, fh, indent=2)
