"""Start the Sentinela SOC Simulator and open it in your browser."""
import os
import sys
import threading
import webbrowser

import uvicorn
from dotenv import load_dotenv

load_dotenv()
# 127.0.0.1: this PC only (default). 0.0.0.0: agents on other machines can send events (needs SENTINELA_INGEST_KEY).
HOST = os.getenv("SENTINELA_HOST", "127.0.0.1")
PORT = int(os.getenv("SENTINELA_PORT", "8000"))


def main():
    if HOST not in ("127.0.0.1", "localhost", "::1") and not os.getenv("SENTINELA_INGEST_KEY", "").strip():
        sys.exit(f"SENTINELA_HOST={HOST} lets other machines connect, so set SENTINELA_INGEST_KEY in .env first "
                 "(see agent/README.md).")
    url = f"http://127.0.0.1:{PORT}"  # the console itself is only served to this PC
    print(f"Sentinela SOC Simulator: {url}  (press Ctrl+C to stop)")
    if HOST != "127.0.0.1":
        print(f"Agents on other machines: send to http://<this PC's IP address>:{PORT} with the ingest key")
    threading.Timer(1.5, webbrowser.open, args=[url]).start()
    uvicorn.run("sentinela.api:app", host=HOST, port=PORT, access_log=False)  # keep the terminal for alerts


if __name__ == "__main__":
    main()
