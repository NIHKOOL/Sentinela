"""Start the Sentinela SOC Simulator and open it in your browser."""
import threading
import webbrowser

import uvicorn

HOST = "127.0.0.1"
PORT = 8000


def main():
    url = f"http://{HOST}:{PORT}"
    print(f"Sentinela SOC Simulator: {url}  (press Ctrl+C to stop)")
    threading.Timer(1.5, webbrowser.open, args=[url]).start()
    uvicorn.run("sentinela.api:app", host=HOST, port=PORT)


if __name__ == "__main__":
    main()
