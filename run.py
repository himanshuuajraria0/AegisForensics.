# run.py
import webbrowser
import threading
import time
from app import app
from tests.make_disk import create_demo_media


def open_browser():
    time.sleep(1.2)
    webbrowser.open("http://127.0.0.1:5000")


if __name__ == "__main__":
    create_demo_media()
    threading.Thread(target=open_browser).start()
    app.run(host="127.0.0.1", port=5000, debug=False)