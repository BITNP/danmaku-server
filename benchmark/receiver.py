"""只接受弹幕的人"""
import websocket
import time
import threading
import multiprocessing
import json
import logging


WS_URL = "ws://localhost:8888/websocket"

PROCESS_NUM = 4
THREAD_NUM = 20000
CONNECTION_DELAY = 500

def on_message(ws, message):
    # logging.info(message)
    pass


def on_error(ws, error):
    # logging.error(error)
    pass


def on_close(ws):
    # logging.info("### closed ###")
    pass


def on_open(ws):
    def send_thread():
        pass
    t = threading.Thread(target=send_thread)
    t.start()


def on_start(num):
    time.sleep(num % CONNECTION_DELAY)
    websocket.enableTrace(False)
    ws = websocket.WebSocketApp(
        WS_URL, on_message=on_message, on_error=on_error, on_close=on_close, on_open=on_open,)
    ws.run_forever()

def thread_web_socket():
    threads = []
    threads = [threading.Thread(target=on_start, args=(i,)) for i in range(THREAD_NUM)]
    [t.start() for t in threads]
    [t.join() for t in threads]

if __name__ == "__main__":
    pool = multiprocessing.Pool(processes=PROCESS_NUM)

    for i in range(PROCESS_NUM):
        pool.apply_async(thread_web_socket)

    pool.close()
    pool.join()
