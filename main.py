#! /usr/bin/python
import tornado
from tornado import web, websocket
import os
from tornado.options import define, options
import logging
from tornado.locks import Condition, Semaphore

define("port", default=8888, help="run on the given port", type=int)


class EchoWebSocket(websocket.WebSocketHandler):
    #
    clients = set()
    # write_semaphore = Semaphore() # defualt = 1

    def check_origin(self, origin):
        return True

    # @classmethod
    def send_to_all(self, message: str):
        # TODO 增加错误处理
        logging.info("sending message %s to %d waiters",
                     message, len(EchoWebSocket.clients))
        for c in (c for c in EchoWebSocket.clients if id(c) != id(self)):
            try:
                c.write_message(message)
            except:
                c.close()

    def open(self):
        EchoWebSocket.clients.add(self)
        self.send_to_all(repr(id(self))+" entered room.")

    def on_message(self, message):
        self.send_to_all(message)

    def on_close(self):
        EchoWebSocket.clients.remove(self)
        self.send_to_all(repr(id(self))+" leave room.")


class HTMLHandler(web.RequestHandler):
    def get(self):
        self.render("index.html")


class Application(tornado.web.Application):
    def __init__(self):
        handlers = [
            (r"/", HTMLHandler),
            (r"/websocket", EchoWebSocket)]
        settings = dict(
            cookie_secret="__TODO:_GENERATE_YOUR_OWN_RANDOM_VALUE_HERE__",  # TODO
            template_path=os.path.join(os.path.dirname(__file__), "templates"),
            static_path=os.path.join(os.path.dirname(__file__), "static"),
            xsrf_cookies=True,
            debug=True
        )

        super(Application, self).__init__(handlers, **settings)


def main():
    tornado.options.parse_command_line()
    app = Application()
    app.listen(options.port)
    tornado.ioloop.IOLoop.current().start()


if __name__ == "__main__":
    main()
