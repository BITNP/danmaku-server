#! /usr/bin/python
import tornado
from tornado import web, websocket
import os
from tornado.options import define, options
import logging
from tornado.locks import Condition, Semaphore
import json
from datetime import datetime
from time import time
from utils import BlackList
from tornado.log import enable_pretty_logging, access_log, app_log, gen_log, LogFormatter
from itertools import groupby, islice
import operator
from collections import Counter
from functools import reduce
from fluent import handler

custom_format = {
    'where': '%(module)s.%(funcName)s',
    'type': '%(levelname)s',
    'stack_trace': '%(exc_text)s'
}

l = logging.getLogger('mongo.log')
h = handler.FluentHandler('mongo.log', host="localhost", port=24224)
formatter = handler.FluentRecordFormatter(custom_format)
h.setFormatter(formatter)
l.addHandler(h)


enable_pretty_logging()
my_log_format = "[%(levelname)s][%(asctime)s][%(name)s]%(message)s\n"
my_log_formatter = LogFormatter(fmt=my_log_format, color=True)
root_logger = logging.getLogger()
root_streamhandler = root_logger.handlers[0]
# root_streamhandler.setLevel('WARN')
root_streamhandler.setFormatter(my_log_formatter)

MESSAGE_LEN_LIMIT = 30
ERROR_COUNT_LIMIT = 20

define("port", default=8888, help="run on the given port", type=int)


# def restrict_message_len(message): return len(message) <= MESSAGE_LEN_LIMIT

def restrict_message_len(message: str) -> bool:
    """Check if message's length is within limits.
    Limitation can be set via `MESAGE_LEN_LIMIT`.

    Arguments:
        message {str} -- Message to be sent.

    Returns:
        bool -- Retrun `True` if it's valid.
    """
    return len(message) <= MESSAGE_LEN_LIMIT


def restrict_message_send_interval(time_old: float, time_new: float) -> bool:
    """Check if message's sent interval is long enough.

    Arguments:
        time_old {float} -- Previous time.
        time_new {float} -- Current time.

    Returns:
        bool -- Return `True` if it's valid.
    """
    return time_new - time_old > 3


def valid_danmaku_type(danmaku: dict) -> bool:
    """Check if it's valid danmaku type.
    1. Contain no more than 3 attribute.
    2. Total content length < 90.
    3. `text` attribute must in it.

    Arguments:
        danmaku {dict} -- {'text': , 'type': , 'color': }

    Returns:
        bool -- [description]
    """
    return True if len(danmaku) <= 3 and len(str(danmaku)) < 90 and 'text' in danmaku else False


def validate_danmaku_no_restriction(danmaku: dict) -> bool:
    if 'token' in danmaku and danmaku['token'] == 'oh-my-fdl':
        danmaku.pop('token')
        return valid_danmaku_type(danmaku)
    else:
        return False


class EchoWebSocket(websocket.WebSocketHandler):
    # 使用 map 记录，真实值为 ip
    clients = set()
    # Blacklist
    blacklist = BlackList()

    def __init__(self, *arg, **kwargs):
        # store the timestamp when broadcase a message in last attempt.
        self.last_time_send_to_all = time()
        # 计算出错次数，达到一定程度则断开连接
        self.error_count = 0
        # 记录累计群发次数
        self.send_to_all_count = 0
        super().__init__(*arg, **kwargs)

    def __add_extra_logging_context(self, logging_message: str) -> str:
        return f"[{self.request.remote_ip}]{len(self.clients)}:" + logging_message

    def info(self, logging_message: str):
        logging.info(self.__add_extra_logging_context(logging_message))

    def warning(self, logging_message: str):
        logging.warning(self.__add_extra_logging_context(logging_message))

    def __exceeded_error_count(self):
        """handle event when `error_count` exceeded the limit."""
        # self.info("error_count exceeded limit, force to close connection!")
        l.warning(self.__basic_log_info(
            "malicious", "error_count exceeded limit, force to close connection!"))
        self.close()

    def __increment_error_count(self):
        """called to increment `error_count`, call `__exceeded_error_count` to deal malicious connection."""
        # self.info(f"`error_count` = {self.error_count + 1}")
        # l.warning(self.__basic_log_info("malicious", f"{self.error_count=}"))
        if self.error_count > ERROR_COUNT_LIMIT:
            self.__exceeded_error_count()
        self.error_count += 1

    def check_origin(self, origin):
        return True

    # @classmethod
    def send_to_all(self, message: dict) -> (bool, str):
        """"""
        # TODO 增加错误处理

        # If message length larger than limitation, exit and count error.
        if not restrict_message_len(message['text']):
            self.__increment_error_count()
            # Log as warning.
            # self.warning("message len larger than expect.")
            l.warning(self.__basic_log_info(
                "malicous", f"message[{message['text']}] length larger than expect."))
            return (False, 'your message length should not exceeded 30 character.')

        # If message sending interval larger than limitatoin, exit and count error.
        if not restrict_message_send_interval(self.last_time_send_to_all, time()):
            self.__increment_error_count()
            # self.warning("message sending interval smaller than expect.")
            l.warning(self.__basic_log_info(
                "malicious", "message sending interval smaller than expect."))
            return (False, 'your message sending interval must below 3s.')

        # If message is a banned, then we do not send the message, exit and count error.
        if EchoWebSocket.blacklist.lookup_message(message['text']):
            self.__increment_error_count()
            # Log as warning.
            # self.warning("ip on blacklist.")
            l.warning(self.__basic_log_info(
                "on_blacklist", "ip on blacklist."))
            return (False, 'your message including banned content.')

        # self.info(f"sending message {message} to all connections")
        l.info(self.__basic_log_info("send2all", message))
        payload: dict = {
            'type': 'danmaku',
            'data': message
        }
        payload: str = json.dumps(payload)
        for c in (c for c in EchoWebSocket.clients if id(c) != id(self)):
            try:
                c.write_message(payload)
            except:
                c.close()

        # update self.last_time_send_to_all
        self.last_time_send_to_all = time()
        # update self.send_to_all_count
        self.send_to_all_count += 1
        return (True, '')

    def send_to_all_no_restriction(self, message: dict):
        l.info(self.__basic_log_info("send2all_no_restriction", message))
        payload: dict = {
            'type': 'danmaku',
            'data': message
        }
        payload: str = json.dumps(payload)
        for c in (c for c in EchoWebSocket.clients if id(c) != id(self)):
            try:
                c.write_message(payload)
            except:
                c.close()
        self.send_to_all_count += 1
        return (True, '')


    @classmethod
    def statistics(cls) -> list:
        '''return statistics information.'''
        rst = []
        for c in cls.clients:
            remote_ip = c.request.headers.get("X-Real-IP") or \
                        c.request.headers.get("X-Forwarded-For") or \
                        c.request.remote_ip
            rst.append({
                'ip': remote_ip,
                'send_all_count': c.send_to_all_count,
                'error_count': c.error_count
            })
        return rst

    def open(self):

        # check if ip is in the blacklist
        # if EchoWebSocket.blacklist.lookup_ip(self.request.remote_ip):
            # self.info('ip on blacklist.')
            # self.close()
            # return
        EchoWebSocket.clients.add(self)
        # self.info(f"[{self}] Total {len(self.clients)} connection.")
        l.info(self.__basic_log_info("open", "WebSocket connect."))

    def on_message(self, message):

        if EchoWebSocket.blacklist.lookup_ip(self.request.remote_ip):
            # If ip is in the blacklist, log and close connection.
            # self.warning('ip on blacklist, close.')
            l.warning('malicious', 'ip on blacklist, close.')
            self.close()
            return

        try:
            message = json.loads(message)
        except:
            # 如果 json 切片 Error，那么直接丢弃或者断开连接
            # self.warning("JSON parse error.")
            l.warning(self.__basic_log_info('malicious', "JSON parse error."))
            self.close()
            # 严格处理下，应当直接加入黑名单
            return

        try:
            if message['type'] == 'danmaku' and valid_danmaku_type(message['data']):
                self.send_to_all(message['data'])
            elif message['type'] == 'danmaku_no_restriction' and validate_danmaku_no_restriction(message['data']):
                self.send_to_all_no_restriction(message['data'])
            else:
                # 如果格式错误，那么直接丢弃或者断开连接
                # self.warning(
                    # "Get message type danmaku, but it's not a valid danmaku type.")
                l.warning(self.__basic_log_info(
                    'malicious', "Get message type danmaku, but it's not a valid danmaku type."))
                self.close()
                return
        except Exception as e:
            l.warning(self.__basic_log_info(
                'melicious', f"Check danmaku type encounter error:[{e}]."))
            # self.warning(f"Check danmaku type encounter error:[{e}].")
            self.close()
            return

    def on_close(self):
        if self in EchoWebSocket.clients:
            EchoWebSocket.clients.remove(self)
        # self.info(f"[{self}][{self.request.remote_ip}] WebSocket close.")

        l.info(self.__basic_log_info('close', "WebSocket close."))
        # self.send_to_all(repr(id(self))+" leave room.")

    def __basic_log_info(self, _type, content) -> dict:
        remote_ip = self.request.headers.get("X-Real-IP") or \
            self.request.headers.get("X-Forwarded-For") or \
            self.request.remote_ip
        return {'ip': remote_ip, 'count': len(EchoWebSocket.clients),
                'id': id(self), 'type': _type, 'content': content, 'error_count': self.error_count,
                'send_count': self.send_to_all_count}


class AdminRequestHandler(web.RequestHandler):

    def prepare(self):
        if self.request.headers.get('APIKEY') != 'oh-my-tlb':
            self.set_status(400)
            self.finish()

    def get(self):
        _sort_by = self.get_argument('sort_by', 'default')
        _n = int(self.get_argument('n', 10000000))
        _reverse = True if self.get_argument('reverse', False) else False

        _rst = EchoWebSocket.statistics()
        if _sort_by == 'ip':
            _rst.sort(key=lambda x: x['ip'], reverse=_reverse)

            _t = [{ip: dict(reduce(operator.add, map(Counter, (i for i in item if (i.pop('ip') or True) and (i.update({'len': 1}) or True)))))}
                  for ip, item in islice(groupby(_rst, key=lambda x: x['ip']), max(0, _n))]
            self.write({'connections': _t})
            return

        elif _sort_by == 'default':
            pass
        elif _sort_by == 'error':
            _rst.sort(key=lambda x: x['error_count'], reverse=_reverse)
        elif _sort_by == 'send':
            _rst.sort(key=lambda x: x['send_all_count'], reverse=_reverse)
        else:
            self.set_status(500)
            self.finish()
        if _n <= 0:
            self.write({'connections': _rst})
        else:
            self.write({'connections': _rst[0:min(len(_rst), _n)]})


class AdminIPRequestHandler(AdminRequestHandler):

    def get(self):
        self.write({'message': EchoWebSocket.blacklist.ip})

    def post(self):
        _ip = self.get_argument('ip')
        _delay = self.get_argument('delay', 300)
        if _ip and _delay:
            EchoWebSocket.blacklist.add_ip(_ip, _delay)
            self.write({_ip: EchoWebSocket.blacklist._ip[_ip]})
        else:
            self.set_status(502)


class AdminMessageRequestHandler(AdminRequestHandler):

    def get(self):
        self.write({'message': EchoWebSocket.blacklist.message})

    def post(self):
        _message = self.get_argument('message')
        _type = self.get_argument('type', 'in')
        _delay = int(self.get_argument('delay', 300))
        if _message:
            EchoWebSocket.blacklist.add_message(_message, _type, _delay)
            self.write({_type: {_message: _delay}})
        else:
            self.set_status(502)


class HTMLHandler(web.RequestHandler):
    def get(self):
        self.render("index.html")


class Application(tornado.web.Application):
    def __init__(self):
        handlers = [
            (r"/", HTMLHandler),
            (r"/websocket", EchoWebSocket),
            (r"/admin", AdminRequestHandler),
            (r"/admin/ip", AdminIPRequestHandler),
            (r"/admin/message", AdminMessageRequestHandler),
        ]
        settings = dict(
            cookie_secret="__TODO:_GENERATE_YOUR_OWN_RANDOM_VALUE_HERE__",  # TODO
            template_path=os.path.join(os.path.dirname(__file__), "templates"),
            static_path=os.path.join(os.path.dirname(__file__), "static"),
            xsrf_cookies=False,
            debug=True,
        )

        super(Application, self).__init__(handlers, **settings)


def main():
    tornado.options.parse_command_line()
    app = Application()
    app.listen(options.port)
    tornado.ioloop.IOLoop.current().start()


if __name__ == "__main__":
    main()
