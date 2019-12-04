from time import time, sleep
from pprint import pformat
import pytest
import re

# TODO 接入

class BlackList:

    def __init__(self):

        self._ip_block_interval = 50000  # s
        # ip 黑名单
        self._ip = {}
        # illegal words，use `in` syntax to match
        self._message_in = {}
        # illegal words, use '==' syntax to match
        self._message_all = {}
        # illegal words, use regex syntex to match
        self._message_regex = {}

    @property
    def ip(self):
        return self._ip

    def add_ip(self, ip: str, delay: int = 10):
        self._ip[ip] = time() + delay

    @property
    def message(self):
        return {'in': self._message_in, 'regex': self._message_regex, 'all': self._message_all}

    def add_message(self, message: str, _type: str = 'all', delay: int = 30) -> bool:
        """add a illegal message to blacklist, return if it's successful added."""
        if _type == 'all':
            self._message_all[message] = time() + delay
            return True
        elif _type == 'in':
            self._message_in[message] = time() + delay
            return True
        elif _type == 'regex':
            prog = re.compile(message)
            self._message_regex[prog] = time() + delay
            return True
        else:
            return False

    def remove_message(self, message: str, _type: str = 'all'):
        if _type == 'all':
            self._message_all.pop(message)
            return True
        elif _type == 'in':
            self._message_in.pop(message)
            return True
        elif _type == 'regex':
            self._message_regex.pop(message)
            return True
        else:
            return False

    def lookup_ip(self, ip: str) -> bool:
        """Lookup if the ip is on blacklist."""
        _time = self._ip.get(ip)

        if _time is None:
            return False

        if time() > _time:
            # remove the ip from the blacklist.
            self._ip.pop(ip)
            return False

        return True

    def lookup_message(self, message: str) -> bool:
        """Lookup if message is on blacklist."""
        ret_val = False

        if message in self._message_all:
            if self._message_all[message] < time():
                # 
                self._message_all.pop(message)
                return False
            else:
                return True

        remove_list = []
        for msg_in in self._message_in.keys():
            if msg_in in message:
                if self._message_in[msg_in] < time():
                    remove_list.append(msg_in)
                else:
                    ret_val = True
                    break
        
        [self._message_in.pop(_item_to_be_removed) for _item_to_be_removed in remove_list]

        if ret_val == True:
            return True

        remove_list = []
        for msg_regex in self._message_regex:
            if msg_regex.match(message):
                if self._message_regex[msg_regex] < time():
                    remove_list.append(msg_in)
                else:
                    ret_val = True
                    break
    
        [self._message_regex.pop(_item_to_be_removed) for _item_to_be_removed in remove_list]

        if ret_val == True:
            return True

        return False

    def __repr__(self):
        """Formatting display when print.
        
        Returns:
            str -- formatted string.
        """
        return pformat({'ip': self.ip, 'message': {
            'all': self._message_all, 'in': self._message_in, 'regex': self._message_regex
        }})


if __name__ == '__main__':
    from pprint import pprint as p
    bl = BlackList()
    assert(len(bl.ip) == 0)
    assert(len(bl._message_all) == 0)
    assert(len(bl._message_in) == 0)
    bl.add_ip('test')
    assert(len(bl.ip) == 1)
    bl.add_message("tesooot", "all")
    assert(len(bl._message_all) == 1)
    bl.add_message("hello", "in")
    assert(len(bl._message_in) == 1)
    assert(bl.lookup_ip('test') == True)
    assert(bl.lookup_ip('random') == False)
    assert(bl.lookup_message('hello') == True)
    assert(bl.lookup_message('zhello234') == True)
    assert(bl.lookup_message('Hello') == False)
    bl.add_message('^Email*','regex')
    assert(bl.lookup_message('Email') == True)
    assert(bl.lookup_message('Email34234') == True)
    assert(bl.lookup_message('aEmail34234') == False)
    p(bl)
    sleep(3)
    assert(bl.lookup_ip('test') == False)
    p(bl)