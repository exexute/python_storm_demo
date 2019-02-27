#!encoding:utf8
import os
from collections import Counter
from streamparse import Bolt


class WordCountBolt(Bolt):
    outputs = ["message"]

    # bolts初始化函数， 用于初始化
    def initialize(self, conf, ctx):
        self.counter = Counter()
        self.pid = os.getpid()

    def parse(self, tup):
        self.logger.info(str(tup))


    def process(self, tup):
        if is_heartbeat(tup):
            pass
        else:
            self.emit([self.parse(tup)])
            self.ack(tup)
