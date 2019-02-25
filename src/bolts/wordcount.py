#!encoding:utf8
import os
from collections import Counter

from streamparse import Bolt


class WordCountBolt(Bolt):
    outputs = ["hostname"]

    # bolts初始化函数， 用于初始化
    def initialize(self, conf, ctx):
        self.counter = Counter()
        self.pid = os.getpid()
        self.total = 0

    def _increment(self, word, inc_by):
        self.counter[word] += inc_by
        self.total += inc_by

    def process(self, tup):
        self.logger.info(help(tup))
        self.emit(["xss"])
