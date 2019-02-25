import os
from collections import Counter

from streamparse import Bolt


class WordCountBolt(Bolt):
    outputs = ["word", "count"]

    # 
    def initialize(self, conf, ctx):
        self.logger.info("enter wordcount initalize function")
        self.counter = Counter()
        self.pid = os.getpid()
        self.total = 0

    def _increment(self, word, inc_by):
        self.logger.info("enter wordcount _increment function")
        self.counter[word] += inc_by
        self.total += inc_by

    def process(self, tup):
        self.logger.info("enter wordcount process function")
        word = tup.values[0]
        self._increment(word, 10 if word == "dog" else 1)
        self.emit([word, self.counter[word]])
