from itertools import cycle

from streamparse import Spout
from utils import owef_kafka


class kafkaSpout(Spout):
    outputs = ["message"]

    def initialize(self, stormconf, context):
        owefk = owef_kafka(hosts="10.129.7.121:9092")
        owefk.consumer(topic='firewalllog', zkhost="xss.tita.gift:2181")
        self.messages = owefk.readmsg()

    def next_tuple(self):
        msg = next(self.messages)
        self.logger.error(type(msg))
        self.logger.error(type(str(msg)))
        self.emit([msg])
