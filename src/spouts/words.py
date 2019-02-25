from itertools import cycle

from streamparse import Spout
from pykafka import KafkaClient


class WordSpout(Spout):
    outputs = ["word"]

    def initialize(self, stormconf, context):
        self.logger.info("enter words initialize function")
        client = KafkaClient(hosts="10.129.7.121:9092")
        topic = client.topics['firewalllog']
        self.consumer = topic.get_balanced_consumer(consumer_group='firewalllog', auto_commit_enable=True)

    def next_tuple(self):
        msg = next(self.consumer)
        self.logger.info("enter words next_tuple function")
        #self.logger.info(
        #        "read data {}".format(msg)
        #    )
        self.emit([msg])
