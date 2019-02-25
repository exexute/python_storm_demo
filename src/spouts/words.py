from itertools import cycle

from streamparse import Spout
from pykafka import KafkaClient
from pykafka.common import OffsetType


class WordSpout(Spout):
    outputs = ["word"]

    def initialize(self, stormconf, context):
        self.logger.info("enter words initialize function")
        client = KafkaClient(hosts="10.129.7.121:9092")
        topic = client.topics['auditlog']
        self.consumer = topic.get_simple_consumer(consumer_group='auditlog_py', auto_commit_enable=True,
            auto_offset_reset=OffsetType.EARLIEST)

    def next_tuple(self):
        msg = next(self.consumer)
        self.logger.info("enter words next_tuple function"+str(msg.value))
        #self.logger.info(
        #        "read data {}".format(msg)
        #    )
        self.emit([msg.value])
