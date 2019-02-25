from itertools import cycle

from streamparse import Spout
from pykafka import KafkaClient
from pykafka.common import OffsetType


class WordSpout(Spout):
    outputs = ["word"]
    def consumer(self, hosts=None, topic=None, auto_commit_enable=None, auto_offset_reset=None):
        _client = KafkaClient(hosts=hosts)
        _topic = _client.topics[topic]
        _consumer = _topic.get_simple_consumer(consumer_group=topic+'_py', auto_commit_enable=auto_commit_enable, auto_offset_reset=auto_offset_reset)
        for msg in _consumer:
            yield msg.value
    def initialize(self, stormconf, context):
        self.logger.info("enter words initialize function")
        self.messages = self.consumer(hosts="10.129.7.121:9092", topic='auditlog', auto_commit_enable=True, auto_offset_reset=OffsetType.EARLIEST)

    def next_tuple(self):
        msg = next(self.messages)
        self.logger.info("enter words next_tuple function"+str(msg))
        #self.logger.info(
        #        "read data {}".format(msg)
        #    )
        self.emit([msg])
