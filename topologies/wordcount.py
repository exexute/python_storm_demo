"""
Word count topology
"""

from streamparse import Grouping, Topology

from bolts.wordcount import WordCountBolt
from spouts.kafkaspout import kafkaSpout


class WordCount(Topology):
    kafka_spout = kafkaSpout.spec()
    count_bolt = WordCountBolt.spec(inputs={kafka_spout: Grouping.fields("message")}, par=2)
