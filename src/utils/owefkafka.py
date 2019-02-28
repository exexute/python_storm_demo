#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2019-02-27 15:48:33
# @Author  : owefsad (1528360120@qq.com)
# @Link    : http://blog.51cto.com/executer
# @Version : $Id$

from pykafka import KafkaClient
from pykafka.common import OffsetType


class owef_kafka(object):
  def __init__(self, hosts=None):
    self.hosts=hosts
    self._get_client()

  def _get_client(self):
    if self.hosts:
      self.client = KafkaClient(hosts=self.hosts)
    else:
      print("hosts must has value")

  def _get_topic(self, topic):
    return self.client.topics[topic]

  def consumer(self, topic, zkhost, auto_commit_enable=True, auto_offset_reset=OffsetType.EARLIEST):
    _topic = self._get_topic(topic)
    self._consumer = _topic.get_balanced_consumer(consumer_group=topic+'_py', auto_commit_enable=auto_commit_enable, zookeeper_connect=zkhost)

  def readmsg(self):
    for msg in self._consumer:
      yield msg.value

  def producer(self, topic):
    _topic = self._get_topic(topic)
    self._producer = _topic.get_producer()

  def writemsg(self, msg):
    self._producer.produce(bytes(msg))

