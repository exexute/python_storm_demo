#!encoding:utf8
import os
from collections import Counter
from streamparse import Bolt
import re
import time

def create_timestamp():
    return int(round(time.time() * 1000))

def parse(msg):
    print(msg)
    message={}
    message['timestamp']=create_timestamp()
    try:
      message['source:type']='firewall'
      pattern=re.compile(u'^fwlog: \u65e5\u5fd7\u7c7b\u578b:([\w\W\u4e00-\u9fa5]+), (?:\u5e94\u7528\u7c7b\u578b:([\w\W\u4e00-\u9fa5]+), \u7528\u6237\u540d/\u4e3b\u673a:((?:(?:25[0-5]|2[0-4]\d|(?:1\d{2}|[1-9]?\d))\.){3}(?:25[0-5]|2[0-4]\d|(?:1\d{2}|[1-9]?\d))), \u4e0a\u884c\u6d41\u91cf\(KB\):(\d+), \u4e0b\u884c\u6d41\u91cf\(KB\):(\d+), \u603b\u6d41\u91cf\(KB\):(\d+)|\u7b56\u7565\u540d\u79f0:([\w\W\u4e00-\u9fa5]+), (?:\u89c4\u5219ID|\u7279\u5f81ID):(\d+), \u6e90IP:((?:(?:25[0-5]|2[0-4]\d|(?:1\d{2}|[1-9]?\d))\.){3}(?:25[0-5]|2[0-4]\d|(?:1\d{2}|[1-9]?\d))), \u6e90\u7aef\u53e3:(\d+), \u76ee\u7684IP:((?:(?:25[0-5]|2[0-4]\d|(?:1\d{2}|[1-9]?\d))\.){3}(?:25[0-5]|2[0-4]\d|(?:1\d{2}|[1-9]?\d))), \u76ee\u7684\u7aef\u53e3:(\d+), \u653b\u51fb\u7c7b\u578b:([\w\W\u4e00-\u9fa5]+), \u4e25\u91cd\u7ea7\u522b:([\w\W\u4e00-\u9fa5]+), \u7cfb\u7edf\u52a8\u4f5c:([\w\W\u4e00-\u9fa5]+), URL:([\w\W]*)|\u7b56\u7565\u540d\u79f0:([\w\W\u4e00-\u9fa5]+), \u6f0f\u6d1eID:(\d+), \u6f0f\u6d1e\u540d\u79f0:([\w\W\u4e00-\u9fa5]+), \u6e90IP:((?:(?:25[0-5]|2[0-4]\d|(?:1\d{2}|[1-9]?\d))\.){3}(?:25[0-5]|2[0-4]\d|(?:1\d{2}|[1-9]?\d))), \u6e90\u7aef\u53e3:(\d+), \u76ee\u7684IP:((?:(?:25[0-5]|2[0-4]\d|(?:1\d{2}|[1-9]?\d))\.){3}(?:25[0-5]|2[0-4]\d|(?:1\d{2}|[1-9]?\d))), \u76ee\u7684\u7aef\u53e3:(\d+), \u534f\u8bae:([\w\W\u4e00-\u9fa5]+), \u653b\u51fb\u7c7b\u578b:([\w\W\u4e00-\u9fa5]+), \u4e25\u91cd\u7b49\u7ea7:([\w\W\u4e00-\u9fa5]+), \u52a8\u4f5c:([\w\W\u4e00-\u9fa5]+))')
      print(msg)
      print(msg.decode('utf-8'))
      matchobj = pattern.match(msg.decode("utf-8"))
      if matchobj:
        fwtype = matchobj.group(1)
        message['fwtype']=fwtype
        if fwtype==u'WEB\u5e94\u7528\u9632\u62a4':
          message['policy']=matchobj.group(7)
          message['feature_id']=matchobj.group(8)
          message['src_ip']=matchobj.group(9)
          message['dest_ip']=matchobj.group(11)
          message['attack_type']=matchobj.group(13)
          message['level']=matchobj.group(14)
          message['sys_action']=matchobj.group(15)
          message['uri']=matchobj.group(16)
        elif fwtype == u'\u6d41\u91cf\u5ba1\u8ba1':
          message['policy']=matchobj.group(7)
          message['flux_type']=matchobj.group(2)
          message['host']=matchobj.group(3)
          message['upflux']=matchobj.group(4)
          message['downflux']=matchobj.group(5)
          message['totalflux']=matchobj.group(6)
        elif fwtype == u'\u50f5\u5c38\u7f51\u7edc\u65e5\u5fd7':
          #pass
          message['policy']=matchobj.group(7)
          message['feature_id']=matchobj.group(8)
          message['src_ip']=matchobj.group(9)
          message['src_port']=matchobj.group(10)
          message['dest_ip']=matchobj.group(11)
          message['dest_port']=matchobj.group(12)
          message['attack_type']=matchobj.group(13)
          message['level']=matchobj.group(14)
          message['sys_action']=matchobj.group(15)
          message['uri']=matchobj.group(16)
        elif fwtype == u'IPS\u9632\u62a4\u65e5\u5fd7':
          #pass
          message['policy']=matchobj.group(17)
          message['feature_id']=matchobj.group(18)
          message['vuln_name']=matchobj.group(19)
          message['src_ip']=matchobj.group(20)
          message['dest_ip']=matchobj.group(22)
          message['dest_port']=matchobj.group(23)
          message['protocol']=matchobj.group(24)
          message['attack_type']=matchobj.group(25)
          message['level']=matchobj.group(26)
          message['sys_action']=matchobj.group(27)
        else:
          print(msg.decode("utf-8"))
      else:
        print(messamsg.decode("utf-8"))
    except Exception as e:
      print(e)
    else:
      pass
    if len(message)>1:
      return message

class WordCountBolt(Bolt):
    outputs = ["message"]

    # bolts初始化函数， 用于初始化
    def initialize(self, conf, ctx):
        self.counter = Counter()
        self.pid = os.getpid()

    def process(self, tup):
        self.logger.error(tup.values[0])
        message=parse(tup.values[0])
        if message:
            self.emit([message])
