#!encoding:utf8
import os
from collections import Counter
from streamparse import Bolt
from utils import owef_kafka
import re
import time

def create_timestamp():
    return int(round(time.time() * 1000))

def parse(msg):
    _msg = '{"timestamp":'+str(create_timestamp())
    try:
      pattern=re.compile(u'^fwlog: \u65e5\u5fd7\u7c7b\u578b:([\w\W\u4e00-\u9fa5]+), (?:\u5e94\u7528\u7c7b\u578b:([\w\W\u4e00-\u9fa5]+), \u7528\u6237\u540d/\u4e3b\u673a:((?:(?:25[0-5]|2[0-4]\d|(?:1\d{2}|[1-9]?\d))\.){3}(?:25[0-5]|2[0-4]\d|(?:1\d{2}|[1-9]?\d))), \u4e0a\u884c\u6d41\u91cf\(KB\):(\d+), \u4e0b\u884c\u6d41\u91cf\(KB\):(\d+), \u603b\u6d41\u91cf\(KB\):(\d+)|\u7b56\u7565\u540d\u79f0:([\w\W\u4e00-\u9fa5]+), (?:\u89c4\u5219ID|\u7279\u5f81ID):(\d+), \u6e90IP:((?:(?:25[0-5]|2[0-4]\d|(?:1\d{2}|[1-9]?\d))\.){3}(?:25[0-5]|2[0-4]\d|(?:1\d{2}|[1-9]?\d))), \u6e90\u7aef\u53e3:(\d+), \u76ee\u7684IP:((?:(?:25[0-5]|2[0-4]\d|(?:1\d{2}|[1-9]?\d))\.){3}(?:25[0-5]|2[0-4]\d|(?:1\d{2}|[1-9]?\d))), \u76ee\u7684\u7aef\u53e3:(\d+), \u653b\u51fb\u7c7b\u578b:([\w\W\u4e00-\u9fa5]+), \u4e25\u91cd\u7ea7\u522b:([\w\W\u4e00-\u9fa5]+), \u7cfb\u7edf\u52a8\u4f5c:([\w\W\u4e00-\u9fa5]+), URL:([\w\W]*)|\u7b56\u7565\u540d\u79f0:([\w\W\u4e00-\u9fa5]+), \u6f0f\u6d1eID:(\d+), \u6f0f\u6d1e\u540d\u79f0:([\w\W\u4e00-\u9fa5]+), \u6e90IP:((?:(?:25[0-5]|2[0-4]\d|(?:1\d{2}|[1-9]?\d))\.){3}(?:25[0-5]|2[0-4]\d|(?:1\d{2}|[1-9]?\d))), \u6e90\u7aef\u53e3:(\d+), \u76ee\u7684IP:((?:(?:25[0-5]|2[0-4]\d|(?:1\d{2}|[1-9]?\d))\.){3}(?:25[0-5]|2[0-4]\d|(?:1\d{2}|[1-9]?\d))), \u76ee\u7684\u7aef\u53e3:(\d+), \u534f\u8bae:([\w\W\u4e00-\u9fa5]+), \u653b\u51fb\u7c7b\u578b:([\w\W\u4e00-\u9fa5]+), \u4e25\u91cd\u7b49\u7ea7:([\w\W\u4e00-\u9fa5]+), \u52a8\u4f5c:([\w\W\u4e00-\u9fa5]+))')
      matchobj = pattern.match(msg)
      if matchobj:
        fwtype = matchobj.group(1)
        _msg+=',"fwtype":"'+fwtype.encode('utf-8')+'","source:type":"'+'firewall'
        if fwtype==u'WEB\u5e94\u7528\u9632\u62a4':
          _msg+='","policy":"'+matchobj.group(7).encode('utf-8')+'","feature_id":"'+matchobj.group(8).encode('utf-8')+'","src_ip":"'+matchobj.group(9).encode('utf-8')+'","dest_ip":"'+matchobj.group(11).encode('utf-8')+'","attack_type":"'+matchobj.group(13).encode('utf-8')+'","level":"'+matchobj.group(14).encode('utf-8')+'","sys_action":"'+matchobj.group(15).encode('utf-8')+'","uri":"'+matchobj.group(16).encode('utf-8')
        elif fwtype == u'\u6d41\u91cf\u5ba1\u8ba1':
          _msg+='","policy":"'+matchobj.group(1).encode('utf-8')+'","flux_type":"'+matchobj.group(2).encode('utf-8')+'","host":"'+matchobj.group(3).encode('utf-8')+'","upflux":"'+matchobj.group(4).encode('utf-8')+'KB","downflux":"'+matchobj.group(5).encode('utf-8')+'KB","totalflux":"'+matchobj.group(6).encode('utf-8')+'KB'
        elif fwtype == u'\u50f5\u5c38\u7f51\u7edc\u65e5\u5fd7':
          #pass
          _msg = '{"policy":"'+matchobj.group(7).encode('utf-8')+'","feature_id":"'+matchobj.group(8).encode('utf-8')+'", "src_port":"'+matchobj.group(10).encode('utf-8')+'", "src_ip":"'+matchobj.group(9).encode('utf-8')+'", "dest_ip":"'+matchobj.group(11).encode('utf-8')+'", "dest_port":"'+matchobj.group(12).encode('utf-8')+'", "uri":"'+matchobj.group(16).encode('utf-8')+'", "attack_type":"'+matchobj.group(13).encode('utf-8')+'", "level":"'+matchobj.group(14).encode('utf-8')+'", "sys_action":"'+matchobj.group(15).encode('utf-8')
        elif fwtype == u'IPS\u9632\u62a4\u65e5\u5fd7':
          _msg = '{"policy":"'+matchobj.group(17).encode('utf-8')+'","feature_id":"'+str(matchobj.group(18))+'", "vuln_name":"'+matchobj.group(19).encode('utf-8')+'", "src_ip":"'+matchobj.group(20).encode('utf-8')+'", "src_port":"'+matchobj.group(21).encode('utf-8')+'", "dest_ip":"'+matchobj.group(22).encode('utf-8')+'", "dest_port":"'+str(matchobj.group(23))+'", "protocol":"'+matchobj.group(24).encode('utf-8')+'", "attack_type":"'+matchobj.group(25).encode('utf-8')+'", "level":"'+matchobj.group(26).encode('utf-8')+'", "sys_action":"'+matchobj.group(27).encode('utf-8')
        else:
          print(msg.decode("utf-8"))
      else:
        print(messamsg.decode("utf-8"))
    except Exception as e:
      raise e
      print(msg.decode('utf-8'))
    else:
      pass
    return _msg+'"}'

class WordCountBolt(Bolt):
    outputs = ["message"]

    # bolts初始化函数， 用于初始化
    def initialize(self, conf, ctx):
        self.counter = Counter()
        self.pid = os.getpid()
        self.ok = owef_kafka(hosts="10.129.7.l21:9092")
        self.ok.producer('indexing')

    def process(self, tup):
        message = parse(tup.values[0])
        self.ok.writemsg(msg=message)
        '''
        self.logger.error(tup.values[0])
        message=parse(tup.values[0])
        if message:
            self.emit([message])
        '''
