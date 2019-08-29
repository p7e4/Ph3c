# ph3c
适用于我校的内网客户端Linux版

# 使用
```
$ sudo python ph3c.py
--> Sent EAPOL Start
Got EAP_TYPE_NOTE
--> Send EAP response with Notification
Got EAP Request for identity
--> Sent EAP response with identity
Got EAP Request for MD5 challenge
--> Send EAP response with MD5 challenge
Got EAP Success
```
# 修改配置
`
$ sudo python ph3.py -r
`

# 依赖
- Python2
- 主流Linux发行版, OpenWrt


# 参考
- YaH3C(https://github.com/humiaozuzu/YaH3C/)
- eapy.py(http://www.secdev.org/python/eapy.py)
- 802.1x技术介绍(http://www.h3c.com/cn/d_200812/624138_30003_0.htm)
