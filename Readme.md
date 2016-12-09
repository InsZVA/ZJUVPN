# GO-ZJUVPN

## 说明

用Go写的VPN认证客户端跨平台（Win&Linux&Mac OS），目标是做一个没有依赖（不依赖于xl2tpd和pppd）的
浙大校园网认证客户端。目前是为有线&玉泉设计的。

## 特性

1. 没有依赖，不用安装xl2tpd和pppd，不用担心软件安装问题，也不用配置繁琐的脚本

2. 仅支持ZJUVPN

## 使用

`./gol2tp -u 学号@种类 -p 密码 -l 本地ip地址`

## 思路

使用`/dev/tun`设备建立虚拟网卡，承载l2tp和ppp协议。

## 进度

目前实现了l2tp协议的建立以及ppp协议的认证和断开。由于为ZJUVPN而设计，可能不支持其他L2TP的VPN，另外
只处理了正常情况，对于异常没有进行处理。

[x] l2tp会话建立

[x] ppp认证

[x] ppp传输

[x] 虚拟网卡安装

[ ] 配置路由表

[x] Windows支持

[x] 协议断开

[x] Windows测试

[ ] Linux测试

[ ] MacOS测试

## 测试问题

Windows：
必须先安装tap0901（可以通过openvpn安装），安装之后，测试UDP没有问题，但是TCP报文回来的都有错误。

## 感谢

[tun-go项目](https://github.com/FlexibleBroadband/tun-go)

[TAP-windows6项目](https://github.com/OpenVPN/tap-windows6)

[pppd项目](https://github.com/wkz/pppd)

[water项目](https://github.com/songgao/water)
