## easyss

有报道表明访问国外技术网站正变得越来越困难，即使用了SS代理技术也面临被干扰的可能性。 
为了以防万一，提前准备，在我看了SS协议后，想再SS协议基础上做一些改进以对抗干扰和嗅探。

## TODO

* 重新实现精简版的SS协议，致力于无障碍访问国外技术网站，只考虑支持高强度的加密算法，如：aes-256-gcm, aes-256-cfb

* 客户端在和服务器交换访问地址部分协议，改为http2的帧格式 ，并对playload部分加密

* 加入客户端和服务器之间随机间隔随机数据大小的随机数据交互，达到初级的干扰嗅探的目的

## Current status

Alpha 
