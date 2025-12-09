# socks5--proxy
 A SOCKS5 server and a forwarding proxy server are connected.

 一个socks5服务器和一个转发服务器。
 
 支持socks5的客户端连接socks5的服务器，socks5服务器会将请求转至转发服务器上，由转发服务器发出实现代理。

 作用：
 1.自己写的，GWF应该没有此程序的数据包的特征
 2.所有数据ASE加密

 使用：

 1.在选定的互联网转发服务器上运行 go run forwardServer.go，确保1081端口打开
 
 2，修改socks5V2.go文件，头部修改FORWARD_SERVER_ADDR等于转发服务器的IP，在本机运行 go run socks5V2.go

 3.我是MACOS，在设置->WIFI->详细信息->代理->socks5里面填入127.0.0.1，端口 1080
