# GFWDnsResolver: 获取GFW DNS域名污染的真实IP的小工具

以前写的小工具，最近整理代码，再这里公布出来。这个小工具用于获取被gfw dns 污染域名的真实ip地址，通常可以用于获取twitter,youtube,facebook等网址的真实ip地址。

## 编译
    cd GFWDnsResolver
    javac GFWDnsResolver
## 运行示例
    java GFWDnsResolver www.youtube.com

输出：

    host:www.youtube.com The real ip is:173.194.72.102