# Burpsuite使用教程

**Chrome浏览器代理插件：Proxy SwitchyOmega**，直接在Chrome插件仓库搜索安装即可。





## Intruder

**Attack type：**

-   sniper：每次只对单个变量进行设置；

-   battering raw：每次可以设置一个变量的值，当攻击需要在请求中的多个位置插入相同的输入时，Battering ram 攻击很有用；

-   pitchfork：可以设置多个变量，每个变量都可以设置单独的payload，且多个变量取payload的顺序是一样的；这个每个变量设置payload数量以最少的那个为准；

    ![image-20230208214654222](C:\Users\friendship\Desktop\Pentest_Interview\burpsuite使用笔记\Burpsuite使用教程.assets\image-20230208214654222.png)

-   cluster bomb：可以设置变量，测试第一个变量payload列表的第一个时，会依次遍历其余变量所有的payload……；





详细使用教程：https://raw.githubusercontent.com/hack-umbrella/CIS/master/burp.png
