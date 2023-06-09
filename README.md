# WX-forensics
微信取证小师，Windows提取微信登录状态下的信息，及解密硬盘中的数据库，图片，形成web浏览

可用于取证登录状态下的微信数据，也可以结合红队知识进行社工

TODO: 寻找新版本下登录微信的wxid偏移，修改文件结构


# 使用
### Main.py(old.py)
![image](https://github.com/i-Corner/WX-forensics/assets/80880063/520ab926-7a07-456a-8623-3ce4caebf834)
#### 在-r -D_B得到解密数据库后，直接运行getHtmlData.py，再打开html文件即可查看
#### 目前版本为3.9.5.81(64bit操作，旧版本均为32bit操作，old.py为3.9.2.26)，不同版本偏移不同，请看提示进行操作

登陆微信，微信版本最好是3.9.5.81，否则可能出现兼容性问题。
如果是旧版本微信3.9.2.x，使用old.py。
使用python main.py -h获取帮助。
使用python main.py -r -D_B解密数据库，如下图所示。
![1686324351248](https://github.com/i-Corner/WX-forensics/assets/82853570/de0cc569-d18a-40f6-b145-388be2fd751e)

使用python main.py -r -D_I解密图片，如下图所示。由于没有多线程操作，图片数量大时，耗费时间长，可自行Ctrl+C中断。
![image](https://github.com/i-Corner/WX-forensics/assets/82853570/aae5a0b7-2158-49d5-b8f3-cf0f50f28b6e)
使用python getHtmlData.py提取数据，如下图所示。
![image](https://github.com/i-Corner/WX-forensics/assets/82853570/db907ff3-4645-4f31-82f7-db627522218c)
执行完上述操作后，打开Wechat.html即可浏览结果。

# 提示
若无法运行main.py -r命令，请参考pdf寻找当前版本的偏移地址，而AES key地址则需要寻找网上公布的偏移（拥有了一次则可以不断查询新版本的）

# 维护
该项目主要用于数字取证大作业，后续可能仅帮忙更新AES Key地址

# 参考
http://eotstxtab.top/2023/05/06/wechat%E8%81%8A%E5%A4%A9%E8%AE%B0%E5%BD%95db%E5%8F%96%E8%AF%81%E8%A7%A3%E5%AF%86/

https://github.com/x1hy9/WeChatUserDB

https://github.com/AdminTest0/SharpWxDump

https://zhuanlan.zhihu.com/p/130314175

https://www.zetetic.net/sqlcipher/design/

# 开源不易，各位请点个Star⭐，欢迎交流讨论

# 免责声明
本项目严禁用于非法目的，仅允许在安全授权的情况下对用户数据库进行备份，产生的所有不良后果与作者无关。

使用该工具则代表默认同意该条款;
