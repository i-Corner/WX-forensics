# WX-forensics
微信取证小师，提取微信登录状态下的信息，及解密硬盘中的数据库，图片，形成web浏览

可用于取证登录状态下的微信数据，也可以结合红队知识进行社工

TODO: 寻找新版本下登录微信的wxid偏移，修改文件结构


# 使用
### Main.py(old.py)
![image](https://github.com/i-Corner/WX-forensics/assets/80880063/aec8ea11-082f-49ff-9ff2-b7aeb15e3a58)
#### 在得到解密数据库后，直接运行getHtmlData.py，再打开html文件即可查看
#### 目前版本为3.9.5.81，不同版本偏移不同，请看提示进行操作



# 提示
若无法运行main.py，请参考pdf寻找当前版本的偏移地址，而AES key地址则需要寻找网上公布的偏移（拥有了一次则可以不断查询新版本的）

# 维护
该仓库主要用于数字取证大作业，后续可能仅帮忙更新AES Key地址

# 参考
http://eotstxtab.top/2023/05/06/wechat%E8%81%8A%E5%A4%A9%E8%AE%B0%E5%BD%95db%E5%8F%96%E8%AF%81%E8%A7%A3%E5%AF%86/

https://github.com/x1hy9/WeChatUserDB

https://github.com/AdminTest0/SharpWxDump/blob/master/Program.cs

# 开源不易，各位请点个Star⭐

# 免责声明
本项目仅允许在授权情况下对数据库进行备份，严禁用于非法目的，否则自行承担所有相关责任。
使用该工具则代表默认同意该条款;
请勿利用本项目的相关技术从事非法测试，如因此产生的一切不良后果与项目作者无关
