#! /usr/bin/env python3
# -*- coding: utf-8 -*-


import binascii
import hmac
import ctypes
import hashlib
import win32api
import win32con
from Crypto.Cipher import AES
import pymem
import struct
import argparse
import os
import getpass
import re
from offset import Version_offset_dict

AESKEY_OFFSET = 0x2FFD590
WECHAT_VERSION = "3.9.2.23"

class Decrypt_image_info():
    def __init__(self):
        self.pattern_dir = r'\\\d+\-\d+'
        self.pattern_name = r'\\[0-9A-z\w]+\.'
        self.pho_head = [0xff, 0xd8, 0x89, 0x50, 0x47, 0x49, 0x42, 0x4d]  # 1,2是jpeg头信息，3，4是png图片头信息，5，6是gif头信息，7，8是bmp头信息
        self.decoded_image = []  # 已解密的文件名集合

def check_os():
    '''
    :return:  当前操作系统名称，目前仅支持windows
    '''
    # os.name 对应 (nt,windows),(posix,linux/mac)
    os_name = os.name
    if os_name == "nt":
        # windows
        os_name = "windows"
    if os_name == "posix":
        # mac
        os_name = "linux"
    return os_name

def check_wxid_version(raw_info):
    global wxid_version
    if "wxid_" in raw_info:
        wxid_version = "new_wxid"
    else:
        wxid_version = "old_wxid"


def get_wxid_list():
    '''
    通过注册表读取PC微信安装的有关信息（安装保存位置，版本信息等）
    :param os_name:
    :return:
    '''
    #windows下wxid路径


    reg_root = win32con.HKEY_USERS
    reg_path = ""
    #打开当前os用户的注册表
    key = win32api.RegOpenKey(reg_root, reg_path, 0)
    #利用枚举遍历注册表表项
    for item in win32api.RegEnumKeyEx(key):
        #注册表表项中正确表项应为计算机\HKEY_USERS\S-1-5-21-2004067182-1827925193-3696931025-1001\SOFTWARE\Tencent\WeChat
        #HKEY_USERS和SOFTWARE中间的长串字符指定为当前用户的唯一SID，命名格式为S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX-XXXX
        #而S-1-5-21-XXXXXX较短的为一些系统服务的用户，为寻找用户的子项，故需要此判断条件
        if len(item[0]) > 20 and "Classes" not in item[0]:
           # print(item[0])
           #用户PC微信安装的注册表项的位置
            sub_reg_path = item[0] + "\\SOFTWARE\\Tencent\\WeChat"
            #print(sub_reg_path)
           #尝试具体打开该键项，由于可能某用户可能未安装，故需要用异常处理
            try:
                key = win32api.RegOpenKeyEx(reg_root, sub_reg_path, 0)
                #print(key)
            except Exception as e:
                continue
    #打开Wechat的注册表安装项后，可根据当中的键值寻找版本，方便后续选择不同版本的偏移获取内存中的个人信息，val为具体value，ty为value类别
    val,ty = win32api.RegQueryValueEx(key, 'Version')

    #读取到的版本号为一个4Bytes的十六进制数，每一个Byte表示一个数字，对应X.X.X.X版本，故切分再输出，较为奇怪的是第一位，0x63最终表示为3，那么需要减去0x60=96
    v= []
    version = str(hex(val))[2:]
    v.append(str(int(version[:2],16)-96))
    v.append(str(int(version[2:4],16)))
    v.append(str(int(version[4:6],16)))
    v.append(str(int(version[6:8],16)))
    WECHAT_VERSION = '.'.join(v)
    print('当前版本为:','.'.join(v))

    #读取键值对中的用户资料保存位置，若FileSavePath注册表键为MyDocument：，说明没有修改默认保存位置，若有则对应的value即为保存位置，若无，则在InstallPath中也可寻找到
    try:
        value, key_type = win32api.RegQueryValueEx(key, 'FileSavePath')
    except Exception as e:
        value, key_type = win32api.RegQueryValueEx(key, 'InstallPath')
        value = value + "\\locales\\WeChat Files\\"
    #print(value)
    # 文件保存路径
    if value == "MyDocument:":
        #经过多台PC测试，若保存wx文件夹注册表键为MyDocument：，说明没有修改默认保存位置
        # 读取当前windows用户的名
        username = getpass.getuser()
        # 打开默认存储聊天资料位置下的wx目录
        file_path = "C:\\Users\\" + username + "\\Documents\\WeChat Files\\"
        #print(file_path)
    else:
        # 若保存wx文件夹注册表键不为MyDocument，则此时已更改默认存储位置，键的值即为资料位置
        file_path = value

    # 获取用户文件
    try:
        wxid_list = os.listdir(file_path)
        #去除干扰文件夹
        wxid_list.remove("All Users")
        wxid_list.remove("Applet")
        # 去除小程序相关文件夹
        wxid_list.remove("WMPF")
    except:
        print("\nfailed to find the path by the script")
        print("Please enter the path of your [WeChat Files]")
        print("You can find the path in your WeChat's setting")
        print("It looks like [x:\\\\xxx\\xxx\\WeChat Files]")
        file_path = input("The path : ") + "\\"
        wxid_list = os.listdir(file_path)
        wxid_list.remove("All Users")
        wxid_list.remove("Applet")
    return file_path,wxid_list



def get_filetype(filepath,Image_decrypt_info): #计算加密码和图片类型
    pho_info = []
    dat = open(filepath,"rb")
    dat_read = dat.read(2)
    h_index = 0
    while h_index < len(Image_decrypt_info.pho_head):
    # 使用图片的第一个头信息字节来计算加密码
    # 第二个字节用来验证解密码是否正确
        code = dat_read[0] ^ Image_decrypt_info.pho_head[h_index]
        idf_code = dat_read[1] ^ code
        h_index = h_index + 1
        if idf_code == Image_decrypt_info.pho_head[h_index]:   #如果前两个字节异或的结果相同，则证明就是当前h_index的图片类型
            dat.close()
            pho_info.append(code)
            if dat_read[0]^Image_decrypt_info.pho_head[0]==dat_read[1]^Image_decrypt_info.pho_head[1]:
                pho_info.append("jpeg")
            elif dat_read[0]^Image_decrypt_info.pho_head[2]==dat_read[1]^Image_decrypt_info.pho_head[3]:
                pho_info.append("png")
            elif dat_read[0]^Image_decrypt_info.pho_head[4]==dat_read[1]^Image_decrypt_info.pho_head[5]:
                pho_info.append("gif")
            elif dat_read[0]^Image_decrypt_info.pho_head[6]==dat_read[1]^Image_decrypt_info.pho_head[7]:
                pho_info.append("bmp")
            return pho_info
        h_index = h_index + 1
    return 0


def image_Decode(filepath,Image_decrypt_info):
    dat = open(filepath,"rb")
    outpath = "./WechatImage"
    try:
        timedir = re.findall(Image_decrypt_info.pattern_dir,filepath)  #保存图片的日期文件夹
        outpath += timedir[0]
        if not os.path.exists(outpath):
            os.makedirs(outpath)
        out_name = re.findall(Image_decrypt_info.pattern_name,filepath)    #文件名
        outpath += "\\"+out_name[0]
        pho_info = get_filetype(filepath,Image_decrypt_info)
        out_name = out_name[0].strip("\\") + pho_info[1]
        outpath += pho_info[1]
        pic = open(outpath, "wb")
        Image_decrypt_info.decoded_image.append(out_name)
        code = pho_info[0]
        for now in dat:
            for nowByte in now:
                newByte = nowByte ^ code    #解密码
                pic.write(bytes([newByte]))
        print(f"已解密图片:{out_name}")
        dat.close()
        pic.close()
    except:
        print("wzfl")



def get_MSG_db(file_path,wxidc,os_name,key,Image_decrypt_info,args):
    '''
    递归解锁某一目录下所有db文件
    :param file_path:  计算机中存储所有wxid资料的位置
    :param wxidc:      wxid_list
    :param os_name:    操作系统名称
    :param key:        前面通过偏移计算所得的密钥
    :return:
    '''
    if os_name == "windows":
        #遍历所有wxid
        for wxid in wxidc:
            #指定目录为其聊天记录信息的目录
            down_path = file_path + wxid + "\Msg"
            #遍历Msg文件夹内所有文件
            for root, dirs, files in os.walk(down_path):
                flag = 1
                # 获取文件所属目录
                for file in files:
                    # 搜索所有数据库文件
                    if file.endswith('.db'):
                        #print(os.path.join(root, file))
                        #xInfo.db数据库未被加密，可直接查看，故需跳过
                        if os.path.join(root, file).endswith('xInfo.db'):
                            continue
                        #利用密钥解密单个数据库文件
                        decrypt_msg(os.path.join(root, file),key)

            #新版微信加密图片存储在MsgAttach，旧版微信加密图片存储在Image
            store_base_path = [r"\MsgAttach", r"\Image"]
            for item_path in store_base_path:
                down_path = file_path + wxid + r"\FileStorage"+item_path
                for root, dirs, files in os.walk(down_path):
                    for file in files:
                        if file.endswith(".dat"):
                            image_Decode(os.path.join(root, file),Image_decrypt_info)
                        else:
                            continue


def get_info(file_path,wxidc,os_name):
    '''
    由上述注册表所得的wx路径，继续深入挖掘用户信息
    :param file_path:
    :param wxidc:
    :param os_name:
    :return:
    '''
    #一个wxid文件下的/config/accinfo.dat蕴含部分用户信息
    if os_name == "windows":
        file = file_path + wxidc + "\\config\\AccInfo.dat"
        try:
            file_size = os.path.getsize(file)
        except:
            print(wxidc+"为失效文件夹")
            print()
            return
    if file_size == 0:
        return

    #
    print("=================基本信息=================")
    #print("用于压缩文件参数id：" + wxidc)
    with open(file, mode="r", encoding="ISO-8859-1") as f:
        # 处理raw数据
        raw_info = f.read()
        # 获取原始wxid的版本
        print('raw_inf:',raw_info)
        check_wxid_version(raw_info)
        if os_name == "windows":
            if wxid_version == "new_wxid":
                raw_info = raw_info[raw_info.find("wxid"):]
            if wxid_version == "old_wxid":
                raw_info = raw_info
        info = ""
        for char in raw_info:
            if "\\" not in ascii(char):
                info = info + str(char)
            else:
                info = info + "`"
        info_2 = list(set(info.split("`")))
        info_2.sort(key=info.index)
        info = info_2
        info_list = []
        for x in info:
            if len(x) > 1:
                info_list.append(x)
        info = info_list
        if wxid_version == "old_wxid":
            for x in info:
                an = re.search("[a-zA-Z0-9_]+", x)
                if len(x) >= 6 and len(an.group(0)) >= 6:
                    d_list = r"!@#$%^&*()+={}|:\"<>?[]\;',./`~'"
                    flag_id = 0
                    for i in x:
                        if i in d_list:
                            wxid = x.replace(i, "")
                            flag_id = 1
                    if flag_id == 0:
                        wxid = an.group(0)
                    break
            info = info[info.index(x):]
            info[0] = wxid

    if info != []:
        # 获取微信id
        try:
            wxid = info[0]
            print("The wxid : " + wxid)
        except:
            pass

        # 获取微信号
        # 微信号长度限制为6-20位, 且只能以字母开头
        try:
            for misc in info:
                if 6 <= len(misc) <= 20 and misc[0].isalpha() is True:
                    wx = misc
            print("The wechat : " + wx)
            info.remove(wx)
        except:
            print("The wechat : " + wxid)


        # 利用正则获取手机号
        for misc in info:
            p_numbers = r"[\+0-9]+"
            p = re.compile(p_numbers)
            numbers = re.search(p, misc)
            try:
                if "+" in numbers.group(0) and len(numbers.group(0) >= 6):
                    number = numbers.group(0)
                else:
                    p_numbers = r"0?(13|14|15|17|18|19)[0-9]{9}"
                    p = re.compile(p_numbers)
                    numbers = re.search(p, misc)
                    number = numbers.group(0)
            except:
                continue
            if "*" in number:
                number = number.replace("*", "")
            print("The phone : " + number)
            try:
                info.remove(number)
            except:
                info.remove(number + "*")
            break

        #获取并输出文件传输记录
        down_path = file_path + wxidc + "\\FileStorage\\File"
        down_path_list = os.listdir(down_path)[:len(os.listdir(down_path)) - 1]
        for down_doc in down_path_list:
            print("=================" + down_doc + "=================")
            for down_info in os.listdir(down_path + "\\" + down_doc):
                print(down_info)
            print("===========================================")
            print()
            print()

        print("以下目录为2022.06后存储位置改变的文件列表")
        print()
        new_path = file_path + wxid + "\\FileStorage\\MsgAttach\\"

        for root, dirs, files in os.walk(new_path):
            # 遍历输出目录路径

            for name in dirs:
                if name in "File":
                    for time_file in os.listdir(root + "\\" + name):
                        print("================" + time_file + "====================")
                        for file_name in os.listdir(root + "\\" + name + "\\" + time_file):
                            print(file_name)
                        print("===========================================")
                        print()
                        print()


def getuserinfo(p,args) :
    '''
    :param p:   pymem内存指针
    :return:
    '''
    try:
        # 获取WeChatWin.dll在内存中的地址，后续的一系列内容均由该地址计算偏移生成
        base_address = pymem.process.module_from_name(p.process_handle, "WeChatWin.dll").lpBaseOfDll
    except:
        print("您未开启微信进程，无法继续，请登录微信")
        exit()
    # 用户名字。测试时发现，名字若含中文之类的文字则为指针，纯英文字符则为直接地址
    try:
        name = p.read_string(base_address + 0x2FFF5D0)
    except:
        name = p.read_bytes(base_address + 0x2FFF5D0,4)
        name = struct.unpack("<I", name)[0]
        name = p.read_string(name)
    else:
        print("读取用户名错误")

    try:
        account = p.read_string(base_address + 0x2FFF970)
    except:
        account = p.read_bytes(base_address + 0x2FFF970,4)
        account = struct.unpack("<I", account)[0]
        account = p.read_string(account)
    else:
        print("读取微信号错误")

    try:
        wxid = p.read_bytes(base_address + 0x2FFF988,4)
        wxid = struct.unpack("<I", wxid)[0]
        wxid = p.read_string(wxid)
    except:
        print("读取wxid错误")

    #area = p.read_bytes(base_address + 0x20F936B8,0x10)
    #area = str(area,'utf-16')

    try:
        # 用户头像，但在动态链接库基址偏移下记录的为其指针，故需读取两次
        pic = p.read_bytes(base_address + 0x3042F54,4)
        pic = struct.unpack("<I", pic)[0]
        pic = p.read_string(pic)
        #pic = p.read_string(hex(pic))
    except:
        print("读取头像url错误")

    try:
        # 用户手机号
        phone = p.read_string(base_address + 0x2FFF540)
        #mail = p.read_string(base_address + 0x2FFD970)
    except:
        print("读取手机号错误")

    try:
        # 用户个人的AES解密密钥，基址固定偏移记录真值的为内存指针，两次读取
        key_addr = p.read_bytes(base_address + 0x2FFF94C,4)
        #print(key_addr)
        #print(struct.unpack("<I", key_addr))
        key_addr = struct.unpack("<I", key_addr)[0]
        #print(hex(key_addr))
        aeskey = p.read_bytes(key_addr, 0x20)
        # 将读取到的aeskey从bytes转换成hex
        result = binascii.b2a_hex(aeskey)
    except:
        print("读取AesKey错误,无法操作与数据库相关操作")

    if args.get_RAM:
        #输出读取到的信息
        print('Name :',name)
        print('account :',account)
        print('pic:',pic)
        print('wxid:',wxid)
        #print('area:',area)
        print('Phone :',phone)
        #print('mail :',mail)
        print(f"数据库密钥为：{result.decode()}")

    return base_address, result.decode()

def decrypt_msg(path, password):
    '''
    利用密钥解锁单个数据库文件
    :param path:        一个需要解密数据库文件的绝对路径
    :param password:    aes解密密钥
    :return:
    '''

    # PC微信数据库具体采用SqlCipher加密，其加密算法是256位的AES-CBC。可以直接通过SqLCipher应用输入所得密钥解锁,但效率较慢，且微信数据库达到一定容量则会使用新的一个文件装载，故写成代码形式一次多个解锁
    # SqLCipher具体加密细节 https://www.zetetic.net/sqlcipher/design/
    # 数据库的默认的页大小是4096字节即4KB，其中每一个页都是被单独加解密的。
    KEY_SIZE = 32

    # 解密密钥迭代次数
    DEFAULT_ITER = 64000

    # 4048数据 + 16IV + 20 HMAC + 12
    DEFAULT_PAGESIZE = 4096
    # SQLite 文件头
    SQLITE_FILE_HEADER = bytes("SQLite format 3", encoding="ASCII") + bytes(1)

    with open(path, "rb") as f:
        blist = f.read()

    # 每一个数据库文件的开头16字节都保存了一段唯一且随机的盐值，作为HMAC的验证和数据的解密
    salt = blist[:16]
    # 解密用的密钥是主密钥和16字节的盐值通过PKCS5_PBKF2_HMAC1密钥扩展算法迭代64000次计算得到的
    key = hashlib.pbkdf2_hmac("sha1", password, salt, DEFAULT_ITER, KEY_SIZE)
    # 丢掉salt后为第一页内容
    page1 = blist[16:DEFAULT_PAGESIZE]

    # 计算HMAC的密钥是刚提到的解密密钥和16字节盐值异或0x3a的值通过PKCS5_PBKF2_HMAC1密钥扩展算法迭代2次计算得到的。
    mac_salt = bytes([x ^ 0x3a for x in salt])
    mac_key = hashlib.pbkdf2_hmac("sha1", key, mac_salt, 2, KEY_SIZE)

    # 加密文件的每一页都存有着消息认证码，算法使用的是HMAC-SHA1。它也被保存在每一页的末尾
    hash_mac = hmac.new(mac_key, digestmod="sha1")
    hash_mac.update(page1[:-32])
    hash_mac.update(bytes(ctypes.c_int(1)))

    # 与认证码校验
    if hash_mac.digest() != page1[-32:-12]:
        raise RuntimeError("密码错误,请检查你的db文件或密钥")

    # 往后的页均是4048字节长度的加密数据段和48字节的保留段，4048+48=4096
    pages = [blist[i:i+DEFAULT_PAGESIZE] for i in range(DEFAULT_PAGESIZE, len(blist), DEFAULT_PAGESIZE)]
    # 补回第一页
    pages.insert(0, page1)
    #print(path.split("\\")[-1])
    new_path = './decrypt_DB/'+path.split('\\')[-1]
    if not os.path.exists('./decrypt_DB'):
        os.makedirs('./decrypt_DB')
    with open(f"{new_path}", "wb") as f:
        # 写入文件头
        f.write(SQLITE_FILE_HEADER)
        # 解密页
        for i in pages:
            t = AES.new(key, AES.MODE_CBC, i[-48:-32])
            f.write(t.decrypt(i[:-48]))
            f.write(i[-48:])
        print(f"已解密数据库:{new_path}")



if __name__ == "__main__":
    os_name = check_os()
    if os_name !="windows":
        print("该软件目前仅支持windows，无法支持您的计算机操作系统。")
        exit()
    parser = argparse.ArgumentParser()
    parser.add_argument("-r","--get_RAM",action='store_true', default=False)
    parser.add_argument("-d","--get_Disk", action='store_true',default=False)

    parser.add_argument("-D","--Decrypt", action='store_true',default=False)
    parser.add_argument("-M","--MSG_output_dir",  default='./decrypt_DB', type=str)
    parser.add_argument("-I","--Image_output_dir", default="./WechatImage", type=str)
    #parser.add_option("-g", "--get_key", action='store_true', dest="get_key", help="仅windows可用,获取以base64编码的key")
    args = parser.parse_args()

    p = pymem.Pymem()
    p.open_process_from_name("WeChat.exe")
    if args.get_RAM and not args.Decrypt:
        base_offset, aesKey = getuserinfo(p,args)
    if args.Decrypt and args.get_RAM:
        base_offset, aesKey = getuserinfo(p, args)
        password = bytes.fromhex(aesKey)
        file_path, wxid_list = get_wxid_list()
        # print("此机器共有" + str(len(wxid_list)) + "个账号登录过")
        # print(wxid_list)
        Image_decrypt = Decrypt_image_info()
        get_MSG_db(file_path,wxid_list,os_name,password,Image_decrypt,args)
        for wxid in wxid_list:
            get_info(file_path, wxid, os_name)
    if args.get_Disk:
        file_path, wxid_list = get_wxid_list()
        print("此机器共有" + str(len(wxid_list)) + "个账号登录过")
        print(wxid_list)
        for item in wxid_list:
            get_info(file_path,item,os_name)
    # decrypt_msg(path,password)