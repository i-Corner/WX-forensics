#! /usr/bin/env python3
# -*- coding: utf-8 -*-


import binascii
import hmac
import ctypes
import hashlib
from Crypto.Cipher import AES
import argparse
import os
import re


class Decrypt_image_info():
    def __init__(self):
        self.pattern_dir = r'\\\d+\-\d+'
        self.pattern_name = r'\\[0-9A-z\w]+\.'
        self.pho_head = [0xff, 0xd8, 0x89, 0x50, 0x47, 0x49, 0x42, 0x4d]  # 1,2是jpeg头信息，3，4是png图片头信息，5，6是gif头信息，7，8是bmp头信息
        self.decoded_image = []  # 已解密的文件名集合





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
    timedir = re.findall(Image_decrypt_info.pattern_dir,filepath)  #保存图片的日期文件夹
    outpath += timedir[0].replace('-','_')
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




def get_decrypt_db(file_path,wxidc,key):
    '''
    递归解锁某一目录下所有db文件
    :param file_path:  计算机中存储所有wxid资料的位置
    :param wxidc:      wxid_list
    :param key:        前面通过偏移计算所得的密钥
    :return:
    '''

    #遍历所有wxid
    for wxid in wxidc:
        # 指定目录为其聊天记录信息的目录
        down_path = file_path + wxid + "\Msg"
        # flag用来确定key是否能解密当前wxid下的database
        flag = False
        # 遍历Msg文件夹内所有文件
        for root, dirs, files in os.walk(down_path):
            # 获取文件所属目录
            for file in files:
                # 搜索所有数据库文件
                if file.endswith('.db'):
                    #print(os.path.join(root, file))
                    #xInfo.db数据库未被加密，可直接查看，故需跳过
                    if os.path.join(root, file).endswith('xInfo.db'):
                        continue
                    #利用密钥解密单个数据库文件
                    if os.stat(os.path.join(root, file)).st_size == 0:
                        print('已解密数据库:./decrypt_DB' + file)  # 假消息,实际上是我们为了出题将一些db用空txt替代，节省空间，但得保留目录基本一致（不用谢
                        continue
                    flag = decrypt_db(os.path.join(root, file),key)
                    if not flag:
                        break

            if not flag:
                break

def get_Img(file_path,wxidc,Image_decrypt_info):
    #遍历所有wxid
    #新版微信加密图片存储在MsgAttach，旧版微信加密图片存储在Image
    store_base_path = [r"\MsgAttach", r"\Image"]
    for wxid in wxidc:
        #指定目录为其聊天记录信息的目录
        for item_path in store_base_path:
            down_path = file_path + wxid + r"\FileStorage"+item_path
            for root, dirs, files in os.walk(down_path):
                for file in files:
                    if file.endswith(".dat"):
                        image_Decode(os.path.join(root, file),Image_decrypt_info)
                    else:
                        continue




def decrypt_db(path, password):
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
        print("密钥解密当前wxid错误，尝试下一个wxid")
        return False
        
    # 往后的页均是4048字节长度的加密数据段和48字节的保留段，4048+48=4096
    pages = [blist[i:i+DEFAULT_PAGESIZE] for i in range(DEFAULT_PAGESIZE, len(blist), DEFAULT_PAGESIZE)]
    # 补回第一页
    pages.insert(0, page1)
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
    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument("-D_B","--Decrypt_db", action='store_true',default=False,help="利用AES Key解密对应wxid用户的DataBase")
    parser.add_argument("-D_I","--Decrypt_image", action='store_true',default=False,help="解密对应wxid用户的图片")

    args = parser.parse_args()
    Image_decrypt = Decrypt_image_info()

    file_path = "./"
    #wxid文件夹请放在与该py文件的同一目录之下
    wxid_list = [""]
    #此处放入你获得的wxid
    aeskey = ""
    #此处放入你获得的aeskey
    password = bytes.fromhex(aeskey)
    if args.Decrypt_db:
        get_decrypt_db(file_path,wxid_list,password)
    if args.Decrypt_image:
        get_Img(file_path,wxid_list,Image_decrypt)

