import os
import time
import json
import sqlite3

DB = None
cursor = None

sql_HeadImg = '''
        select smallHeadImgUrl from ContactHeadImgUrl
        where usrName = ?
        '''
sql_name = '''
        select NickName,Remark from Contact
        where UserName = ?
        '''
sql_msg = '''
        select Type,IsSender,CreateTime,StrContent from MSG
        where StrTalker = ? and Type = 1
        order by CreateTime
        '''

def getInfo_FromDB(cursor):
    dict_result = {}
    sql = 'select strUsrName from Session'
    cursor.execute(sql)
    result = cursor.fetchall()
    for wxid, in result:
        NickName,Remark,Url = '','',''
        cursor.execute(sql_HeadImg, [wxid])
        r = cursor.fetchone()
        if r!= None:
            Url = r[0]
        cursor.execute(sql_name, [wxid])
        r = cursor.fetchone()
        if r!= None:
            NickName,Remark = r[0],r[1]
        dict_result[wxid]=[NickName,Remark,Url]
    return dict_result

def getMessage_FromDB(cursor,wxid):
    cursor.execute(sql_msg, [wxid])
    result = cursor.fetchall()
    return result 

def getOtherUserName_FromDB(cursor):
    sql = 'select UsrName from Name2ID'
    cursor.execute(sql)
    result = cursor.fetchall()
    now_db_wxid = [wxid for wxid, in result]
    return now_db_wxid
    
def get_MSGdb_list():
    msg_db_list = []
    for root, dirs, files in os.walk(".\\decrypt_DB\\"):
        # 获取文件所属目录
        for file in files:
            # 搜索所有数据库文件
            if file.endswith('.db'):
                if file.startswith("MSG"):
                    msg_db_list.append(file)
    sorted(msg_db_list)
    return msg_db_list
    
def dump_json(save_path, json_name, data):
    with open(save_path, 'w') as f:
        f.write(json_name + " = ")
        json.dump(data, f)
    print("已保存数据",save_path)
    
def Msg2Json():
    MSG = {}
    msg_db_list = get_MSGdb_list()
    for db in msg_db_list:
        print("正在提取"+db+"的信息...")
        DB = sqlite3.connect(".\\decrypt_DB\\"+db, check_same_thread=False)
        cursor = DB.cursor()
        IDs = getOtherUserName_FromDB(cursor)
        for ID in IDs:
            msg = getMessage_FromDB(cursor,ID)
            if len(msg)!=0:
                if(ID in MSG):
                    MSG[ID] += msg
                else:
                    MSG[ID] = msg
        print("已提取"+db+"的信息")
    dump_json('json/msg.js', "msg", MSG) 
    
def WxidInfo2Json():
    MicroMsg_db = ".\\decrypt_DB\\MicroMsg.db"
    DB = sqlite3.connect(MicroMsg_db, check_same_thread=False)
    cursor = DB.cursor()
    wxid_info = getInfo_FromDB(cursor)
    dump_json('json/wxid_info.js', "wxid_info", wxid_info) 

def ImgInfo2Json():
    time_dir = os.listdir(".\\WechatImage\\")
    result = {}
    for time in time_dir:
        img_name = os.listdir(".\\WechatImage\\"+time)
        result[time] = img_name
    dump_json('json/Image.js', "Img", result) 

if __name__ == "__main__":
    start = time.time()
    WxidInfo2Json()
    Msg2Json()
    ImgInfo2Json()
    end = time.time()
    print("成功提取数据，用时", end - start, 's')
    
