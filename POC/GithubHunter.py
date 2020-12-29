# -*- coding: utf-8 -*-

import configparser
import os
import re
import smtplib
import sqlite3
import sys
import traceback
from email import encoders
from email.header import Header
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr, parseaddr
from time import gmtime, sleep, strftime

import requests
from lxml import etree
from lxml.html import tostring
from ClassCongregation import login_github
import CodeTest

_str = '''
    [RECEIVER]
    receiver1 = xxx@163.com

    [KEYWORD]
    keyword1 = frp

    [PAYLOADS]
    p1 = username
    p2 = password
    '''
indexstr = '''主要用途：本工具主要是查询Github中可能泄露的代码，用户名，密码，数据库信息，网络结构信息等
实现方法：通过登陆Github后，搜索关键词，然后呈现数据并发送给指定邮箱'''
print(indexstr)

def hunter(gUser, gPass, keywords):#根据关键词获取想要查询的内容

    print('''                                
    #     # # ##### #    # #    # #####     #     # #    # #    # ##### ###### #####  
    #       #   #   #    # #    # #    #    #     # #    # ##   #   #   #      #    # 
    #  #### #   #   ###### #    # #####     ####### #    # # #  #   #   #####  #    # 
    #     # #   #   #    # #    # #    #    #     # #    # #  # #   #   #      #####  
    #     # #   #   #    # #    # #    #    #     # #    # #   ##   #   #      #   #  
     #####  #   #   #    #  ####  #####     #     #  ####  #    #   #   ###### #    # V2.1   \r\n\r\n''')

    try:
        #代码搜索
        if CodeTest.github_now == None:
            s = login_github(gUser,gPass)
            CodeTest.github_now = s
            print('[+]登陆成功，正在检索泄露信息.......')
        else:
            s = CodeTest.github_now
            print('[+]检测到已经登录.......')
        sleep(1)
        codes = []
        tUrls = []
        #新加入2条正则匹配，第一条匹配搜索出来的代码部分；第二条则进行高亮显示关键词
        pattern_code = re.compile(r'<div class="file-box blob-wrapper my-1">(.*?)</div>', re.S)
        pattern_sub = re.compile(r'''<span class='text-bold'>''', re.S)
        for keyword in keywords:
            print('[*]当前检索关键字 %s'%keyword)
            for page in range(1,4):
                print('[*]正在检索第 %s 页'%page)
                #更改搜索排序方式的url，收录可能存在泄漏的url还是使用xpath解析
                search_code = 'https://github.com/search?o=desc&p=' + str(page) + '&q=' + keyword +'&s=indexed&type=Code'
                resp = s.get(search_code)
                results_code = resp.text
                dom_tree_code = etree.HTML(results_code)
                #获取存在信息泄露的链接地址
                Urls = dom_tree_code.xpath('//div[@class="f4 text-normal"]/a/@href')
                for url in Urls:
                    url = 'https://github.com' + url
                    tUrls.append(url)
                #获取代码部分，先获得整个包含泄露代码的最上层DIV对象，再把对象进行字符化，便于使用正则进行匹配泄露代码部分的div
                results = dom_tree_code.xpath('//div[@class="hx_hit-code code-list-item d-flex py-4 code-list-item-public "]')
                for div in results:
                    result = etree.tostring(div, pretty_print=True, method="html")
                    code = str(result, encoding='utf-8')
                    #如果存在<div class="file-box blob-wrapper">此标签则匹配泄露的关键代码部分，不存在则为空。
                    if '<div class="file-box blob-wrapper my-1">' in code:
                        data = pattern_code.findall(code)
                        codes.append(pattern_sub.sub('''<span style="color:red">''', data[0]))
                    else:
                        codes.append(' ')
            
        return tUrls, codes

    except Exception as e:
        #如发生错误，则写入文件并且打印出来
        #error_Record(str(e), traceback.format_exc())
        print(e)

def insert_DB(url, code):
    try:
        conn = sqlite3.connect('hunter.db')
        cursor = conn.cursor()
        cursor.execute('CREATE TABLE IF NOT EXISTS Baseline (url varchar(1000) primary key, code varchar(10000))')
        cursor.execute('INSERT OR REPLACE INTO Baseline (url, code) values (?,?)', (url, code))
        cursor.close
        conn.commit()
        conn.close()
    except Exception as e:
        print("[-]数据库操作失败！\n")
        #error_Record(str(e), traceback.format_exc())
        print(e)

def compare_DB_Url(url):
    try:
        con = sqlite3.connect('hunter.db')
        cur = con.cursor()
        cur.execute('SELECT url from Baseline where url = ?', (url,))
        results = cur.fetchall()
        cur.close()
        con.commit()
        con.close()
        return results
    except Exception as e:
        #error_Record(str(e), traceback.format_exc())
        print(e)

def send_mail(host, username, password, sender, receivers, message): 
    def _format_addr(s):
        name,addr = parseaddr(s)
        return formataddr((Header(name,'utf-8').encode(),addr))

    msg = MIMEText(message, 'html', 'utf-8')
    subject = 'Github信息泄露监控通知'
    msg['Subject'] = Header(subject, 'utf-8').encode()
    msg['From'] = _format_addr('Github信息泄露监控<%s>' % sender)
    msg['To'] = ','.join(receivers)
    try:
        smtp_obj = smtplib.SMTP(host, 25)
        smtp_obj.login(username, password)
        smtp_obj.sendmail(sender, receivers, msg.as_string())
        print('[+]邮件发送成功！')
        smtp_obj.close()
    except Exception as err:
        print(err)

def check(**kwargs):
    config = configparser.ConfigParser()
    _config = configparser.RawConfigParser(allow_no_value=True)
    config.read('./POC/info.ini')
    #print(config.sections())
    _config.read_string(_str)
    g_User = config['Github']['user']
    g_Pass = config['Github']['password']
    host = config['EMAIL']['host']
    m_User = config['EMAIL']['user']
    m_Pass = config['EMAIL']['password']
    m_sender = config['SENDER']['sender']
    receivers = []
    for k in _config['RECEIVER']:
        receivers.append(_config['RECEIVER'][k])
    keywords = []
    #组合关键词，keyword + payload,两者之间加入“+”号，符合Github搜索语法
    for keyword in _config['KEYWORD']:
        for payload in _config['PAYLOADS']:
            keywords.append(_config['KEYWORD'][keyword] + '+' + _config['PAYLOADS'][payload])

    for index in keywords:
        print('[*]检索关键字: %s'%index)
    message = 'Dear all<br><br>未发现任何新增敏感信息！'
    tUrls, codes= hunter(g_User, g_Pass, keywords)
    target_codes = []
    #第一次运行会查找是否存在数据文件，如果不存在则新建，存在则进行新增条目查找
    if os.path.exists('./POC/hunter.db'):
        print("[*]存在数据库文件，进行新增数据查找......")
        #拆分关键词，在泄露的代码中查找关键词和payload.如果两者都存在则进行下一步数据库查找
        for keyword in keywords:
            payload = keyword.split('+')
            for i in range(0, len(tUrls)):
                if (payload[0] in codes[i]) and (payload[1] in codes[i]):
                    format_code = codes[i].replace(payload[0],'<em style="color:red">' + payload[0] + '</em>')
                    format_code = format_code.replace(payload[1],'<em style="color:red">' + payload[1] + '</em>')
                    #如果数据库中返回的值为空，则说明该条目在数据库中不存在，那么添加到target_codes里面用户发送邮件，并且添加到数据库中
                    if not compare_DB_Url(tUrls[i]):
                        target_codes.append('<br><br><br>' + '链接：' + tUrls[i] + '<br><br>')
                        target_codes.append('命中关键词: <em style="color:red">' + payload[0] + '</em> and <em style="color:red">' + payload[1] + '</em><br><br>')
                        target_codes.append('简要代码如下：<br><div style="border:1px solid #bfd1eb;background:#f3faff">' + format_code + '</div>')
                        insert_DB(tUrls[i], format_code)
    else:
        print("[*]未发现数据库文件，创建并建立基线......")
        for keyword in keywords:
            payload = keyword.split('+')
            for i in range(0, len(tUrls)):
                #关键词和payload同时存在则加入到target_codes,并写入数据库
                if (payload[0] in codes[i]) and (payload[1] in codes[i]):
                    format_code = codes[i].replace(payload[0],'<em style="color:red">' + payload[0] + '</em>')
                    format_code = format_code.replace(payload[1],'<em style="color:red">' + payload[1] + '</em>')
                    target_codes.append('<br><br><br>' + '链接：' +tUrls[i] + '<br><br>')
                    target_codes.append('命中关键词: <em style="color:red">' + payload[0] + '</em> and <em style="color:red">' + payload[1] + '</em><br><br>')
                    target_codes.append('简要代码如下：<br><div style="border:1px solid #bfd1eb;background:#f3faff">' + format_code + '</div>')
                    insert_DB(tUrls[i], format_code)
    #当target_codes有数据时，则进行邮件预警                
    if target_codes:
        warning = ''.join(target_codes)
        result = 'Dear all<br><br>发现信息泄露! ' + '一共发现<em style="color:red"> {} </em>条'.format(int(len(target_codes)/2)) + warning
        send_mail(host, m_User, m_Pass, m_sender, receivers, result)
    else:
        print('[-]未找到相关敏感信息')
        #send_mail(host, m_User, m_Pass, m_sender, receivers, message)













