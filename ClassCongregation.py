import random,requests,datetime,time
from urllib.parse import urlparse
from lxml import etree

class Dnslog:  # Dnslog判断
    def __init__(self):
        #该网站是通过PHPSESSID来判断dns归属谁的所以可以随机一个
        h = "abcdefghijklmnopqrstuvwxyz0123456789"
        salt_cookie = ""
        for i in range(26):
            salt_cookie += random.choice(h)
        self.headers = {
            "Cookie": "PHPSESSID="+salt_cookie
        }
        H = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        salt = ""
        for i in range(15):
            salt += random.choice(H)
        try:
            self.host = str(salt + "." + self.get_dnslog_url())
        except Exception as e:
            print(e)
            self.host=""

    def dns_host(self) -> str:
        return str(self.host)

    def get_dnslog_url(self):
        try:
            self.dnslog_cn=requests.get("http://www.dnslog.cn/getdomain.php",headers=self.headers,timeout=6).text
            return self.dnslog_cn
        except Exception as e:
            print("获取DOSLOG出错%s"%e)

    def result(self) -> bool:
        # DNS判断后续会有更多的DNS判断，保持准确性
        return self.dnslog_cn_dns()


    def dnslog_cn_dns(self) -> bool:
        try:
            status = requests.get("http://www.dnslog.cn/getrecords.php?t="+self.dnslog_cn,headers=self.headers,  timeout=6)
            self.dnslog_cn_text = status.text
            if self.dnslog_cn_text.find(self.host) != -1:  # 如果找到Key
                return True
            else:
                return False
        except Exception as e:
            print(self.host + "|| dnslog_cn_dns", e)

    def dns_text(self):
        return self.dnslog_cn_text

def _urlparse(url):
    try:
        getipport = urlparse(url)
        hostname = getipport.hostname
        port = getipport.port

        if port == None and r"https://" in url:
            port = 443

        elif port == None and r"http://" in url:
            port = 80

        if r"https://" in url:
            url = "https://"+hostname+":"+str(port)

        elif r"http://" in url:
            url = "http://"+hostname+":"+str(port)
        return url
    except Exception as e:
        return url

#github登录功能函数
def login_github(username,password):#登陆Github
    #初始化参数
    login_url = 'https://github.com/login'
    session_url = 'https://github.com/session'
    try:
        #获取session
        s = requests.session()
        resp = s.get(login_url).text
        dom_tree = etree.HTML(resp)
        key = dom_tree.xpath('//input[@name="authenticity_token"]/@value')
        user_data = {
            'commit': 'Sign in',
            'utf8': '✓',
            'authenticity_token': key,
            'login': username,
            'password': password
        }
        #发送数据并登陆
        s.post(session_url,data=user_data)
        s.get('https://github.com/settings/profile')
        return s
    except Exception as e:
        print('[-]产生异常，请检查网络设置及用户名和密码')
        #error_Record(str(e), traceback.format_exc())