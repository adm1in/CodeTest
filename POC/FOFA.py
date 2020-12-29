import base64,requests,time
import random,re,threading
import urllib.parse
from lxml import etree
from requests.packages import urllib3
from concurrent.futures import ThreadPoolExecutor, wait, ALL_COMPLETED, FIRST_COMPLETED,as_completed

urllib3.disable_warnings()

#捕获的页数,没有会员白嫖5页
pages = 5
##修改为自己登录后的cookie值
_fofapro_ars_session = """
    3ef51220657f30d15068b54146de7899
"""

print('''FOFA常用语法:
title="beijing"
header="jboss"
body="Hacked by"
domain="qq.com"
host=".gov.cn"
ip="220.181.111.1/24"
server=="Microsoft-IIS/7.5"
ip="1.1.1.1"
app="Shiro权限管理系统"
app="Apache-Shiro"
app="泛微-协同办公OA"''')
print("用法: 在目标处输入查询语法,需要编辑源码修改cookie (普通用户默认查询5页)")

def load_url(url, index):
    global _fofapro_ars_session
    headers = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        'X-Requested-With': 'XMLHttpRequest',
        'Connection': 'close',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.75 Safari/537.36'
    }
    proxies = {}
    try_times = 0
    max_change_porxies_times = 3
    url_base64 = base64.b64encode(url.encode()).decode()
    
    _fofapro_ars_session = _fofapro_ars_session.strip()
    search_lan = 'https://fofa.so/result?page={}&q={}&qbase64={}'.format(index,urllib.parse.quote(url),urllib.parse.quote(url_base64))

    rep_test = requests.get(search_lan,timeout=15, verify=False, headers=headers,cookies={'_fofapro_ars_session':_fofapro_ars_session}).text
    time.sleep(random.uniform(1.5, 2))  # 每读取一次页面暂停一会,否则会被封
        
    tree = etree.HTML(rep_test)
    for i in range(1,11):
        try:
            http = tree.xpath('//*[@id="ajax_content"]/div[{}]/div[1]/div[1]/a/text()'.format(i))[0].strip()
            if http == '':
                http = tree.xpath('//*[@id="ajax_content"]/div[{}]/div[1]/div[1]/a[2]/text()'.format(i))[0].strip()
        except IndexError:#没有捕获到数据时,跳过
            #print(1)
            break
        threadLock.acquire()
        url_list.append(http)
        threadLock.release()

url_list = []
threadLock = threading.Lock()
def check(**kwargs):
    global url_list
    url_list = []
    item_list = []
    all_task = []
    executor = ThreadPoolExecutor(max_workers=3)
    #print('[+]FOFA收集 %s 页结果如下:'%(pages))
    for index in range(1,pages+1):
        args = (kwargs['url'], index)
        all_task.append(executor.submit(lambda p: load_url(*p),args))
    wait(all_task, return_when=ALL_COMPLETED)
    print('[+]FOFA收集 %s 页结果如下, 总计 [%s]'%(pages,url_list.__len__()))
    for url in url_list:
        print(url)

#测试
if __name__ == "__main__":
    url = "title=\"beijing\""
    #check(url)























