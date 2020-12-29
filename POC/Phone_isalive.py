import requests,time
from requests.packages import urllib3
urllib3.disable_warnings()

"""
:学信网查找手机号是否存在
"""
def spider(urls,mphone):
    """
    :return:content
    """
    s = requests.session()
    s.trust_env = False
    s.verify = False
    content = None
    s.headers = {
        'Accept': 'application/json, text/javascript, */*; q=0.01',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Connection': 'close',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'Referer': 'https://account.chsi.com.cn/account/preregister.action?from=account-reghead',
        'Origin': 'https://account.chsi.com.cn',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.75 Safari/537.36'
        }
    s.data = {
        'mphone': mphone,
        'dataInfo': mphone,
        'optType': 'REGISTER'
    }
    try:
        req = s.post(urls, data=s.data, headers=s.headers, timeout=2, allow_redirects=False)
        content = req.text.strip()
        time.sleep(1)
    except Exception as e:
        print('请求 %s 出现异常 %s'%(urls,type(e)))
    return content


def check(**kwargs):
    mphone = kwargs['url']#/*str*/
    status = spider('https://account.chsi.com.cn/account/checkmobilephoneother.action', mphone)
    if status == 'false':
        print('%s 已注册'%(mphone))
        return '已注册'
    elif status == 'true':
        print('%s 未注册'%(mphone))
        return '未注册'
    else:
        print('%s 出现错误'%(mphone))
        time.sleep(2)
        return
if __name__ == "__main__":
    a = spider('https://account.chsi.com.cn/account/checkmobilephoneother.action','13231700895')
    print(a)