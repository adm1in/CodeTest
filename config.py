###################基础输出环境配置###################
VUL_EXP = {
    'ApacheActiveMQ': ['cve_2015_5254','cve_2016_3088'],
    'ApacheShiro': ['cve_2016_4437'],
    'ApacheSolr': ['cve_2017_12629','cve_2019_0193','cve_2019_17558'],
    'ApacheStruts2': ['s2_005', 's2_008', 's2_009', 's2_013', 's2_015', 's2_016', 's2_029', 's2_032', 's2_045', 's2_046', 's2_048', 's2_052', 's2_057', 's2_059', 's2_061', 's2_devMode'],
    'ApacheTomcat': ['tomcat_examples','cve_2017_12615','cve_2020_1938'],
    'ApacheUnomi': ['cve_2020_13942'],
    'Drupal': ['cve_2018_7600', 'cve_2018_7602', 'cve_2019_6340'],
    'Elasticsearch': ['cve_2014_3120','cve_2015_1427'],
    'Jenkins': ['cve_2017_1000353','cve_2018_1000861'],
    'Nexus': ['cve_2019_7238','cve_2020_10199'],
    'OracleWeblogic': ['cve_2014_4210', 'cve_2017_3506', 'cve_2017_10271', 'cve_2018_2894', 'cve_2019_2725', 'cve_2019_2729', 'cve_2020_2551', 'cve_2020_2555', 'cve_2020_2883', 'cve_2020_14882'],
    'RedHatJBoss': ['cve_2010_0738','cve_2010_1428','cve_2015_7501'],
    'ThinkPHP': ['cve_2018_20062','cve_2019_9082'],
    'Fastjson': ['cve_2017_18349_24','cve_2017_18349_47']
}

headers = {
    'Accept': 'application/x-shockwave-flash,'
              'image/gif,'
              'image/x-xbitmap,'
              'image/jpeg,'
              'image/pjpeg,'
              'application/vnd.ms-excel,'
              'application/vnd.ms-powerpoint,'
              'application/msword,'
              '*/*',
    'User-agent':'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Safari/537.36',
    'Content-Type':'application/x-www-form-urlencoded'
}

VULN = True
DEBUG = None
DELAY = 0
TIMEOUT = 10
OUTPUT = None
CMD = "echo VuLnEcHoPoCSuCCeSS"
RUNALLPOC = False