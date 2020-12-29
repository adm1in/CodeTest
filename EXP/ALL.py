import sys
sys.path.append('../')
from ClassCongregation import _urlparse
from CodeTest import color,now
from EXP import ApacheActiveMQ
from EXP import ApacheShiro
from EXP import ApacheSolr
from EXP import ApacheStruts2
from EXP import ApacheTomcat
from EXP import ApacheUnomi
from EXP import Drupal
from EXP import Elasticsearch
from EXP import Fastjson
from EXP import Jenkins
from EXP import Nexus
from EXP import OracleWeblogic
from EXP import RedHatJBoss
from EXP import ThinkPHP

def check(**kwargs):
    url = _urlparse(kwargs['url'])
    now.timed(de = 0)
    color ("[+] Scanning target domain "+url, 'green')
    ExpApacheActiveMQ = ApacheActiveMQ.ApacheActiveMQ(url,"echo VuLnEcHoPoCSuCCeSS")
    ExpApacheShiro = ApacheShiro.ApacheShiro(url,"echo VuLnEcHoPoCSuCCeSS")
    ExpApacheSolr = ApacheSolr.ApacheSolr(url,"echo VuLnEcHoPoCSuCCeSS")
    ExpApacheStruts2 = ApacheStruts2.ApacheStruts2(url,"echo VuLnEcHoPoCSuCCeSS")
    ExpApacheTomcat = ApacheTomcat.ApacheTomcat(url,"echo VuLnEcHoPoCSuCCeSS")
    ExpApacheUnomi = ApacheUnomi.ApacheUnomi(url,"echo VuLnEcHoPoCSuCCeSS")
    ExpDrupal = Drupal.Drupal(url,"echo VuLnEcHoPoCSuCCeSS")
    ExpElasticsearch = Elasticsearch.Elasticsearch(url,"echo VuLnEcHoPoCSuCCeSS")
    ExpFastjson = Fastjson.Fastjson(url,"echo VuLnEcHoPoCSuCCeSS")
    ExpJenkins = Jenkins.Jenkins(url,"echo VuLnEcHoPoCSuCCeSS")
    ExpNexus = Nexus.Nexus(url,"echo VuLnEcHoPoCSuCCeSS")
    ExpOracleWeblogic = OracleWeblogic.OracleWeblogic(url,"echo VuLnEcHoPoCSuCCeSS")
    ExpRedHatJBoss = RedHatJBoss.RedHatJBoss(url,"echo VuLnEcHoPoCSuCCeSS")
    ExpThinkPHP = ThinkPHP.ThinkPHP(url,"echo VuLnEcHoPoCSuCCeSS")

    #ApacheActiveMQ
    ExpApacheActiveMQ.cve_2015_5254()
    ExpApacheActiveMQ.cve_2016_3088()

    #ApacheShiro
    ExpApacheShiro.cve_2016_4437()

    #ApacheSolr
    ExpApacheSolr.cve_2017_12629()
    ExpApacheSolr.cve_2019_0193()
    ExpApacheSolr.cve_2019_17558()

    #ApacheStruts2
    ExpApacheStruts2.s2_005()
    ExpApacheStruts2.s2_008()
    ExpApacheStruts2.s2_009()
    ExpApacheStruts2.s2_013()
    ExpApacheStruts2.s2_015()
    ExpApacheStruts2.s2_016()
    ExpApacheStruts2.s2_029()
    ExpApacheStruts2.s2_032()
    ExpApacheStruts2.s2_045()
    ExpApacheStruts2.s2_046()
    ExpApacheStruts2.s2_048()
    ExpApacheStruts2.s2_052()
    ExpApacheStruts2.s2_057()
    ExpApacheStruts2.s2_059()
    ExpApacheStruts2.s2_061()
    ExpApacheStruts2.s2_devMode()

    #ApacheTomcat
    ExpApacheTomcat.tomcat_examples()
    ExpApacheTomcat.cve_2017_12615()
    ExpApacheTomcat.cve_2020_1938()

    #ApacheUnomi
    ExpApacheUnomi.cve_2020_13942()

    #Drupal
    ExpDrupal.cve_2018_7600()
    ExpDrupal.cve_2018_7602()
    ExpDrupal.cve_2019_6340()

    #Elasticsearch
    ExpElasticsearch.cve_2014_3120()
    ExpElasticsearch.cve_2015_1427()

    #Fastjson
    ExpFastjson.cve_2017_18349_24()
    ExpFastjson.cve_2017_18349_47()

    #Jenkins
    ExpJenkins.cve_2017_1000353()
    ExpJenkins.cve_2018_1000861()

    #Nexus
    ExpNexus.cve_2019_7238()
    ExpNexus.cve_2020_10199()

    #OracleWeblogic
    ExpOracleWeblogic.cve_2014_4210()
    ExpOracleWeblogic.cve_2017_3506()
    ExpOracleWeblogic.cve_2017_10271()
    ExpOracleWeblogic.cve_2018_2894()
    ExpOracleWeblogic.cve_2019_2725()
    ExpOracleWeblogic.cve_2019_2729()
    ExpOracleWeblogic.cve_2020_2551()
    ExpOracleWeblogic.cve_2020_2555()
    ExpOracleWeblogic.cve_2020_2883()
    ExpOracleWeblogic.cve_2020_14882()

    #RedHatJBoss
    ExpRedHatJBoss.cve_2010_0738()
    ExpRedHatJBoss.cve_2010_1428()
    ExpRedHatJBoss.cve_2015_7501()

    #ThinkPHP
    ExpThinkPHP.cve_2018_20062()
    ExpThinkPHP.cve_2019_9082()

