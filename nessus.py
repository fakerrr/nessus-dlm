#!/usr/bin/env python
#_*_ encoding: utf-8 _*_
from securitycenter import SecurityCenter5
import json
import sys
import re
reload(sys)
sys.setdefaultencoding('utf-8')



#设置账号密码
url = 'xxx .com'
username = 'admin'
password = 'admin'
#使用nessus官方库进行登录
sc =  SecurityCenter5(url)
sc.login(username,password)
#获取证书数据信息
credential = sc.get('credential?filter=usable&fields=name%2Cdescription%2CmodifiedTime%2Ctype%2Cowner%2CownerGroup%2Ctags')
credential_data = credential.json()
#获取扫描任务信息
test = sc.get('scan?filter=usable&fields=canUse%2CcanManage%2Cowner%2Cgroups%2CownerGroup%2Cstatus%2Cname%2CcreatedTime%2Cschedule%2Cpolicy%2Cplugin%2Ctype')
a = test.json()
#获取新导入的证书ID用于修改扫描任务，使用ip进行匹配遍历证书数据，将以ip开头的证书id返回出来
def GetCredentialData(ip):
    for x in credential_data['response']['usable']:
        if ip in x['name']:
            print(x['name'])
            print(x['id'])
            if x['name'].startswith(ip):
                print("it's new credential")
                return(x['id'])
#遍历扫描任务，获取所有基线扫描任务id，以此id进行扫描任务修改
for i in a['response']['usable']:
    print('policy_id is '+ i['policy']['id']+'\r\njob name is '+i['name'])
    if i['policy']['id'] ==  '1000001' or i['policy']['id'] == '1000002':
        #获取任务名中的ip地址
        ip = re.findall(r'[0-9]+(?:\.[0-9]+){3}',i['name'])
        print(i['name'])
        print(ip[0])
        # 获取扫描任务的扫描策略编号，1000002是windows基线，1000001是linux基线
        print("scan job policy id is " + i['policy']['id'] + "\r\nid = 1000002 is windows ; id = 1000001 is linux")
        policy_id = (i['policy']['id'])
        credential_id = GetCredentialData(ip[0])
        if credential_id:
            credential_id = int(credential_id)
            parameters = {
                "repository":{
                    "id":3
                },
                "schedule":{
                    "start":"TZID=Asia/Shanghai:20190424T110000",
                    "repeatRule":"FREQ=TEMPLATE;INTERVAL=1",
                    "type":"template"
                },
                "policy":{
                    "id":policy_id
                },
                "credentials":[
                    {
                        "id":credential_id
                    }
                ],
                "plugin":{
                    "id":-1
                }
            }
            sc.patch('scan/%s' %i['id'],data=json.dumps(parameters))
        else:
            continue
    else:
        continue
