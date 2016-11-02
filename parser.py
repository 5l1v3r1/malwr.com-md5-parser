from bs4 import BeautifulSoup

import requests

import json

head = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36', 'Connection': 'keep-alive', 'Accept': '*/*', 'Accept-Encoding': 'gzip, deflate'}

s = requests.Session()
login_url = "https://malwr.com/account/login/"
r1 = s.get(login_url, headers=head)
csrf_token = r1.cookies['csrftoken']
data = {"username":"******", "password":"*******","csrfmiddlewaretoken":csrf_token}
r = s.post(login_url, data=data, headers=head)

r1  = s.get("https://malwr.com/analysis/search/",headers=head)

r = s.post("https://malwr.com/analysis/search/", data={"search":"signature:Performs some HTTP requests", "csrfmiddlewaretoken":r1.cookies['csrftoken']}, headers=head)
data = r.text

soup = BeautifulSoup(data, "lxml")
list = []
for tr in soup.find_all("table", {"class" : "table table-striped"}):
	links = tr.find_all('a')
	for link in links:
		list.append(str(link.get_text()))

data = [['Md5', 'Symantec', 'Microsoft', 'ESET-NOD32', 'F-Secure', 'Kaspersky', 'McAfee', 'Sophos']]
for md5 in list:
	r = requests.post("https://www.virustotal.com/vtapi/v2/file/report", data = {"apikey": 'your api key', "resource": md5})
	res = json.loads(r.text)
	if res['response_code']:
		lst = [md5,res['scans']['Symantec']['result'],res['scans']['Symantec']['result'],res['scans']['ESET-NOD32']['result'],res['scans']['F-Secure']['result'],res['scans']['Kaspersky']['result'],res['scans']['McAfee']['result'],res['scans']['Sophos']['result']]
	else:
		lst = [md5,'None','None','None','None','None','None','None']	
	data.append(lst)
import csv
with open('test.csv', 'w', newline='') as fp:
    a = csv.writer(fp, delimiter=',')
    a.writerows(data)
