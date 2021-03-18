import requests
from bs4 import BeautifulSoup
from urllib.parse import parse_qs,urlparse
import json
import c_html
import time, os, sys, re

def get_contant(url,headers):
    contant={}
    table_tr0 = ''
    table_tr1 = ""
    table_tr2 = ""
    num=0
    global author
    global titile
    html = c_html.Template_mixin()
    VERSION_DICT ={}
    request = requests.get(url, headers=headers)
    if (request.status_code != 200):
        print("获取网址失败")
    soup = BeautifulSoup(request.text, "html.parser")

    t = soup.find_all("div", class_="px-3 pt-3 d-block d-lg-none")

    for T in t:
        x = T.find_all(class_="break-all subject m-0")
        y = T.find_all("div",class_="row mx-0 mt-2")
        for I in x:
            title = I.text
            VERSION_DICT['title'] = title
        for k in y:
            k = soup.find_all("div", class_="col-8 px-0")
            for s in k:
               a=s.find_all("a",class_="small")
               for A in a:
                   author=A.string
                   VERSION_DICT['author'] = author



    #VERSION_DICT = {"title": title, "author": author}
    table_td = html.TABLE_TMPL_TOTAL % dict(title=VERSION_DICT['title'], author=VERSION_DICT['author'],)
    table_tr0 += table_td


    post = soup.find_all("tr", class_="post")

    for i in post:
        contant_name = ''
        contant_value = ''
        td = i.find_all("td", class_="px-0")
        for j in td:
            span = j.find("span", class_="username font-weight-bold")
            name = span.find('a')
            contant_name = name.string.strip()

            Contant = j.find("div", class_="message mt-1 break-all")
            contant_value = Contant.text
            contant_Value = ''
            if (contant_value != None):
                contant_Value = contant_value.strip()  # 评论内容
                with open('result.txt', 'a', encoding='utf-8') as f:
                    f.write(json.dumps(contant_Value, ensure_ascii=False) + '\n')
                contant[contant_name] = contant_Value
                num += 1
                case1 = {"name": contant_name, "contant": contant_Value}
                table_td_module = html.TABLE_TMPL_MODULE % dict(name=case1["name"], contant=case1["contant"], )

                table_tr1 += table_td_module
                total_str = '共 %s' % (num)
                output = html.HTML_TMPL % dict(value=total_str, table_tr=table_tr0, table_tr2=table_tr1, )

    filename = 'TestReport.html'
    dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'untitled')
    filename = os.path.join(dir, filename)
    with open(filename, 'wb') as f:
        f.write(output.encode('utf8'))


    print(contant)




#https://bbs.pediy.com/thread-200668.htm
if __name__ == "__main__":
    url = "https://bbs.pediy.com/thread-200668.htm"

    headers = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Encoding': 'gzip, deflate, sdch',
        'Accept-Language': 'zh-CN,zh;q=0.8',
        'Connection': 'keep-alive',
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/43.0.235'
    }

    get_contant(url, headers)
