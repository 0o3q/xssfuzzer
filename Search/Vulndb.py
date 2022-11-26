from typing import Counter
from urllib.parse import parse_qs, urlencode, urlparse, urljoin
from Search.payloads import *
from bs4 import BeautifulSoup, Comment
from Utils.utils import RandomString, double_randint
from requests.exceptions import TooManyRedirects, ConnectTimeout
from base64 import b64decode
from Crawler import sessions
import warnings
import re
from requests.exceptions import *

warnings.filterwarnings("ignore", category=UserWarning, module='bs4')

__all__ = [
    'ReflectedXSS',
    'CrossSiteRequestForgery',
]

def init_session():
    return sessions()(Site=False)

attr = {
    'first_url':1,
    'current_url':2,
    'method':3,
    # 'history':4,
    # 'history_len':5,
    'response_url':4,
    'response_cookies':5,
    'response_headers':6,
    'response_status':7,
    'request_cookies':8,
    'request_headers':9,
    'data':10,
    'body':11
}

STRING_OR_COMMENT_REMOVE_REGEX = """([`'"](?!'"`).*?[`'"])|(\/\/.*)|(\/\*((.|\n)*)\*\/)"""
LINUX_DEFAULT_FILE_ETC_PASSWD_FORMAT_REGEX = r"^(#.*|[a-z]*:[^:]*:[0-9]*:[0-9]*:[^:]*:/[^:]*:/[^:]*)$"

def report(vuln, url, req_info, pay):
    print("="*50)
    print(f"{vuln} find!!")
    print(f"URL: {url}")
    print(f"Request: {req_info}")
    print(f"Payload: {pay}")

class ReflectedXSS:
    def __init__(self, datatable, **info):
        self.element_eq_pay, \
            self.element_empty_value, \
                self.element_event, \
                    self.script_pay, \
                        self.alert_box_check, \
                            self.attribute_injection, \
                                self.cross_site_scriping_pay\
                                    = fuzzer_payloads.xss()
        self.datatable = datatable
        self.sess = sessions().init_sess()
        self.input_payload = ''
        self.message = False
        self.vuln_level = 0
        self.req_info = {}
        self.info = info

        self.exploit()

    def exploit(self):
        for content in self.datatable:
            self.body = b64decode(content[attr['body']]).decode()
            self.current_url = content[attr['current_url']]
            self.urinfo = urlparse(self.current_url)
            self.method = content[attr['method']]
            try:
                self.search_text(
                    data = content[attr['data']],
                    headers = content[attr['request_headers']],
                    cookies = content[attr['request_cookies']],
                )
            except:
                continue

    def search_text(self, data, headers, cookies):
        rs = RandomString(5)
        
        if self.urinfo.query:
            qs = parse_qs(self.urinfo.query)
            for key, value in qs.items():
                if type(value) == list:
                    value = value[0]
                self.req_info = {'vector':'qs','key':key, 'input':dict(qs)}
                if value in self.body and (rs in self.string_search_text(rs)):
                    self.html_injection_test()

        if data:
            for key, value in data.items():
                self.req_info = {'vector':'data', 'key':key, 'input':dict(data)}
                if value in self.body and (rs in self.string_search_text(rs)):
                    self.html_injection_test()

        if cookies:
            for key, value in cookies.items():
                self.req_info = {'vector':'cookies','key':key, 'input':dict(cookies)}
                if value in self.body and (rs in self.string_search_text(rs)):
                    self.html_injection_test()

        if headers:
            for key, value in headers.items():
                self.req_info = {'vector':'headers','key':key, 'input':dict(headers)}
                if value in self.body and (rs in self.string_search_text(rs)):
                    self.html_injection_test()

    def string_search_text(self, rs):
        temp = self.req_info['input']
        rs = rs
        if self.req_info['vector'] == 'fragment':
            r = self.sess.request(self.method, self.urinfo._replace(**{self.req_info['vector']:rs}).geturl(), **self.info)
        elif self.req_info['vector'] == 'qs':
            temp[self.req_info['key']] = rs
            r = self.sess.request(self.method, self.urinfo._replace(query=urlencode(temp, doseq=True)).geturl(), **self.info)
        else:
            temp[self.req_info['key']] = rs
            r = self.sess.request(self.method, self.current_url, **{self.req_info['vector']:temp}, **self.info)

        return r.text
    
    def html_injection_test(self):
        for attr in self.attribute_injection:
            attr_key = RandomString(5)
            attr_val = RandomString(5)
            rs = attr.format(attr_key, attr_val)
            test = self.string_search_text(rs)
            soup = BeautifulSoup(test, 'html.parser')
            if soup.find(attrs={attr_key.lower():attr_val}):
                self.message = (rs, self.req_info)
                if self.cross_site_scripting_test('attr'):
                    return
        for element in self.element_eq_pay:
            attribute_key_rs = RandomString(5)
            attribute_value_rs = RandomString(5)
            inner_text_rs = RandomString(5)
            rs = element.format(attribute_key_rs,attribute_value_rs, inner_text_rs)
            soup = BeautifulSoup(self.string_search_text(rs), 'html.parser')
            if soup.find(attrs={attribute_key_rs.lower():attribute_value_rs}, text=inner_text_rs) or soup.find(attrs={attribute_value_rs.lower():attribute_value_rs}) or soup.find(text=inner_text_rs):
                self.message = (rs, self.req_info)
                if self.cross_site_scripting_test('element'):
                    return
            elif [rs in i.text for i in soup.find_all('script')]:
                self.message = (rs, self.req_info)
                if self.cross_site_scripting_test('script'):
                    return
            elif [rs in i for i in soup.find_all(text=lambda s: isinstance(s, Comment))]:
                self.message = (rs, self.req_info)
                if self.cross_site_scripting_test('comment'):
                    return

    def cross_site_scripting_test(self, vector):
        if vector == 'attr':
            for element_event in self.element_event:
                for attr in self.attribute_injection:
                    for box in self.alert_box_check:
                        rs = attr.format(element_event, box)
                        soup = BeautifulSoup(self.string_search_text(rs), 'html.parser')
                        if soup.find(attrs={element_event.lower():box}):
                            report(vuln='XSS',url=self.current_url,req_info=self.req_info,pay=rs)
                            return True

        elif vector in ['comment', 'element']:
            for alert in self.cross_site_scriping_pay:
                alert_soup = BeautifulSoup(alert, 'html.parser').find()
                return_soup = BeautifulSoup(self.string_search_text(alert), 'html.parser')
                if return_soup.find(attrs=alert_soup.attrs, name=alert_soup.name, text=alert_soup.text):
                    report(vuln='XSS',url=self.current_url,req_info=self.req_info,pay=alert)
                    return True
            return False
        elif vector == 'script':
            for script_pay in self.script_pay:
                soup = BeautifulSoup(self.string_search_text(script_pay), 'html.parser')
                for script_tag in soup.find_all('script'):
                    temp = re.sub(STRING_OR_COMMENT_REMOVE_REGEX, '', script_tag.string)
                    if True in [i in temp for i in [ 'alert()', 'prompt()', 'print()', 'confirm()']]:
                        report(vuln='XSS',url=self.current_url,req_info=self.req_info,pay=script_pay)
                        return True
        return False

class CrossSiteRequestForgery:
    def __init__(self, datatable, **info) -> None:
        self.info = info
        self.database = datatable
        self.sess = sessions().init_sess()

    def exploit(self):
        for content in self.database:
            self.sess = sessions().init_sess()
            self.body = b64decode(content[attr['body']]).decode()
            self.current_url = content[attr['current_url']]
            self.urinfo = urlparse(self.current_url)
            self.method = content[attr['method']]
            try:
                self.request_key = {
                    'data':content[attr['data']],
                    'headers':content[attr['request_headers']],
                    'cookies':content[attr['request_cookies']],
                }
                self.search_text()
            except Exception as e:
                print('NOSQLInjection :', e)
                continue
    
    def search_text(self):
        if self.urinfo.query:
            qs = parse_qs(self.urinfo.query)
            for key, value in qs.items():
                if type(value) == list:
                    value = value[0]
                self.req_info = {'vector':'qs','key':key, 'input':dict(qs)}
                self.nosql_where_sleep_injection()

        if self.request_key['data']:
            for key, value in self.request_key['data'].items():
                self.req_info = {'vector':'data', 'key':key, 'input':dict(self.request_key['data'])}
                self.nosql_where_sleep_injection()

        if self.request_key['cookies']:
            for key, value in self.request_key['cookies'].items():
                self.req_info = {'vector':'cookies','key':key, 'input':dict(self.request_key['cookies'])}
                self.nosql_where_sleep_injection()

        if self.request_key['headers']:
            for key, value in self.request_key['headers'].items():
                self.req_info = {'vector':'headers','key':key, 'input':dict(self.request_key['headers'])}
                self.nosql_where_sleep_injection()

    def string_search_text(self, rs, timeout=3):
        temp = self.req_info['input']
        rs = rs
        if self.req_info['vector'] == 'fragment':
            r = self.sess.request(self.method, self.urinfo._replace(**{self.req_info['vector']:rs}).geturl(), **(self.info | {'timeout':timeout}))
        elif self.req_info['vector'] == 'qs':
            temp[self.req_info['key']] = rs
            r = self.sess.request(self.method, self.current_url, params=urlencode(temp, doseq=True), **(self.info | {'timeout':timeout}))
        else:
            temp[self.req_info['key']] = rs
            r = self.sess.request(self.method, self.current_url, **{self.req_info['vector']:temp}, **(self.info | {'timeout':timeout}))
        return r.text

    def csrf_token_matching(self):
        pass
