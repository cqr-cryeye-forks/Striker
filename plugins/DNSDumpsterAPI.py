"""
This is the (unofficial) Python API for dnsdumpster.com Website.
Using this code, you can retrieve subdomains

"""
from __future__ import print_function

import http
import re
import sys

import requests
from bs4 import BeautifulSoup


class DNSDumpsterAPI:
    """DNSDumpsterAPI Main Handler"""

    def __init__(self, verbose=False):
        self.verbose = verbose

    def display_message(self, s):
        if self.verbose:
            print(f'[verbose] {s}')

    @staticmethod
    def retrieve_results(table):
        res = []
        trs = table.findAll('tr')
        for tr in trs:
            tds = tr.findAll('td')
            pattern_ip = r'([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})'
            ip = re.findall(pattern_ip, tds[1].text)[0]
            domain = tds[0].text.replace('\n', '').split(' ')[0]
            header = ' '.join(tds[0].text.replace('\n', '').split(' ')[1:])
            reverse_dns = tds[1].find('span', attrs={}).text

            additional_info = tds[2].text
            country = tds[2].find('span', attrs={}).text
            autonomous_system = additional_info.split(' ')[0]
            provider = ' '.join(additional_info.split(' ')[1:])
            provider = provider.replace(country, '')
            data = {'domain': domain,
                    'ip': ip,
                    'reverse_dns': reverse_dns,
                    'as': autonomous_system,
                    'provider': provider,
                    'country': country,
                    'header': header}
            res.append(data)
        return res

    @staticmethod
    def retrieve_txt_record(table):
        return [td.text for td in table.findAll('td')]

    def search(self, domain):
        dnsdumpster_url = 'https://dnsdumpster.com/'
        s = requests.session()
        headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'max-age=0',
            'TE': 'Trailers',
        }
        req = s.get(dnsdumpster_url, headers=headers, verify=False)
        soup = BeautifulSoup(req.content, 'html.parser')
        csrf_middleware = soup.findAll('input', attrs={'name': 'csrfmiddlewaretoken'})[0]['value']
        self.display_message(f'Retrieved token: {csrf_middleware}')

        cookies = {'csrftoken': csrf_middleware}
        headers['Referer'] = dnsdumpster_url
        data = {'csrfmiddlewaretoken': csrf_middleware, 'targetip': domain, 'user': 'free'}
        req = s.post(dnsdumpster_url, cookies=cookies, data=data, headers=headers, verify=False)

        if req.status_code != 200:
            print(
                u"Unexpected status code from {url}: {code}".format(
                    url=dnsdumpster_url, code=req.status_code),
                file=sys.stderr,
            )
            return []

        page_data = req.content.decode('utf-8')
        if 'There was an error getting results' in page_data:
            raise ValueError("There was an error getting results")

        if 'Too many requests from your IP address, temporary limit enforced. Try again tomorrow or go PRO with ' \
                in page_data:
            raise ValueError(
                "Too many requests from this IP address. Need PRO tool: https://hackertarget.com/domain-profiler/")

        soup = BeautifulSoup(req.content, 'html.parser')
        tables = soup.findAll('table')

        print(tables)

        resource = {'domain': domain, 'dns_records': {}}
        resource['dns_records']['dns'] = self.retrieve_results(tables[0])
        resource['dns_records']['mx'] = self.retrieve_results(tables[1])
        resource['dns_records']['txt'] = self.retrieve_txt_record(tables[2])
        resource['dns_records']['host'] = self.retrieve_results(tables[3])

        # Network mapping image
        try:
            val = soup.find('img', attrs={'class': 'img-responsive'})['src']
            if val.startswith('/'):
                val = val[1:]
            tmp_url = f'{dnsdumpster_url}{val}'
            response = requests.get(tmp_url, verify=False)
            # image_data = response.content.decode()
            resource['img'] = tmp_url
            resource['is_image_available'] = response.status_code == http.HTTPStatus.OK
            # resource['image_data'] = image_data
        except Exception as e:
            print(f'Get DNS image error: {e}')
            resource['is_image_available'] = False

        # XLS hosts.
        # eg. example.com-201606131255.xlsx
        try:
            pattern = f'https://dnsdumpster.com/static/xls/{domain}-[0-9]12\.xlsx'
            if xls_url := re.findall(pattern, req.content.decode('utf-8')):
                xls_url = xls_url[0]
                xls_data = requests.get(xls_url, verify=False).content.decode('base64')
                resource['xls_data'] = xls_data
        except Exception as e:
            print(f'Get XLS data error: {e}')

        return resource
