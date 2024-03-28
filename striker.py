#!/usr/bin/env python3.10
import contextlib
import http
import json
import os
import re
import socket
from http.cookiejar import LWPCookieJar
from re import search
from urllib.error import HTTPError
from urllib.parse import urlencode, urlparse

import mechanize
import nmap
import requests
from mechanize import HTTPRefreshProcessor
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning

from constants import result_dict
from core.cli_arguments import cli_arguments
from plugins.DNSDumpsterAPI import DNSDumpsterAPI

disable_warnings(InsecureRequestWarning)


class Checker:

    def __init__(self, target_url):
        self.br = self._init_browser()
        self._init_target(target_url)
        self.ip_addr = socket.gethostbyname(self.domain)
        self.bypass_ip_addr = None
        # params = []
        result_dict["global_info"] = {}
        print(f'[!] IP Address : {self.ip_addr}')
        result_dict["global_info"]["ip_address"] = self.ip_addr

        try:
            r = requests.get(target, verify=False)
            header = r.headers['Server']
            if 'cloudflare' in header:
                print('[-] Cloudflare detected')
                result_dict["global_info"]["cloudflare"] = "Detected"

                self.bypass(self.domain)
            else:
                print(f'[!] Server: {header}')
                result_dict["global_info"]["server"] = header

            with contextlib.suppress(KeyError):
                print('[!] Powered By: ' + r.headers['X-Powered-By'])
                result_dict["global_info"]["server"] = header

            try:
                print(f"[!] Clickjacking protection {r.headers['X-Frame-Options']}")
                result_dict["global_info"]["clickjacking_protection"] = r.headers['X-Frame-Options']

            except KeyError:
                print('[-] Clickjacking protection is not in place.')

        except Exception as e:
            print(f"Gather general information error: {e}")

    @staticmethod
    def _init_browser():
        # ssl._create_default_https_context = ssl._create_unverified_context
        br = mechanize.Browser()
        # br.set_ca_data(context=ssl._create_unverified_context(cert_reqs=ssl.CERT_NONE))
        # Cookie Jar
        cj = LWPCookieJar()
        br.set_cookiejar(cj)

        # Browser options
        br.set_handle_equiv(True)
        br.set_handle_redirect(True)
        br.set_handle_referer(True)
        br.set_handle_robots(False)

        # Follows refresh 0 but not hangs on refresh > 0
        br.set_handle_refresh(HTTPRefreshProcessor(), max_time=1)
        br.addheaders = [
            ('User-agent',
             'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36')]
        return br

    def _init_target(self, target_url):
        if 'http' in target_url:
            parsed_uri = urlparse(target_url)
            self.domain = '{uri.netloc}'.format(uri=parsed_uri)
        else:
            self.domain = target_url
            try:
                self.br.open(f'http://{target_url}')
                self.target = f'http://{target_url}'
            except Exception:
                self.target = f'https://{target_url}'

    def sql_injection(self, url):
        req = self.br.open('https://suip.biz/?act=sqlmap').read()
        self.br.select_form(nr=0)
        self.br.form['page'] = url
        req = self.br.submit()
        result = str(req.read().decode('utf-8'))
        if match := search(fr"---{re.S}\.*---", result):
            print('[+] One or more parameters are vulnerable to SQL injection')
            # result_dict["fuzzable_urls"]["xss"] = True
            run_test = bool(cli_arguments.silent or input('[?] Show whole report? [Y/n] ').lower() != 'n')
            if run_test:
                print("-" * 40)
                print(match.group().split('---')[1][:-3])
                print("-" * 40)
        else:

            print('[-] None of parameters is vulnerable to SQL injection')
#             result_dict["fuzzable_urls"]["xss"] = False

    def cms(self):
        try:
            result = str(self.br.open(f'https://whatcms.org/?s={self.domain}').read())
            detect = search(r'">[^<]*</a><a href="/New-Detection', result)
            is_word_press = False
            with contextlib.suppress(Exception):
                r = self.br.open(f'{target}/robots.txt').read().decode('utf-8')
                if "wp-admin" in str(r):
                    is_word_press = True
            if detect:
                detect_cms = detect.group().split('">')[1][:-27]
                print(f"[!] CMS Detected : {detect_cms}")
                result_dict["global_info"]["cms"] = detect_cms

                if 'WordPress' in detect:
                    run_test = bool(cli_arguments.silent or input('[?] Use WPScan? [Y/n] ').lower() != 'n')
                    if run_test:
                        os.system(f'wpscan --random-agent --url {self.domain}')
            elif is_word_press:
                print("[!] CMS Detected : WordPress")
                result_dict["global_info"]["cms"] = "WordPress"
                run_test = bool(cli_arguments.silent or input('[?] Use WPScan? [Y/n] ').lower() != 'n')
                if run_test:
                    os.system(f'wpscan --random-agent --url {self.domain}')
            else:
                print(f"[!] {self.domain} doesn't seem to use a CMS")
                result_dict["global_info"]["cms"] = "False"
        except Exception as e:
            print(f'Get CMS error: {e}')

    def honeypot(self):
        # noinspection SpellCheckingInspection
        honey = f"https://api.shodan.io/labs/honeyscore/{self.ip_addr}?key=C23OXE0bVMrul2YeqcL7zxb6jZ4pj2by"

        try:
            honey_process = str(self.br.open(honey).read().decode('utf-8'))
            if '0.0' in honey_process:
                print("[+] Honeypot Probability: 0%")
                result_dict["global_info"]["honeypot_probability"] = "0%"
            elif '0.1' in honey_process:
                print("[+] Honeypot Probability: 10%")
                result_dict["global_info"]["honeypot_probability"] = "10%"
            elif '0.2' in honey_process:
                print("[+] Honeypot Probability: 20%")
                result_dict["global_info"]["honeypot_probability"] = "20%"
            elif '0.3' in honey_process:
                print("[+] Honeypot Probability: 30%")
                result_dict["global_info"]["honeypot_probability"] = "30%"
            elif '0.4' in honey_process:
                print("[+] Honeypot Probability: 40%")
                result_dict["global_info"]["honeypot_probability"] = "40%"
            elif '0.5' in honey_process:
                print("[-] Honeypot Probability: 50%")
                result_dict["global_info"]["honeypot_probability"] = "50%"
            elif '0.6' in honey_process:
                print("[-] Honeypot Probability: 60%")
                result_dict["global_info"]["honeypot_probability"] = "60%"
            elif '0.7' in honey_process:
                print("[-] Honeypot Probability: 70%")
                result_dict["global_info"]["honeypot_probability"] = "70%"
            elif '0.8' in honey_process:
                print("[-] Honeypot Probability: 80%")
                result_dict["global_info"]["honeypot_probability"] = "80%"
            elif '0.9' in honey_process:
                print("[-] Honeypot Probability: 90%")
                result_dict["global_info"]["honeypot_probability"] = "90%"
            elif '1.0' in honey_process:
                print("[-] Honeypot Probability: 100%")
                result_dict["global_info"]["honeypot_probability"] = "100%"
        except Exception as e:
            print(f'[-] Honeypot prediction failed: {e}')

    def nmap_scanner(self):
        nm_scan = nmap.PortScanner()
        result = nm_scan.scan(self.ip_addr)
        result_dict["nmap"] = []

        for host in nm_scan.all_hosts():
            protocols = []
            ports = []

            print(f'Host : {host} ({nm_scan[host].hostname()})')
            print(f'State : {nm_scan[host].state()}')
            for proto in nm_scan[host].all_protocols():
                print('----------')
                print(f'Protocol : {proto}')
                protocols.append(proto)

                l_port = sorted(nm_scan[host][proto])
                for port in l_port:
                    print('port : %s\t state : %s' % (port, nm_scan[host][proto][port]['state']))
                    ports.append(f"{port} - {nm_scan[host][proto][port]['state']}")

            obj = {
                "host": host,
                "state": nm_scan[host].state(),
                "protocols": protocols,
                "ports": ports,
            }
            result_dict["nmap"].append(obj)

    def bypass(self, domain: str = None):
        if not domain:
            domain = self.domain
        post = urlencode({'cfS': domain})
        result = str(self.br.open('http://www.crimeflare.info/cgi-bin/cfsearch.cgi ', dict(post)
                                  ).read().decode('utf-8'))

        if match := search(r' \b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', result):
            self.bypass_ip_addr = match.group().split(' ')[1][:-1]
            result_dict["global_info"]["real_ip_address"] = self.bypass_ip_addr

            print(f'[+] Real IP Address : {self.bypass_ip_addr}')

    def dns_dump(self):
        try:
            resource = DNSDumpsterAPI(verbose=False).search(self.domain)
        except ValueError as e:
            print(e)
            return

        print('\n[+] DNS Records')
        result_dict["dns_dump"]["dns_records"] = []
        result_dict["dns_dump"]["mx_records"] = []
        result_dict["dns_dump"]["host_records"] = []
        result_dict["dns_dump"]["txt_records"] = []

        for entry in resource['dns_records']['dns']:
            line = ("{domain} ({ip}) {as} {provider} {country}".format(**entry))
            print(line)
            result_dict["dns_dump"]["dns_records"].append({"record": line})

        for entry in resource['dns_records']['mx']:
            print("\n[+] MX Records")
            line = ("{domain} ({ip}) {as} {provider} {country}".format(**entry))
            print(line)
            result_dict["dns_dump"]["mx_records"].append({"record": line})

        print("\n[+] Host Records (A)")
        for entry in resource['dns_records']['host']:
            if entry['reverse_dns']:
                line = ("{domain} ({reverse_dns}) ({ip}) {as} {provider} {country}".format(**entry))
                print(line)
            else:
                line = ("{domain} ({ip}) {as} {provider} {country}".format(**entry))
                print(line)
            result_dict["dns_dump"]["host_records"].append({"record": line})

        print('\n[+] TXT Records')
        for entry in resource['dns_records']['txt']:
            print(entry)
            result_dict["dns_dump"]["txt_records"].append({"record": entry})

        dns_image_link = f"https://dnsdumpster.com/static/map/{self.domain}.png"
        try:
            response = requests.get(dns_image_link, verify=False)
            if response.status_code == http.HTTPStatus.OK:
                print(f'\n[+] DNS Map: {dns_image_link}\n')
                result_dict['dns_dump']['dns_map'] = str(dns_image_link)
        except Exception as e:
            result_dict['dns_dump']['dns_map'] = "Not found"
            print(e)
        else:
            result_dict['dns_dump']['dns_map'] = "Not found"
            print('\n[-] No map for DNS')

    def fingerprint(self):
        try:
            result = str(self.br.open(f'https://www.censys.io/ipv4/{self.ip_addr}/raw').read())
            if match := search(r'os_description: [^<];', result):
                print('[+] Operating System : ' + match.group().split(':')[1][:-5])
                result_dict["global_info"]["operating_system"] = match.group().split(':')[1][:-5]
        except Exception as e:
            print(f"[>] Gather operation system error: {e}")

    def get_robots_txt(self):
        try:
            r = self.br.open(f'{target}/robots.txt').read().decode('utf-8')
            print('[+] Robots.txt retrieved\n', r)
            result_dict["global_info"]["robots_txt"] = r
        except Exception as e:
            print(f"[>] Gather Robots.txt retrieved error: {e}")

    def run_harvester(self):
        os.system(f'cd plugins/theHarvester && python3 theHarvester.py -d {self.domain} -b all')

    def wrapper_sql_injection(self):
        params = []
        try:
            self.br.open(target)
            print('[>] Crawling the target for fuzzable URLs')
            result_dict["fuzzable_urls"] = {"urls": []}

            for link in self.br.links():
                if 'http' not in link.url and '=' in link.url:
                    url = f'{target}/{link.url}'
                    params.append(url)
            if not params:
                print('[-] No fuzzable URLs found')
                result_dict["fuzzable_urls"]["amount"] = 0
                return

            print('[+] Found %i fuzzable URLs' % len(params))
            result_dict["fuzzable_urls"]["amount"] = len(params)

            for url in params:
                print(url)
                self.sql_injection(url)
                url = url.replace('=', '<svg/onload=alert()>')
                with contextlib.suppress(HTTPError):
                    r = str(self.br.open(url).read().decode('utf-8'))
                    vulnerable = False
                    if '<svg/onload=alert()>' in r:
                        print('[+] One or more parameters are vulnerable to XSS')
                        vulnerable = True
                    obj = {"url": url,
                           "vulnerable_to_xss": vulnerable,
                           }
                    result_dict["fuzzable_urls"]["urls"].append(obj)

                    break
        except Exception as e:
            print(e)


if __name__ == '__main__':
    target = cli_arguments.url
    output_file = cli_arguments.output_file

    checker = Checker(target)
    checker.fingerprint()
    checker.cms()
    checker.honeypot()

    print("-" * 40 + 'Get robot.txt' + "-" * 40)
    checker.get_robots_txt()
    print("-" * 40 + 'Nmap' + "-" * 40)
    checker.nmap_scanner()
    print("-" * 40 + 'DNS dump' + "-" * 40)
    checker.dns_dump()
    print("-" * 40 + 'Run harvester' + "-" * 40)
    checker.run_harvester()
    print("-" * 40 + 'Testing SQL Injection' + "-" * 40)
    checker.wrapper_sql_injection()

    json_data = json.dumps(result_dict)
    output_file.write_text(json_data)
    print(f"Final results save to {output_file.absolute().as_uri()}")
