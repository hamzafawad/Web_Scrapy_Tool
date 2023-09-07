import sys
import logging
from urllib.parse import * 
import requests
import re
import whois
from bs4 import BeautifulSoup, Comment
from urllib.request import *
from http.client  import *
from pprint import pprint
from requests.exceptions import HTTPError
import socket
import time
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.uic import loadUi
from random import *
import datetime
import string
import tldextract
from geopy.geocoders import Nominatim
from http.client  import *
from pprint import pprint
import os
import metadata_parser
from lxml import html
from urllib.error import URLError
import validators
import pyshorteners
import nmap
from socket import getservbyport
import jsbeautifier
import cssbeautifier

class LoginForm(QDialog):
    def __init__(self, parent=None):
        super(LoginForm, self).__init__(parent)
        loadUi("F:/QT5 Projects/MyTool/Scrapy.ui",self)  
        self.ip.clicked.connect(self.Ip) 
       # self.links.clicked.connect(self.lnk)
        self.exit.clicked.connect(self.Quit)
        self.clear.clicked.connect(self.clear_text) 
        self.req.clicked.connect(self.reqst)
        self.dmnV.clicked.connect(self.DV)
        self.headerinfo.clicked.connect(self.hdr)
        self.dminfo.clicked.connect(self.DomainInfo) 
        self.cmnts.clicked.connect(self.Commnets) 
        self.firewall.clicked.connect(self.fire) 
        self.adminpage.clicked.connect(self.AdminPage)
        self.Kywds.clicked.connect(self.keywords)
        self.pglinks.clicked.connect(self.pagslinks)
        self.MediaLinks.clicked.connect(self.medialinks)
        self.Script.clicked.connect(self.scripts)
        self.geolocation.clicked.connect(self.location)   
        self.forms.clicked.connect(self.loginforms) 
        self.subdomains.clicked.connect(self.domains) 
        self.emails.clicked.connect(self.Emails)
        self.images.clicked.connect(self.Images)
        self.metadata.clicked.connect(self.MetaData) 
        self.drivelinks.clicked.connect(self.googledrivlink)
        self.files.clicked.connect(self.Files)
        self.cookies.clicked.connect(self.Cookies)
        self.cms.clicked.connect(self.CMS)
        self.domainfinder.clicked.connect(self.DomainFinder) 
        self.tags.clicked.connect(self.TagsFinder) 
        self.names.clicked.connect(self.Personnames)
        self.programming.clicked.connect(self.Programming) 
        self.shorlinker.clicked.connect(self.ShortLinker)
        self.wbtech.clicked.connect(self.WebTech)
        self.portscanner.clicked.connect(self.PortScanner)
        self.sourcecode.clicked.connect(self.SourceCode)
        current_time = datetime.datetime.now()
        formatted_time = current_time.strftime("%m/%d/%Y %I:%M:%S %p")
        self.output.insertPlainText( formatted_time+"\n")
         
    #main function GUI
    def Quit(self):
            self.close()
    def clear_text(self):
        self.Input.setText("")
        self.output.clear() 
        self.portnum.clear()
        
    def Ip(self):
        domainIp = self.Input.text()
        self.output.insertPlainText("\n <---Ipies details--->\n")
        try:
            response = requests.get("https://"+str(domainIp))
            response.raise_for_status()
 
        except HTTPError as http_err:
                self.output.insertPlainText(str("Server_Down/Not_Found"))
                self.output.insertPlainText("\n")
        except Exception as err:
                self.output.insertPlainText(str("Server_Down/Not_Found"))
                self.output.insertPlainText("\n")
        except socket.gaierror as e:
                print(f'Error: {e}. Could not retrieve information for URL: {url}.')
        else:
                ip_address = socket.gethostbyname(str(domainIp))
                hostname, aliaslist, addresslist = socket.gethostbyaddr(ip_address)
                domain = domainIp.split(".", 1)[1]  
                self.output.insertPlainText("domain: ")
                self.output.insertPlainText(domainIp)
                self.output.insertPlainText("\n")
                self.output.insertPlainText("Hostname: ")
                self.output.insertPlainText(hostname)
                self.output.insertPlainText("\n")
                self.output.insertPlainText(str(socket.gethostbyname(domainIp))+str(response)+str("Server Up")+str("\n"))
                self.output.insertPlainText("\n")
    def reqst(self):
      
        url = self.Input.text()
    
        self.output.insertPlainText("\n <---Req Methos details--->\n")
        methods = []
        
        try:
            # Send a GET request and check the response status code
            response = requests.get("https://" + str(url))
            if response.status_code == 200:
                methods.append('GET')
                self.output.insertPlainText("Request Method: "+str(methods))
        except requests.exceptions.RequestException as e:
            self.output.insertPlainText(f"Error sending GET request: {e}")
            self.output.insertPlainText(f"Error sending GET request: {e}")
            print(f"Error sending GET request: {e}")
        
        try:
            # Send a POST request and check the response status code
            response = requests.post("https://" + str(url))
            if response.status_code == 405:
                self.output.insertPlainText("Request Method: "+str(methods)+str("\n"))
                methods.append('POST')
        except requests.exceptions.RequestException as e:
            print(f"Error sending POST request: {e}")
            self.output.insertPlainText(f"Error sending POST request: {e}")
        
        try:
            # Send a PUT request and check the response status code
            response = requests.put("https://" + str(url))
            if response.status_code == 405:
                self.output.insertPlainText("Request Method: "+str(methods)+str("\n"))
                methods.append('PUT')
        except requests.exceptions.RequestException as e:
            self.output.insertPlainText(f"Error sending PUT request: {e}")
            print(f"Error sending PUT request: {e}")
        
        try:
            # Send a DELETE request and check the response status code
            response = requests.delete("https://" + str(url))
            if response.status_code == 405:
                self.output.insertPlainText("Request Method: "+str(methods)+str("\n"))
                methods.append('DELETE')
        except requests.exceptions.RequestException as e:
            self.output.insertPlainText(f"Error sending DELETE request: {e}")
            print(f"Error sending DELETE request: {e}")
        
        # Print the list of request methods used by the website
        self.output.insertPlainText("Request methods used by the website: "+str(methods)+str("\n"))
        #print('Request methods used by the website:', methods)
     
    def DV(self):
        dv=self.Input.text()
        self.output.insertPlainText("\n <---Domain Versoin details--->\n")
        # Fetch the contents of the readme.html file
        response = requests.get("https://"+str(dv))
        content = response.text
        
        # Search for the WordPress version number in the content
        match = re.search(r'WordPress\s+(\d+(\.\d+)+)', content)
        
        if match:
            version = match.group(1)
            self.output.insertPlainText(str('WordPress version: '))
            self.output.insertPlainText(str(version)+str("\n"))
            #print('WordPress version:', version)
        else:
            # Search for the Joomla version number in the content
            match = re.search(r'Joomla!\s+(\d+(\.\d+)+)', content)
            if match:
                version = match.group(1)
                self.output.insertPlainText(str('Joomla version: '))
                self.output.insertPlainText(str(version)+str("\n"))
                #print('Joomla version:', version)
            else:
                self.output.insertPlainText(str('WordPress and Joomla versions not found')+str("\n"))
                #print('WordPress and Joomla versions not found')
        
    def hdr(self):
        Header=self.Input.text()
        self.output.insertPlainText("\n <---Header details--->\n")
        # Fetch the contents of the readme.html file
        response = requests.get("https://"+str(Header))
        for header in response.headers:
            self.output.insertPlainText(header + ': ' + response.headers[header]+str("\n"))
           # print(header + ': ' + response.headers[header])
        
    def DomainInfo(self):
        Dminput=self.Input.text()
        self.output.insertPlainText("\n <---Domain Versoin details--->\n")
        domain ="https://"+str(Dminput) 
        website_url =domain
        tld_info = tldextract.extract(website_url)
        domain = tld_info.subdomain + '.' + tld_info.domain + '.' + tld_info.suffix
        countries = {
            "us": "United States",
            "ca": "Canada",
            "uk": "United Kingdom",
            "in": "India",
            "pk": "Pakistan",
            "au": "Australia",
            "br": "Brazil",
            "cn": "China",
            "de": "Germany",
            "fr": "France",
            "it": "Italy",
            "jp": "Japan",
            "kr": "South Korea",
            "mx": "Mexico",
            "ng": "Nigeria",
            "ru": "Russia",
            "za": "South Africa",
            "eg": "Egypt",
            "ng": "Nigeria",
            "sa": "Saudi Arabia",
            "ae": "United Arab Emirates",
            "qa": "Qatar",
            "se": "Sweden",
            "es": "Spain",
            "ch": "Switzerland",
            "th": "Thailand",
            "vn": "Vietnam",
            "id": "Indonesia",
            "ph": "Philippines",
            "my": "Malaysia",
            "ar": "Argentina",
            "cl": "Chile",
            "co": "Colombia",
            "pe": "Peru",
            "ve": "Venezuela",
            "at": "Austria",
            "be": "Belgium",
            "dk": "Denmark",
            "fi": "Finland",
            "gr": "Greece",
            "ie": "Ireland",
            "il": "Israel",
            "nl": "Netherlands",
            "no": "Norway",
            "pl": "Poland",
            "pt": "Portugal",
            "ro": "Romania",
            "rs": "Serbia",
            "sg": "Singapore",
            "sk": "Slovakia",
            "si": "Slovenia",
            "tr": "Turkey",
            "my": "Malaysia",
            "ng": "Nigeria",
            "ph": "Philippines",
            "ae": "United Arab Emirates",
            "dk": "Denmark",
            "edu": "United States",
        }
        
        country_code = tld_info.suffix.split('.')[-1]
        if country_code in countries:
            country_name = countries[country_code]
            self.output.insertPlainText(str("Country:"+country_name)+"\n")
        else:
            self.output.insertPlainText(str("Country not found")+"\n")
           

        w = whois.whois(domain)
        self.output.insertPlainText("Domain name: "+domain+str("\n"))
        self.output.insertPlainText("Domain Registrar: "+str(w.registrar)+str("\n"))
        self.output.insertPlainText("Registration Date: "+str(w.creation_date)+str("\n"))
        self.output.insertPlainText("Expiration Date: "+str(w.expiration_date)+str("\n"))
        self.output.insertPlainText("Last Updated Date: "+str(w.updated_date)+str("\n"))
        self.output.insertPlainText("Domain Name Servers: "+str(w.name_servers)+str("\n"))
        self.output.insertPlainText("Status: "+str(w.status)+str("\n"))
        self.output.insertPlainText("Registrant Email: "+str(w.email)+str("\n"))
        self.output.insertPlainText("Registrant Organization: "+str(w.org)+str("\n"))
        self.output.insertPlainText("Registrant Address: "+str(w.address)+str("\n"))
        self.output.insertPlainText("Registrant City: "+str(w.city)+str("\n"))
        self.output.insertPlainText("Registrant State/Province: "+str(w.state)+str("\n"))
        self.output.insertPlainText("Registrant Postal Code: "+str(w.zipcode)+str("\n"))
        self.output.insertPlainText("Registrant Country: "+str(w.country)+str("\n"))
        self.output.insertPlainText("Admin Name: "+str(w.admin_name)+str("\n"))
        self.output.insertPlainText("Admin Email:"+str(w.admin_email)+str("\n"))
        self.output.insertPlainText("Admin Organization:"+str(w.admin_org)+str("\n"))
        self.output.insertPlainText("Tech Name: "+str(w.tech_name)+str("\n"))
        self.output.insertPlainText("Tech Email: "+str(w.tech_email)+str("\n"))
        self.output.insertPlainText("Tech Organization: "+str(w.tech_org)+str("\n"))
      

    def src(self):
        sourcecode=self.Input.text()
        self.output.insertPlainText("\n <---sourcecode details--->\n")
        with urlopen("https://"+str(sourcecode)) as response:
             self.output.insertPlainText(str(response.readlines()))
             self.output.insertPlainText("\n")
             
    def Commnets(self):
        url=self.Input.text()
        self.output.insertPlainText("\n <---comments details--->\n")
        response = requests.get("https://"+str(url))
        soup = BeautifulSoup(response.text, "html.parser")
        
        comments = []
        for comment in soup.find_all("div", class_="comment-content"):
            comment_member = comment.find("cite", class_="fn")
            if comment_member is not None:
                comment_member = comment_member.text
            comment_text = comment.find("p").text
            replies = []
            for reply in comment.find_all_next("div", class_="comment-reply"):
                reply_member = reply.find("cite", class_="fn")
                if reply_member is not None:
                    reply_member = reply_member.text
                reply_text = reply.find("p")
                if reply_text is not None:
                    replies.append((reply_member, reply_text.text))
            comments.append((comment_member, comment_text, replies))
        
        if comments:
            for comment in comments:
                self.output.insertPlainText(str("Member: "+str(comment[0])))
                self.output.insertPlainText("\n")
                self.output.insertPlainText(str("Commets: "+str(comment[1])))
                self.output.insertPlainText("\n")
                #print("Member:", comment[0])
                #print("Comment:", comment[1])
                for reply in comment[2]:
                    if reply[0] is not None:
                        self.output.insertPlainText(str("Reply from"+ reply[0] )+str( ":"+reply[1])+str("\n"))
                        #print("Reply from", reply[0] + ":", reply[1])
                    else:
                        self.output.insertPlainText("Reply:"+reply[1]+str("\n"))
                        #print("Reply:", reply[1])
                #print()
                self.output.insertPlainText("\n")
        else:
            self.output.insertPlainText("No comments found."+str("\n"))
           #print("No comments found.")
    def fire(self):
          url=self.Input.text()
          self.output.insertPlainText("\n <---Firewall details--->\n")
          # Fetch the contents of the readme.html file
          response = requests.get("https://"+str(url))
          if 'Server' in response.headers:
              
              self.output.insertPlainText("Firewall detected."+str("\n"))
              self.output.insertPlainText((f'The website is using the [{response.headers["Server"]}] firewall'))
             # print(f'The website is using the [{response.headers["Server"]}] firewall')
          else:
            self.output.insertPlainText('The website is not using a known firewall'+str("\n"))
    def AdminPage(self): 
            url=self.Input.text()
            response = requests.get("https://"+str(url))
            self.output.insertPlainText("\n <---AdaminPages details--->\n")
            soup = BeautifulSoup(response.text, "html.parser")
            admin_patterns = ["admin", "login", "dashboard", "wp-admin", "admin.php", "administrator"]
            #response = requests.get(url)
            if response.status_code == 200:
                for pattern in admin_patterns:
                    if pattern in response.text:
                        self.output.insertPlainText(str(f"https://{url}/{pattern}")+"\n")
            html_content = response.content
            soup = BeautifulSoup(html_content, 'html.parser')
            links = soup.find_all('a')
            admin_keywords = ['admin', 'login', 'wp-login.php', 'dashboard', 'wp-admin', 'administrator']
            admin_links = []
            for link in links:
              for keyword in admin_keywords:
                 if keyword in link.get('href', ''):
                    admin_links.append(link.get('href'))
            for admin_link in admin_links:
                
                self.output.insertPlainText(str(admin_link)+"\n")
    def keywords(self):
        url=self.Input.text()
        self.output.insertPlainText("\n <---Keywords details--->\n")
        response = requests.get("https://"+str(url))
        soup = BeautifulSoup(response.content, "html.parser")
        text = soup.get_text()  
        
        text = re.sub(r'[^\w\s]', '', text.lower())
        
        stop_words = ["a", "an", "the", "in", "on", "at", "to", "from", "of", "for", "with", "by", "about", "as", "is", "was", "were", "be", "been", "that", "this", "these", "those", "has", "have", "had", "but", "and", "or", "not", "may", "can", "will", "shall", "must", "could", "would", "should"]
        words = text.split()
        keywords = [word for word in words if word not in stop_words]
        
        # count frequency of each keyword
        frequency = {}
        for word in keywords:
            if word in frequency:
                frequency[word] += 1
            else:
                frequency[word] = 1
        
        keywords = sorted(frequency, key=frequency.get, reverse=True)
        
        # print all keywords
        for keyword in keywords:
            self.output.insertPlainText(str(keyword)+"\n")
           
    def pagslinks(self):
        url=self.Input.text()
        self.output.insertPlainText("\n <---Pagelinks details--->\n")
        response = requests.get("https://"+str(url))
        #soup = BeautifulSoup(response.content, "html.parser")
        soup = BeautifulSoup(response.content, "lxml")
        domain = tldextract.extract(url).domain
       # response = requests.get(url)
        self.output.insertPlainText("domain name:"+str(domain)+"\n")
        
        soup = BeautifulSoup(response.content, 'html.parser')
        
        text = soup.get_text()
        
        text = text.strip()
        text = text.translate(str.maketrans("", "", string.punctuation))
        
        num_chars = len(text)
        num_symbols = sum([not char.isalnum() and not char.isspace() for char in text])
        num_upper = sum([char.isupper() for char in text])
        num_lower = sum([char.islower() for char in text])
        num_digits = sum([char.isdigit() for char in text])
        num_whitespace = sum([char.isspace() for char in text])
        
        self.output.insertPlainText("Number of characters:"+str(num_chars)+"\n")
        self.output.insertPlainText("Number of symbols:"+str(num_symbols)+"\n")
        self.output.insertPlainText("Number of uppercase letters:"+str(num_upper)+"\n")
        self.output.insertPlainText("Number of lowercase letters:"+str(num_lower)+"\n")
        self.output.insertPlainText("Number of digits:"+str(num_digits)+"\n")
        self.output.insertPlainText("Number of whitespace characters:"+str(num_whitespace)+"\n")
        pages = []
        for tag in soup.find_all("a"):
            try:
                page = tag.get("href")
                if not page.startswith("http"):
                    page = url + page
                pages.append(page)
            except AttributeError as e:
                print(e)
        
        pages.sort()
        
        self.output.insertPlainText(str("\nAll pages found on the website in alphabetical order:")+"\n")
        for page in pages:
            self.output.insertPlainText(str(page)+"\n")
            #print(page)
        
       # print("\nTotal Pages found: "+str(len(pages))+ " of "+str(url)+"website"+"\n")
        self.output.insertPlainText(str("\nTotal Pages found: "+str(len(pages))+ " of "+str(url)+"website"+"\n"))
        self.output.insertPlainText("\n\nBacklinks\n\n")
        links = []
        for link in soup.find_all('a'):
            link_url = link.get('href')
            if link_url and 'http' in link_url:
                links.append(link_url)
        
        # Extract external links (links to other websites)
        external_links = []
        for link in links:
            if url not in link:
                external_links.append(link)
        for link in external_links:
            self.output.insertPlainText(str(link)+"\n")

    def medialinks(self):
        url=self.Input.text()
        self.output.insertPlainText("\n <---Social Media Links details--->\n")
        response = requests.get("https://"+str(url))
        soup = BeautifulSoup(response.content, "lxml")
        
        keywords = ["youtube.com", "twitter.com", "instagram.com","facebook.com","LinkedIn.com","TikTok.com",
            "Whatsapp.com","indeed.com","pinterest.com","Snapchat.com",'geo.tv']
        for link in soup.find_all('a'):
                href = link.get('href')
                if href is not None and any(keyword in href for keyword in keywords):
                    self.output.insertPlainText(str(href)+"\n")
                    #print(href)
    def scripts(self):
        url=self.Input.text()
        self.output.insertPlainText("\n <---Scripts details--->\n")
        
        response = requests.get("https://"+str(url))
        soup = BeautifulSoup(response.content, "html.parser")
        scripts = soup.find_all('script')
        
        for script in scripts:
            if 'src' in script.attrs:
                self.output.insertPlainText(str(script['src'])+"\n")
    def location(self):
        url=self.Input.text()
        self.output.insertPlainText("\n <---Geolocation details--->\n")
        geolocator = Nominatim(user_agent="my-app")
        try:
            location = geolocator.geocode("https://"+str(url))
            if location is not None:
                self.output.insertPlainText(str("Location: ", location.address)+"\n")
                self.output.insertPlainText(str("Latitude: ", location.latitude)+"\n")
                self.output.insertPlainText(str("Longitude: ", location.longitude)+"\n")
                if 'address' in location.raw:
                    self.output.insertPlainText(str("Country: ", location.raw['address'].get('country'))+"\n")
                    self.output.insertPlainText(str("State: ", location.raw['address'].get('state'))+"\n")
                  
                    self.output.insertPlainText(str("City: ", location.raw['address'].get('city'))+"\n")
                else:
                    self.output.insertPlainText(str("No address information found for this location")+"\n")
            else:
                self.output.insertPlainText(str("Geolocation not found")+"\n")
        except Exception as e:
            
            self.output.insertPlainText(str("Error occurred: ")+str(e)+"\n")
    def loginforms(self):
        url=self.Input.text()
        self.output.insertPlainText("\n <---LoginForms details--->\n")
        
        response = requests.get("https://"+str(url)+str("/login"))
        
        html_content = response.content
        soup = BeautifulSoup(html_content, 'html.parser')

        forms = soup.find_all('form')
        self.output.insertPlainText(str(f"Found {len(forms)} forms on {url}:")+"\n")
        for form in forms:
            self.output.insertPlainText(str(f"Form {forms.index(form) + 1} attributes:")+"\n")
            self.output.insertPlainText(str(f"Method: {form.get('method')}")+"\n")
            self.output.insertPlainText(str(f"Action: {form.get('action')}")+"\n")
            self.output.insertPlainText(str(f"Inputs: {[input.get('name') for input in form.find_all('input')]}\n")+"\n")
    
    
    
    def domains(self):
       # url = "https://www.ulm.edu.pk/"
        url=self.Input.text()
        self.output.insertPlainText("\n <---Domains Info details--->\n")
      
        try:
            req =  requests.get("https://"+str(url))
            req.raise_for_status() # check for HTTP errors
        except requests.exceptions.HTTPError as e:
            self.output.insertPlainText(str(f"HTTP error occurred: {e}")+"\n")
            exit()
        except requests.exceptions.RequestException as e:
            self.output.insertPlainText(str(f"An error occurred: {e}")+"\n")
            
            exit()
        
        soup = BeautifulSoup(req.content, 'html.parser')
        main_domains = set()
        sub_domains = set()
        hidden_domains = set()
        
        # Find links in visible elements
        for link in soup.find_all('a'):
            href = link.get('href')
            if href is not None:
                parsed_url = urlparse(href)
                domain = parsed_url.netloc.strip() if parsed_url.netloc else urlparse(url).netloc
                if domain:
                    if domain.endswith("."+urlparse(url).netloc):
                        main_domains.add(domain)
                    else:
                        sub_domains.add(domain)
        
        # Find links in hidden elements
        hidden_links = soup.find_all(lambda tag: tag.has_attr('href') and tag.get('style') == 'display:none;')
        for link in hidden_links:
            href = link.get('href')
            if href is not None:
                parsed_url = urlparse(href)
                domain = parsed_url.netloc.strip() if parsed_url.netloc else urlparse(url).netloc
                if domain:
                    hidden_domains.add(domain)
        
        # Find links in comments
        comments = soup.find_all(string=lambda text: isinstance(text, Comment))
        for comment in comments:
            urls = re.findall(r'(https?://\S+)', comment)
            for url in urls:
                parsed_url = urlparse(url)
                domain = parsed_url.netloc.strip() if parsed_url.netloc else urlparse(url).netloc
                if domain:
                    hidden_domains.add(domain)
        
        num_domains = len(main_domains) + len(sub_domains) + len(hidden_domains)
        self.output.insertPlainText(str(f"Total number of domains found: {num_domains}")+"\n")
        
        self.output.insertPlainText(str(f"Main domains \t({len(main_domains)}):")+"\n\n")
        
        for domain in main_domains:
            try:
                ip = socket.gethostbyname(domain)
                self.output.insertPlainText(str(f"{domain} \t({ip})")+"\n")
               
            except socket.gaierror as e:
                self.output.insertPlainText(str(f"Could not resolve {domain}: {e}")+"\n")
                
        
      
        self.output.insertPlainText(str(f"Sub domains ({len(sub_domains)}):\t Ipies")+"\n")
        for domain in sub_domains:
            try:
                ip = socket.gethostbyname(domain)
                self.output.insertPlainText(str(f"{domain} \t({ip})")+"\n")
                
            except socket.gaierror as e:
                self.output.insertPlainText(str(f"Could not resolve {domain}: {e}")+"\n")
                
        
        
        self.output.insertPlainText(str(f"Hidden domains ({len(hidden_domains)}):")+"\n")
        for domain in hidden_domains:
            try:
                ip = socket.gethostbyname(domain)
                self.output.insertPlainText(str(f"{domain} \t({ip})")+"\n")
                
            except socket.gaierror as e:
                
                self.output.insertPlainText(str(f"Could not resolve {domain}: {e}")+"\n")
   
    def Emails(self):
        url=self.Input.text()
        self.output.insertPlainText("\n <---Emails details--->\n")
        try:
            response = requests.get(str('https://')+str(url))
        except requests.exceptions.SSLError as e:
            self.output.insertPlainText(str(f"SSL Error: {e}")+"\n")
           
        else:
            html_content = response.text
        
            email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            emails = re.findall(email_pattern, html_content)
        
            for email in emails:
                self.output.insertPlainText(str(email)+"\n")
                
    def Images(self):
        self.output.insertPlainText("\n <---AllImagesDownloads details--->\n")
        ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'tiff', 'psd', 'pdf', 'eps', 'ai'}
        def folder_create(images, folder_name):
            try:
                # folder creation
                os.mkdir(folder_name)
        
            except:
                
                self.output.insertPlainText(str("Folder Exist with that name!")+"\n")
                folder_create(images, folder_name)
        
            download_images(images, folder_name)
        
        def download_images(images, folder_name):
            count = 0
            image_urls = []
            
            self.output.insertPlainText(str(f"Total {len(images)} Image Found!")+"\n")
            if len(images) != 0:
                for i, image in enumerate(images):
                    try:
                        image_link = image["data-srcset"]
                    except:
                        try:
                            image_link = image["data-src"]
                        except:
                            try:
                                image_link = image["data-fallback-src"]
                            except:
                                try:
                                    image_link = image["src"]
                                except:
                                    pass
        
                    try:
                        r = requests.get(image_link).content
                        file_extension = image_link.split('.')[-1]
                        if file_extension in ALLOWED_EXTENSIONS:
                            with open(f"{folder_name}/images{i+1}.{file_extension}", "wb+") as f:
                                f.write(r)
                            count += 1
                            image_urls.append(image_link)
                    except:
                        pass
        
                if count == len(images):
                    
                    self.output.insertPlainText(str(("All Images Downloaded!"))+"\n")
                else:
                    
                    self.output.insertPlainText(str((f"Total {count} Images Downloaded Out of {len(images)}"))+"\n")
        
            
            self.output.insertPlainText(str(("List of image URLs:"))+"\n")
            for url in image_urls:
                self.output.insertPlainText(str(url)+"\n")
                
        
        def main():
            url=self.Input.text()            
            response = requests.get("https://"+str(url))
            soup = BeautifulSoup(response.content, "html.parser")
            images = soup.findAll('img')
            folder_create(images, os.path.basename(url))
        
        if __name__ == '__main__':
            main()
            
            
    def MetaData(self):
        url=self.Input.text()
        self.output.insertPlainText("\n <---MetaData Info About Website Details--->\n")
        try:
            parser = metadata_parser.MetadataParser(url="https://"+str(url), search_head_only=True)
        
            # get all the metadata properties and sort them alphabetically
            properties = sorted(parser.metadata.items())
    
            self.output.insertPlainText(str("Metadata properties:")+"\n")

            self.output.insertPlainText(str(("--------------------"))+"\n")
            for property, value in properties:
               
                self.output.insertPlainText(str((f"{property}: {value}"))+"\n")

                self.output.insertPlainText(str("--------------------")+"\n")

        
        except Exception as e:
            self.output.insertPlainText(str(f"An error occurred: {e}")+"\n")
    def googledrivlink(self):
        self.output.insertPlainText("\n <---Google Drive links Details--->\n")
        def find_google_drive_links(url):
            try:
                response = requests.get(url)
                soup = BeautifulSoup(response.text, 'html.parser')
                links = soup.find_all('a')
        
                found_links = False
        
                for link in links:
                    href = link.get('href')
                    if href and 'drive.google.com' in href:
                        found_links = True
                        link_text = link.get_text().strip()
                        if link_text:
                            self.output.insertPlainText(str(f"Link Text: {link_text}")+"\n")
                            print(f"Link Text: {link_text}")
                            self.output.insertPlainText(str(f"Link URL: {href}")+"\n")
                            print(f"Link URL: {href}")
                            self.output.insertPlainText("\n")
                           
        
                if not found_links:
                    self.output.insertPlainText(str("No links to Google Drive files found.")+"\n")
                    print("No links to Google Drive files found.")
        
                # Recursively scan child pages
                for link in links:
                    href = link.get('href')
                    if href and not re.match(r"(?i)javascript:", href) and "#" not in href and "?" not in href:
                        if href.endswith('/'):
                            href = href[:-1]
                        if not href.startswith('http'):
                            href = url + href
        
                        find_google_drive_links(href)
        
            except requests.exceptions.RequestException as e:
                self.output.insertPlainText(str(f"Error: {e}")+"\n")
                print(f"Error: {e}")
                
                return None
        
        
       # url = 'https://usindh.edu.pk/'
        url=self.Input.text()
        find_google_drive_links("https://"+str(url))
     
    def Files(self):
            self.output.insertPlainText("\n <---Files Details--->\n")
            url=self.Input.text()           
            visited_urls = set()
            def crawl(url):
                visited_urls.add(url)
                try:
                    response = requests.get("https://"+str(url))
                    response.raise_for_status()  # raise an exception if an HTTP error occurred
                except requests.exceptions.HTTPError as e:
                    self.output.insertPlainText(str((f"An HTTP error occurred while accessing {url}: {e}"))+"n")
                    
                    return
            
                tree = html.fromstring(response.content)
            
                file_types = ['.pdf', '.png', '.jpg', '.txt', '.zip', '.xps', '.xltm', '.mp3', '.mp4', '.docx', '.xlsx', '.vsdx', '.pptx', '.ppsx', '.dotx', '.doc', '.docm', '.html', '.xml', '.csv', '.gif', '.pot', '.ppt', '.potx', '.xps']
            
                for link in tree.xpath('//a'):
                    href = link.get('href')
                    if href is not None:
                        if any(file_type in href for file_type in file_types):
                            self.output.insertPlainText(str(href)+"\n")
                           
                        if href.startswith(url) and href not in visited_urls:
                            try:
                                crawl(href)
                            except requests.exceptions.HTTPError as e:
                                self.output.insertPlainText(str((f"An HTTP error occurred while accessing {href}: {e}"))+"n")
                                continue
            crawl(url)
    def Cookies(self):
        self.output.insertPlainText("\n <---Cookies Details--->\n")
        url=self.Input.text()           
        response = requests.get("https://"+str(url))
        cookies = response.cookies
        self.output.insertPlainText(str(cookies)+"n")


    def CMS(self):
       try:
            self.output.insertPlainText("\n <---CMS Details--->\n")
            url=self.Input.text()           
            response = requests.get("https://"+str(url))
            soup = BeautifulSoup(response.text, 'html.parser')
            
            if 'WordPress' in response.text:
                version = soup.find('meta', attrs={'name': 'generator'})
                if version:
                    self.output.insertPlainText("This website is using WordPress " + version['content'] + "\n")
                else:
                    self.output.insertPlainText("This website is using WordPress\n")
                    
            elif 'Joomla' in response.text:
                version = soup.find('meta', attrs={'name': 'generator'})
                if version:
                    self.output.insertPlainText("This website is using Joomla " + version['content'] + "\n")
                else:
                    self.output.insertPlainText("This website is using Joomla\n")
                    
            elif 'Drupal' in response.text:
                version = soup.find('meta', attrs={'name': 'generator'})
                if version:
                    self.output.insertPlainText("This website is using Drupal " + version['content'].split(' ')[1] + "\n")
                else:
                    self.output.insertPlainText("This website is using Drupal\n")
                    
            elif 'Magento' in response.text:
                version = soup.find('meta', attrs={'name': 'generator'})
                if version:
                    self.output.insertPlainText("This website is using Magento " + version['content'] + "\n")
                else:
                    self.output.insertPlainText("This website is using Magento\n")
                    
            elif 'Shopify' in response.text:
                self.output.insertPlainText("This website is using Shopify\n")
                
            elif 'Wix' in response.text:
                self.output.insertPlainText("This website is using Wix\n")
                
            elif 'Squarespace' in response.text:
                version = soup.find('meta', attrs={'name': 'generator'})
                if version:
                    self.output.insertPlainText("This website is using Squarespace " + version['content'] + "\n")
                else:
                    self.output.insertPlainText("This website is using Squarespace\n")
                    
            elif 'Ghost' in response.text:
                version = soup.find('meta', attrs={'name': 'generator'})
                if version:
                    self.output.insertPlainText("This website is using Ghost " + version['content'] + "\n")
                else:
                    self.output.insertPlainText("This website is using Ghost\n")
                    
            elif 'TYPO3' in response.text:
                version = soup.find('meta', attrs={'name': 'generator'})
                if version:
                    self.output.insertPlainText("This website is using TYPO3 " + version['content'] + "\n")
                else:
                    self.output.insertPlainText("This website is using TYPO3\n")
                    
            elif 'Umbraco' in response.text:
                self.output.insertPlainText("This website is using Umbraco\n")
                
            elif 'Concrete5' in response.text:
                version = soup.find('meta', attrs={'name': 'generator'})
                if version:
                    self.output.insertPlainText("This website is using Concrete5 " + version['content'] + "\n")
                else:
                    self.output.insertPlainText("This website is using Concrete5\n")
                    
            else:
                self.output.insertPlainText("The CMS of this website is not known.\n") 
       except requests.exceptions.RequestException:
               self.output.insertPlainText("Connection Error: Could not establish a connection to the website.\n")
   
    def DomainFinder(self):
        self.output.insertPlainText("\n <---DomainFinder--->\n")
        def is_available(domain):
            try:
                w = whois.whois(domain)
                return not w.status
            except Exception:
                return False
        def find_available_domains(keyword):
            domains = []
            tlds = ['.com', '.net', '.org', '.io', '.co', '.ai', '.app', '.blog', '.design'] 
            for tld in tlds:
                domain = keyword + tld
                if is_available(domain):
                    domains.append(domain)
            return domains
        url=self.Input.text()           
        keyword =str("https://"+url)
        available_domains = find_available_domains(keyword)
        self.output.insertPlainText(str(available_domains)+"\n")
    def TagsFinder(self):
        self.output.insertPlainText("\n <---Tags Details--->\n")
        url=self.Input.text()
        if not url.startswith('http'):
            url = 'https://' + url
        domain_name = tldextract.extract(url).registered_domain

        response = requests.get(url)
        html = response.text

        soup = BeautifulSoup(html, 'html.parser')

        tag_counts = {}
        for tag in soup.find_all():
            tag_name = tag.name
            if tag_name in tag_counts:
                tag_counts[tag_name] += 1
            else:
                tag_counts[tag_name] = 1

        total_tags = sum(tag_counts.values())

        
        self.output.insertPlainText(str(f"Tag counts for {url} ({domain_name})\n")+"\n")
        for tag_name, count in tag_counts.items():
            self.output.insertPlainText(str(f"{tag_name}: {count}")+"\n")
            
        self.output.insertPlainText(str(f"\nTotal tags: {total_tags}")+"\n")

    def Personnames(self):
        self.output.insertPlainText("\n <---Personname finder--->\n")
        url=self.Input.text()

        # Send a GET request to the website and get its HTML content
        response = requests.get(str("https://")+url)
        html_content = response.content

        # Parse the HTML content using BeautifulSoup
        soup = BeautifulSoup(html_content, "html.parser")

        # Extract all the text content from the website
        text = soup.get_text()

        # Define a regular expression pattern to match person names
        pattern = r"([A-Z][a-z]+)\s+([A-Z][a-z]+)"

        # Find all occurrences of the pattern in the text
        matches = re.findall(pattern, text)

        # Extract the person names from the matches
        person_names = [" ".join(match) for match in matches]

        # Print the person names in new lines
        for name in person_names:
           
            self.output.insertPlainText(str(name)+"\n")
            
    def Programming(self):
        self.output.insertPlainText("\n <---Languages Detector finder--->\n")
        url=self.Input.text()

        response = requests.get(str("https://")+url)
        # Define the website URL to analyze
        # url = "https://www.uetpeshawar.edu.pk/"

        # # Make a request to the website and store the response
        # response = requests.get(url)

        # Parse the HTML of the website using BeautifulSoup
        soup = BeautifulSoup(response.content, "html.parser")

        # Check if PHP is used on the website
        if "php" in str(response.headers.get("X-Powered-By")).lower():
            self.output.insertPlainText(str("Server-side Programming Language: PHP")+"\n")
          
        else:
            self.output.insertPlainText(str("Server-side Programming Language: Not detected")+"\n")
            

        # Check if JavaScript is used on the website
        if soup.find_all("script"):
            self.output.insertPlainText(str("Client-side Programming Language: JavaScript")+"\n")
            
        else:
            self.output.insertPlainText(str("Client-side Programming Language: Not detected")+"\n")

        # Check if jQuery is used on the website
        if soup.find_all("script", src=lambda src: src and "jquery" in src):
            self.output.insertPlainText(str("JavaScript Library: jQuery")+"\n")
            
        else:
            self.output.insertPlainText(str("JavaScript Library: Not detected")+"\n")
        # Check if Bootstrap is used on the website
        if soup.find_all("link", href=lambda href: href and "bootstrap" in href) or soup.find_all("script", src=lambda src: src and "bootstrap" in src):
            self.output.insertPlainText(str("CSS and JavaScript Framework: Bootstrap")+"\n")
           
        else:
            self.output.insertPlainText(str("CSS and JavaScript Framework: Not detected")+"\n")

        # Check if Underscore is used on the website
        if soup.find_all("script", src=lambda src: src and "underscore" in src):
            self.output.insertPlainText(str("JavaScript Library: Underscore")+"\n")
            
        else:
            self.output.insertPlainText(str("JavaScript Library: Not detected")+"\n")

        if soup.find_all("script", src=lambda src: src and "backbone" in src):
            self.output.insertPlainText(str("JavaScript Library: Backbone")+"\n")
           
        else:
            self.output.insertPlainText(str("JavaScript Library: Not detected")+"\n")
        # Check if Ruby is used on the website
        if soup.find_all("meta", attrs={"name": "ruby"}):
            self.output.insertPlainText(str("Server-side Programming Language: Ruby")+"\n")
        else:
            
            self.output.insertPlainText(str("Server-side Programming Language: Not detected")+"\n")

        # Check if Java is used on the website
        if soup.find_all("meta", attrs={"name": "java"}):
            self.output.insertPlainText(str("Server-side Programming Language: Java")+"\n")
            
        else:
            self.output.insertPlainText(str("Server-side Programming Language: Not detected")+"\n")
         
        # Check if Python is used on the website
        if soup.find_all("meta", attrs={"name": "python"}):
            self.output.insertPlainText(str("Server-side Programming Language: Python")+"\n")
            
        else:
            self.output.insertPlainText(str("Server-side Programming Language: Not detected")+"\n")
           

        # Check if C is used on the website
        if soup.find_all("meta", attrs={"name": "c"}):
            self.output.insertPlainText(str("Server-side Programming Language: C")+"\n")
        else:
            self.output.insertPlainText(str("Server-side Programming Language: Not detected")+"\n")

        if soup.find_all("meta", attrs={"name": "cpp"}):
            self.output.insertPlainText(str("Server-side Programming Language: C++")+"\n")
            
        else:
            self.output.insertPlainText(str("Server-side Programming Language: Not detected")+"\n")
            

        # Check if C# is used on the website
        if soup.find_all("meta", attrs={"name": "csharp"}):
            self.output.insertPlainText(str("Server-side Programming Language: C#")+"\n")
        else:
            self.output.insertPlainText(str("Server-side Programming Language: Not detected")+"\n")

        # Check if HTML4 is used on the website
        if soup.find_all("meta", attrs={"http-equiv": "Content-Type", "content": "text/html; charset=ISO-8859-1"}):
            self.output.insertPlainText(str("Markup Language: HTML4")+"\n")
            
        else:
            self.output.insertPlainText(str("Markup Language: Not detected")+"\n")
        if soup.find_all("meta", attrs={"charset": "utf-8"}) or soup.find_all("meta", attrs={"name": "viewport"}):
            self.output.insertPlainText(str("Markup Language: HTML5")+"\n")
            
        else:
            self.output.insertPlainText(str("Markup Language: Not detected")+"\n")
            

        # Check if CSS is used on the website
        if soup.find_all("link", attrs={"rel": "stylesheet"}):
            self.output.insertPlainText(str("Stylesheet Language: CSS")+"\n")
            
        else:
            self.output.insertPlainText(str("Stylesheet Language: Not detected")+"\n")
        
    def ShortLinker(self):
        self.output.insertPlainText("\n <---Shortlink Details--->\n")
        url=self.Input.text()

        shortener = pyshorteners.Shortener()

        # Shorten a URL using TinyURL
        short_url = shortener.tinyurl.short('https://'+str(url))
        self.output.insertPlainText("Shortlink:"+str(short_url)+"\n")
        
    def WebTech(self):
        self.output.insertPlainText("\n <---Web technologies Details--->\n")
        url=self.Input.text()
        response = requests.get("https://"+str(url))
        soup = BeautifulSoup(response.content, 'html.parser')
        libraries = {
            'Isotope': 'JavaScript libraries',
            'Yoast SEO': 'SEO',
            'jQuery Migrate': 'JavaScript libraries',
            'Backbone.js': 'JavaScript frameworks',
            'Popup Maker': 'WordPress plugins',
            'Lodash': 'JavaScript libraries',
            'WordPress': 'CMS',
            'MySQL': 'Databases',
            'Twitter Emoji': 'Font scripts',
            'Highlight.js': 'JavaScript libraries',
            'Google Font API': 'Font scripts',
            'LiteSpeed': 'Web servers',
            'jQuery': 'JavaScript libraries',
            'OWL Carousel': 'JavaScript libraries',
            'Open Graph': 'Miscellaneous',
            'Underscore.js': 'JavaScript libraries',
            'MediaElement.js': 'Video players',
            'RSS': 'Miscellaneous',
            'PHP': 'Programming languages',
            'core-js': 'JavaScript libraries',
            'HTTP/3': 'Miscellaneous',
            'Bootstrap': 'UI frameworks',
            'Clipboard.js': 'JavaScript libraries',
            'prettyPhoto': 'JavaScript libraries',
            'jQuery UI': 'JavaScript libraries'
        }

        found = False

        for library, category in libraries.items():
            if soup.find('script', src=lambda x: x and library.lower() in x.lower()) and library.lower() != 'jquery':
                self.output.insertPlainText(str(f"Name: {library} - {category}")+"\n")

                
                found = True
            elif soup.find('link', href=lambda x: x and library.lower() in x.lower()) and library.lower() != 'jquery':
                
                self.output.insertPlainText(str(f"Name: {library} - {category}")+"\n")
                found = True

        if not found:
            
            self.output.insertPlainText(str("No technologies found.")+"\n")
        else:
            
            self.output.insertPlainText(str("At least one technology found.")+"\n")
    
    def PortScanner(self):
        self.output.insertPlainText("\n <---PortScanning Details--->\n")
        ip=self.Input.text()
        nmScan = nmap.PortScanner()
       # ip=input("Get here domain Ip:? ")

        DI=socket.gethostbyname(str(ip))
        portN=self.portnum.text()
        nmScan.scan(DI,'21-'+str(portN))


        start_time = time.time()

        for host in nmScan.all_hosts():
              self.output.insertPlainText(str('Host : %s (%s)' % (host, nmScan[host].hostname()))+"\n")
              self.output.insertPlainText(str('State : %s' % nmScan[host].state())+"\n")
              for proto in nmScan[host].all_protocols():
                  
                  self.output.insertPlainText(str('----------')+"\n")
                  
                  self.output.insertPlainText(str("Nmap scan report for "+str(ip)+" "+str(DI))+"\n")
                  
                  self.output.insertPlainText(str("PORT   \t  STATE    \tSERVICE")+"\n")
                  
                  lport = nmScan[host][proto].keys()
                  sorted(lport)
                  for port in lport:
                      s=nmScan[host].all_protocols()
                      t=str(''.join(s))
                      try:
                          
                          service=socket.getservbyport(port)
                          
                          self.output.insertPlainText(str( ((str(port)+str("/"+t)+str("\t   "+nmScan[host][proto][port]['state']+str("\t"+service)))))+"\n")
                          thread.start()
                      except:
                         
                         continue
                     
                  end_time = time.time()
                
        self.output.insertPlainText(str("To all scan all ports it took {} seconds".format(end_time-start_time))+"\n")
    def SourceCode(self):
        self.output.insertPlainText("\n <---SourceCode Details--->\n")
        url=self.Input.text()
        
       # url = "https://www.kkkuk.edu.pk"
        self.output.insertPlainText("\n<-------------------------HTML-SourceCode------------------------------------------>\n")
        response = requests.get(str("https://")+url)
        soup = BeautifulSoup(response.text, 'html5lib')
        beautified_html = soup.prettify()
        self.output.insertPlainText(str(beautified_html)+"\n")
        
        self.output.insertPlainText("\n<-------------------------CSS-SourceCode------------------------------------------->\n")
        pattern = re.compile(r"<style.*?>\s*(.*?)\s*</style>", re.DOTALL)
        matches = pattern.findall(response.text)
        for match in matches:
            beautified_css = cssbeautifier.beautify(match.strip())
            self.output.insertPlainText(str((beautified_css))+"\n")
        
        self.output.insertPlainText("\n<-------------------------JavaScript-SourceCode----------------------------------------------------------->\n")
        pattern = re.compile(r"<script.*?>\s*(.*?)\s*</script>", re.DOTALL)
        matches = pattern.findall(response.text)
        for match in matches:
            beautified_js = jsbeautifier.beautify(match.strip())
            self.output.insertPlainText(str(beautified_js)+"\n")
        self.output.insertPlainText("\n<-------------------------jQuery------------------------------------------->\n")
        jquery_pattern = re.compile(r'\$\((\'.*?\'|".*?")\)', re.DOTALL)
        jquery_matches = jquery_pattern.findall(response.text)
        if jquery_matches:
            for match in jquery_matches:
               
                    self.output.insertPlainText(str(match)+"\n")
         
        else:
           self.output.insertPlainText(str("No jQuery matches found that contain the string 'popup'")+"\n")
                    
        self.output.insertPlainText("\n<-------------------------BootStarp------------------------------------------->\n")
        bootstrap_pattern = re.compile(r'(bootstrap-.*?\.css|bootstrap-.*?\.js)', re.DOTALL)
        bootstrap_matches = bootstrap_pattern.findall(response.text)
        if bootstrap_matches:
            for match in bootstrap_matches:
                self.output.insertPlainText(str(match)+"\n")

        else:
            self.output.insertPlainText(str("No Bootstrap matches found")+"\n")
            
        self.output.insertPlainText("\n<-------------------------PHP------------------------------------------->\n")
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'}

        response = requests.get("https://"+str(url), headers=headers)

        soup = BeautifulSoup(response.content, 'html.parser')

        patterns = [
            re.compile(r'<script language="php">.*?</script>', re.DOTALL),  # script tags with PHP language
            re.compile(r'<!--.*?-->', re.DOTALL),  # PHP code in comments
            re.compile(r'<!\[CDATA\[.*?\]\]>', re.DOTALL),  # PHP code in CDATA sections
            re.compile(r'<pre.*?>\s*(<\?php.*?\?>)\s*</pre>', re.DOTALL),  # PHP code in a <pre> tag
            re.compile(r'<textarea.*?>\s*(<\?php.*?\?>)\s*</textarea>', re.DOTALL),  # PHP code in a <textarea> tag
            re.compile(r'<xmp.*?>\s*(<\?php.*?\?>)\s*</xmp>', re.DOTALL),  # PHP code in a <xmp> tag
            re.compile(r'<listing.*?>\s*(<\?php.*?\?>)\s*</listing>', re.DOTALL),  # PHP code in a <listing> tag
            re.compile(r'<plaintext.*?>\s*(<\?php.*?\?>)\s*</plaintext>', re.DOTALL),  # PHP code in a <plaintext> tag
        ]

        php_code = ''

        for pattern in patterns:
            match = pattern.search(str(soup))
            if match:
                php_code = match.group()
                break

        if php_code:
            self.output.insertPlainText(str(php_code)+"\n")
         
        else:
            self.output.insertPlainText(str('No PHP code found on the page.')+"\n")

    def lnk(self):
        pass


        if __name__ == '__main__':
      
            Crawler(urls=['https://'+str(calllinks)]).run()
            self.output.insertPlainText(run(self))
            
           
            
            

        
app = QApplication(sys.argv)
form = LoginForm()

form.show()
app.exec_()
