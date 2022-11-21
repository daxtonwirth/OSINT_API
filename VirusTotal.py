import requests
from requests.auth import HTTPBasicAuth
import json
import base64

import API_Keys
VirusTotal_API_Key = API_Keys.VirusTotal_API_Key
AbuseIPDB_API_KEY = API_Keys.AbuseIPDB_API_KEY
XFE_API_KEY = API_Keys.IBMXForce_API_KEY
XFE_API_PASS = API_Keys.IBMXForce_API_PASS

ipaddress = input("Enter IP address: ") 

VirusTotal_Request = requests.get("https://www.virustotal.com/api/v3/ip_addresses/" + ipaddress, headers={'x-apikey': VirusTotal_API_Key}).json()
#print(VirusTotal_Request)

try: country = VirusTotal_Request["data"]["attributes"]["country"] 
except: country = ""
try: owner = VirusTotal_Request["data"]["attributes"]["as_owner"]
except: owner = "N/A"
try: regional_internet_registry = VirusTotal_Request["data"]["attributes"]["regional_internet_registry"]
except: regional_internet_registry = ""
try: harmless = VirusTotal_Request["data"]["attributes"]["last_analysis_stats"]["harmless"]
except: harmless = ""
try: malicious = VirusTotal_Request["data"]["attributes"]["last_analysis_stats"]["malicious"]
except: malicious = ""
try: total = int(harmless) + int(malicious)
except: total = harmless
try: reputation = VirusTotal_Request["data"]["attributes"]["reputation"]
except: reputation = ""
try:cert = VirusTotal_Request["data"]["attributes"]["last_https_certificate"]["public_key"]["issuer"]
except KeyError:
    cert = ""

print(f"\nOSINT on {ipaddress}:")
print(f"Vendor score: {malicious}/{total} | Commun score: {reputation} | Country: {country} ({regional_internet_registry}) | Owner: {owner}")

#exit()

url = "https://api.abuseipdb.com/api/v2/check/"
headers={'Key': AbuseIPDB_API_KEY, 'Accept': 'application/json'}
params={'ipAddress': ipaddress, 'maxAgeInDays': '90'}
AbuseIPDB_Request = requests.request(method='GET', url=url, headers=headers, params=params)
decodedResponse = json.loads(AbuseIPDB_Request.text) # print (json.dumps(decodedResponse, sort_keys=True, indent=4))

abuseConfidenceScore = decodedResponse["data"]["abuseConfidenceScore"]
countryCode = decodedResponse["data"]["countryCode"]
domain = decodedResponse["data"]["domain"]
isp = decodedResponse["data"]["isp"]
isWhitelisted = decodedResponse["data"]["isWhitelisted"]
if isWhitelisted:
    isWhitelisted = "AllowListed"
else:
    isWhitelisted = "Not AllowListed"
numDistinctUsers = decodedResponse["data"]["numDistinctUsers"]
totalReports = decodedResponse["data"]["totalReports"]


print(f"AbuseIPDB: Abuse score: {abuseConfidenceScore}/100 ({isWhitelisted}) | ISP: {isp} | Country: {countryCode} | Domain: {domain}")


# XFE_API_KEY 
# curl -X GET --header 'Accept: application/json' -u {API_KEY:API_PASSWORD} 'https://exchange.xforce.ibmcloud.com/api/ipr/10.10.10.10'
#key = (XFE_API_KEY + ":" + XFE_API_KEY).encode
#token = base64.b64encode(key)
#XFE_Request = requests.get("https://exchange.xforce.ibmcloud.com/api/ipr/" + ipaddress, headers={'Authorization': "Basic " + token,'Accept': 'application/json'}).json()
XFE_Request = requests.get("https://exchange.xforce.ibmcloud.com/api/ipr/" + ipaddress, auth=HTTPBasicAuth(XFE_API_KEY, XFE_API_PASS))
#print(XFE_Request.text)
decodedResponse = json.loads(XFE_Request.text)
score = decodedResponse["score"]
print(f"XFE: {score}/10")
