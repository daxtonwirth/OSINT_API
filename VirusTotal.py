import requests
import json

import API_Keys

VirusTotal_API_Key = API_Keys.VirusTotal_API_Key
AbuseIPDB_API_KEY = API_Keys.AbuseIPDB_API_KEY
ipaddress = input("Enter IP address: ") 

VirusTotal_Request = requests.get("https://www.virustotal.com/api/v3/ip_addresses/" + ipaddress, headers={'x-apikey': VirusTotal_API_Key}).json()
#print(request1)
try:
    country = VirusTotal_Request["data"]["attributes"]["country"]
    owner = VirusTotal_Request["data"]["attributes"]["as_owner"]
    regional_internet_registry = VirusTotal_Request["data"]["attributes"]["regional_internet_registry"]
    harmless = VirusTotal_Request["data"]["attributes"]["last_analysis_stats"]["harmless"]
    malicious = VirusTotal_Request["data"]["attributes"]["last_analysis_stats"]["malicious"]
    total = int(harmless) + int(malicious)
    reputation = VirusTotal_Request["data"]["attributes"]["reputation"]
    cert = VirusTotal_Request["data"]["attributes"]["last_https_certificate"]["public_key"]["issuer"]
except:
    cert = ""


#print(f"Vendor score: {malicious}/{total}")
#print(f"Commun score: {reputation}")
#print(f"Country: {country} ({regional_internet_registry})")
#print(f"Owner: {owner} ({cert})")

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


print(f"Abuse score: {abuseConfidenceScore}/100 ({isWhitelisted}) | ISP: {isp} | Country: {countryCode} | Domain: {domain}")
