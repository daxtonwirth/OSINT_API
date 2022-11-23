import requests
from requests.auth import HTTPBasicAuth
import json

import API_Keys
VirusTotal_API_Key = API_Keys.VirusTotal_API_Key
AbuseIPDB_API_KEY = API_Keys.AbuseIPDB_API_KEY
XFE_API_KEY = API_Keys.IBMXForce_API_KEY
XFE_API_PASS = API_Keys.IBMXForce_API_PASS
Scamalytics_API_KEY = API_Keys.Scamalytics_API_KEY


def IP_Address(ipaddress):
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
    except KeyError: cert = ""

    print(f"\nOSINT on {ipaddress}:")
    print(f">> VirusTotal: {malicious}/{total} | Community score: {reputation} | Country: {country} ({regional_internet_registry}) | Owner: {owner} {cert}")

    # AbuseIPDB API
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

    print(f">> AbuseIPDB: Abuse score: {abuseConfidenceScore}/100 ({isWhitelisted}) | Reported {totalReports} times by {numDistinctUsers} users | ISP: {isp} | Country: {countryCode} | Domain: {domain}")


    XFE_Request = requests.get("https://exchange.xforce.ibmcloud.com/api/ipr/" + ipaddress, auth=HTTPBasicAuth(XFE_API_KEY, XFE_API_PASS))
    #print(XFE_Request.text)
    decodedResponse = json.loads(XFE_Request.text)
    score = decodedResponse["score"]
    print(f">> XFE: {score}/10")

    Scamalytics_Request = requests.get("https://api11.scamalytics.com/daxtonwirth/?key=" + Scamalytics_API_KEY + "&ip=" + ipaddress)
    decodedResponse = json.loads(Scamalytics_Request.text)
    risk = decodedResponse["risk"]
    score = decodedResponse["score"]
    print(f">> Scamalytics: Risk: {risk} - {score}/100")

def Hash(hash):
    print(f"\nOSINT on {hash}: ")

    VirusTotal_Request = requests.get("https://www.virustotal.com/api/v3/files/" + hash, headers={'x-apikey': VirusTotal_API_Key}).json()
    #print(VirusTotal_Request)

    try: harmless = VirusTotal_Request["data"]["attributes"]["last_analysis_stats"]["harmless"]
    except: harmless = ""
    try: malicious = VirusTotal_Request["data"]["attributes"]["last_analysis_stats"]["malicious"]
    except: malicious = ""
    try: undetected = VirusTotal_Request["data"]["attributes"]["last_analysis_stats"]["undetected"]
    except: undetected = ""
    try: total = int(harmless) + int(malicious) + int(undetected)
    except: total = harmless

    print(f">> VirusTotal: {malicious}/{total}")

    XFE_Request = requests.get("https://exchange.xforce.ibmcloud.com/api/malware/" + hash, auth=HTTPBasicAuth(XFE_API_KEY, XFE_API_PASS))
    decodedResponse = json.loads(XFE_Request.text)
    risk = decodedResponse["malware"]["risk"]
    print(f">> XFE: Risk - {risk}")

def Domain(domain):
    print(f"\nOSINT on {domain}: ")

    VirusTotal_Request = requests.get("https://www.virustotal.com/api/v3/domains/" + domain, headers={'x-apikey': VirusTotal_API_Key}).json()
    #print(VirusTotal_Request)

    try: harmless = VirusTotal_Request["data"]["attributes"]["last_analysis_stats"]["harmless"]
    except: harmless = ""
    try: malicious = VirusTotal_Request["data"]["attributes"]["last_analysis_stats"]["malicious"]
    except: malicious = ""
    try: undetected = VirusTotal_Request["data"]["attributes"]["last_analysis_stats"]["undetected"]
    except: undetected = ""
    try: total = int(harmless) + int(malicious) + int(undetected)
    except: total = harmless
    try: registrar = VirusTotal_Request["data"]["attributes"]["registrar"]
    except: registrar = ""
    try: reputation = " Reputation: " + VirusTotal_Request["data"]["attributes"]["reputation"] 
    except: reputation = ""
    try: last_https_certificate = "- Cert: " + VirusTotal_Request["data"]["attributes"]["last_https_certificate"]["issuer"]["O"]
    except: last_https_certificate = ""


    print(f">> VirusTotal: {malicious}/{total}{reputation} | {registrar} {last_https_certificate}")

    # XFE domain request
    XFE_Request = requests.get("https://exchange.xforce.ibmcloud.com/api/url/" + domain, auth=HTTPBasicAuth(XFE_API_KEY, XFE_API_PASS))
    #print(XFE_Request.text)
    decodedResponse = json.loads(XFE_Request.text)
    score = decodedResponse["result"]["score"]
    print(f">> XFE: {score}/10")


ipaddress = input("Enter IP address: ") # Example: 8.8.8.8, 121.162.131.223
if ipaddress != "":
    IP_Address(ipaddress)

hash = input("\nEnter the file hash: ") # Example: Chrome: 76868ae832f6c6bd26cadc7d7c269986, malicious: c0202cf6aeab8437c638533d14563d35
if hash != "":
    Hash(hash)

domain = input("\nEnter domain: ") # Example: gmail.com, gmial.com
if domain != "":
    Domain(domain)