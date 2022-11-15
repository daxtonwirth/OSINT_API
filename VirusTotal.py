import requests

ipaddress = input("Enter IP address: ") 
api_key = "3d963df91101946a611363c13a59a7eb1857804d71977662dc1d0db82a22363a"

request1 = requests.get("https://www.virustotal.com/api/v3/ip_addresses/" + ipaddress, headers={'x-apikey': api_key}).json()
#print(request1)
try:
    country = request1["data"]["attributes"]["country"]
    owner = request1["data"]["attributes"]["as_owner"]
    regional_internet_registry = request1["data"]["attributes"]["regional_internet_registry"]
    harmless = request1["data"]["attributes"]["last_analysis_stats"]["harmless"]
    malicious = request1["data"]["attributes"]["last_analysis_stats"]["malicious"]
    reputation = request1["data"]["attributes"]["reputation"]
    cert = request1["data"]["attributes"]["last_https_certificate"]["public_key"]["issuer"]
except:
    cert = ""

total = int(harmless) + int(malicious)


print(f"Country: {country} ({regional_internet_registry})")
print(f"Owner: {owner} ({cert})")
print(f"Vendor score: {malicious}/{total}")
print(f"Commun score: {reputation}")
