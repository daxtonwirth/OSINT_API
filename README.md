# OSINT_API

# Overview

This software queries popular threat feed websites including [Virustotal](http://Virustotal.com), [AbuseIPDB](http://AbuseIPDB.com), [IBM  X-Force Exchange](http://exchange.xforce.ibmcloud.com) to automate retreiving the necessary threat information to work security alerts. Once a free API account is made and the key is added, it queries API, retreived the important information in the json file, and formats the results of those queries in an easy-to-read format to save the user time from having to manually visit the websites.

My purpose for writing this software is to learn how to work with APIs and automate my OSINT which will save me time in the future.

[Software Demo Video](http://youtube.link.goes.here)

# Development Environment

I used Python with the requests library to query the APIs. I also signed up for a free account on each of the websites to obtain an API key. 

# Useful Websites

* [VirusTotal API documentation](https://developers.virustotal.com/reference/ip-object)
* [IBM X-Force](https://exchange.xforce.ibmcloud.com/)
* [AbuseIPDB API documentation](https://docs.abuseipdb.com/?python#check-endpoint)

# Future Work

* Have the API constantly run and obtain log information and query the API and alert on IPs that have a certain amount of hits
* Create a honeypot and post the scanning IPs to abuseipdb
