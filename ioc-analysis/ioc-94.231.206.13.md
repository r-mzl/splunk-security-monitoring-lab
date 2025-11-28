# Indicator of Compromise Analysis (IOC) -- 94.231.206.13

This document provides analysis of SSH bruteforce acitivity associate with the IP **94.231.206.13** observed and validated using public threat intelligence sources.

---

## 1. Indicator Overview
**GreyNoise:** Observed as SSH Alternative Port Crawler and attempts of mulitple SSH connections
**VirusTotal:** Several engines have flagged the IP as malicious/suspicious
**AbuseIPDB:** Reported for SSH bruteforce and portscanning, with 100-percent confidence of abuse rating.
**AlienVault OTX:** Received two pulses on a honeypot
**Censys:** Commonly seen on OpenSSH_X.X, hosted on a VPS provider

**Assessment:**
- The IP appears to be a part of Onyphe, a cyber defense firm. They are known to take snapshots and assess vulnerabilities of the web applications
- The activity seems to be for educational purposes

**Recommendation:**
- Block **94.231.206.13** at the network level for the time being
- A request can be made to Onyphe to blacklist our range of IP addresses
- Continue monitoring SSH auth logs for repeated bruteforce attempts
- Implement SSH keys and restrict SSH to trusted IP ranges