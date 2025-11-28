PS. This is a simulated lab writeup, the failed SSH auth attempts have been made from the local machine.

# Daily Infrastructure and Threat Monitoring Brief
**Date:** 11/28/25
**Author:** Shashank Maddikunta

--

## 1. Overview:
- Splunk Enterprise deployed on Ubuntu Server
- Ingesting /var/log/auth.log and /var/log/syslog
- Monitoring SSH authentication activity and system events

-- 

## 2. Notable Events:
- Multiple failed SSH auth observed from a local machine
- Repeated failures from IP 192.168.0.187, which exceeded the bruteforce threshold (>5 attempts)

--

## 3. Detection Summary:
**Detection:** SSH Bruteforce by IP
**SPL:**
index=* "Failed password" | rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)" | stats count by src_ip | where count > 5

**Result:**
- 192.168.0.187 -- 9 failed attempts

--

## 4. Threat Intelligence (IOC Traige)
**IOC:** 192.168.0.187
**Assessment:** These requests were planned attacks from the penetration testing team to ensure the systems in operating condition

OSINT:
- GreyNoise: N/A
- VirusTotal: N/A
- AbuseIPDB: N/A
- OTX: N/A

## 5. Recommended Actions:
- Block malicious IPs at firewall
- Implement SSH hardening such as SSH keys and changing default SSH ports
- Continue monitoring SSH logs on Splunk

##6. Appendix:
- Screenshots are located in the screenshots folder
