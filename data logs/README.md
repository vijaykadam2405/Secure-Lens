# 📊 Test Data Directory
## Quantum Malware Hunter & AI - Testing Datasets

---

## 📁 Files Overview

### **Original Test Data**
- `auth.log` - Original authentication log (18 lines, 3 IPs)
- `threat_activity.json` - Original honeypot log (12 events, 3 IPs)

### **Comprehensive Simulated Data** ⭐ RECOMMENDED FOR DEMO
- `simulated_auth.log` - All attack types (200+ lines, 8 scenarios)
- `simulated_honeypot.json` - Advanced attacks (70+ events, 10 scenarios)

### **Individual Scenario Files** (.log format)
- `simulated_normal.log` - Benign activity only (5 IPs)
- `simulated_brute_force.log` - Brute-Force attack (25 failed logins)
- `simulated_reconnaissance.log` - Reconnaissance attack (15 invalid users)
- `simulated_mixed_attacks.log` - Multiple attacks (3 IPs, mixed patterns)

### **Individual Scenario Files** (.json format)
- `threat_payload_execution.json` - Ransomware payload execution

### **Documentation**
- `TEST_DATA_GUIDE.md` - Complete testing guide with all scenarios

---

## 🚀 Quick Start

### **For Competition Demo (RECOMMENDED):**
```
Upload these two files:
1. simulated_auth.log
2. simulated_honeypot.json

Expected: 12 IPs, 9 threats, all attack types covered
```

### **For Quick Testing:**
```
Upload any combination:
- simulated_brute_force.log (tests Brute-Force detection)
- simulated_reconnaissance.log (tests Reconnaissance detection)
- threat_payload_execution.json (tests Payload-Execution detection)
- simulated_normal.log (tests benign activity, should show 0 threats)
```

---

## 📊 Coverage Summary

| File | IPs | Benign | Malicious | Attack Types |
|------|-----|--------|-----------|--------------|
| auth.log | 3 | 1 | 2 | Mixed |
| simulated_auth.log | 8 | 3 | 5 | All types |
| simulated_normal.log | 5 | 5 | 0 | None |
| simulated_brute_force.log | 1 | 0 | 1 | Brute-Force |
| simulated_reconnaissance.log | 1 | 0 | 1 | Reconnaissance |
| simulated_mixed_attacks.log | 3 | 0 | 3 | Mixed |

---

## ✅ What Each File Tests

### **simulated_auth.log + simulated_honeypot.json** (COMPLETE TEST)
- ✅ Benign activity detection
- ✅ Brute-Force (>20 failed logins)
- ✅ Reconnaissance (>10 invalid users)
- ✅ Payload-Execution (suspicious commands)
- ✅ Generic-Attack (edge cases)
- ✅ Ransomware deployment
- ✅ Cryptominer installation
- ✅ Backdoor creation
- ✅ Data exfiltration
- ✅ Botnet malware

### **simulated_normal.log** (BENIGN ONLY)
- ✅ Normal user logins
- ✅ No false positives
- ✅ Legitimate activity patterns

### **simulated_brute_force.log** (SINGLE ATTACK TYPE)
- ✅ 25 failed login attempts
- ✅ Brute-Force classification
- ✅ Threshold validation (>20)

### **simulated_reconnaissance.log** (SINGLE ATTACK TYPE)
- ✅ 15 invalid user attempts
- ✅ Reconnaissance classification
- ✅ Threshold validation (>10)

### **simulated_mixed_attacks.log** (EDGE CASES)
- ✅ 50 failed logins (Brute-Force)
- ✅ 19 failed logins (Generic-Attack, edge case)
- ✅ 9 invalid users (Generic-Attack, edge case)

---

## 🎯 Testing Strategy

### **For Judges/Demo:**
1. Start with **simulated_auth.log + simulated_honeypot.json**
2. Show comprehensive detection (12 IPs, 9 threats)
3. Highlight threat distribution chart
4. Point out all attack categories detected

### **For Verification:**
1. Test **simulated_normal.log** → Should show 0 threats
2. Test **simulated_brute_force.log** → Should show 1 Brute-Force
3. Test **simulated_reconnaissance.log** → Should show 1 Reconnaissance
4. Test **threat_payload_execution.json** → Should show 1 Payload-Execution

### **For Edge Case Testing:**
1. Test **simulated_mixed_attacks.log**
2. Verify 185.220.101.33 = Brute-Force (50 > 20)
3. Verify 10.0.0.100 = Generic-Attack (19 < 20)
4. Verify 172.16.0.50 = Generic-Attack (9 < 10)
                        
---

## 📖 Full Documentation

See **TEST_DATA_GUIDE.md** for:
- Detailed scenario descriptions
- Expected detection results
- Verification checklists
- Troubleshooting tips

---

**Test Data Version:** 1.0  
**Last Updated:** October 7, 2025  
**Created for:** Indian Army Terrier Cyber Quest 2025 - Track 2
