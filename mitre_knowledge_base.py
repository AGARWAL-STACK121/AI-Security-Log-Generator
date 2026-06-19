"""
MITRE ATT&CK Knowledge Base
============================
This file contains the MITRE ATT&CK techniques database used for RAG retrieval.
Each technique has an ID, name, description, and keywords for matching.
"""

MITRE_TECHNIQUES = [
    {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversaries use brute force techniques to gain access to accounts by systematically trying all possible passwords or using common password lists.",
        "keywords": ["brute force", "login failed", "multiple failed", "password attempt", "authentication failure", "repeated login"],
        "severity": "CRITICAL",
        "recommended_action": "Block the source IP immediately, enable account lockout policy, and enforce Multi-Factor Authentication (MFA).",
        "indicators": ["Multiple failed login attempts from single IP", "Rapid successive authentication failures"]
    },
    {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Adversaries attempt to exploit weaknesses in internet-facing applications such as web servers or databases to gain unauthorized access.",
        "keywords": ["sql injection", "xss", "web attack", "exploit", "injection", "cross site", "web vulnerability"],
        "severity": "CRITICAL",
        "recommended_action": "Apply web application firewall (WAF) rules, patch the vulnerable application immediately, and review all recent web server logs.",
        "indicators": ["SQL syntax in web requests", "Script tags in input fields", "Unusual HTTP request patterns"]
    },
    {
        "id": "T1046",
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "description": "Adversaries scan the network to discover active hosts and open ports/services, often as a reconnaissance step before an attack.",
        "keywords": ["port scan", "network scan", "service discovery", "nmap", "port sweep", "reconnaissance"],
        "severity": "HIGH",
        "recommended_action": "Block the scanning IP at the firewall level, investigate if this is an internal or external source, and review network segmentation.",
        "indicators": ["Sequential port connection attempts", "ICMP sweep activity", "Connection attempts to many ports in short time"]
    },
    {
        "id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Defense Evasion",
        "description": "Adversaries use stolen or compromised credentials to access systems and bypass security controls, making the activity appear legitimate.",
        "keywords": ["unauthorized access", "invalid credentials", "account compromise", "stolen credentials", "unauthorized login"],
        "severity": "HIGH",
        "recommended_action": "Reset the compromised account password immediately, revoke active sessions, enable MFA, and audit recent account activity.",
        "indicators": ["Login from unusual geographic location", "Access at unusual time", "Access to sensitive resources not normally accessed"]
    },
    {
        "id": "T1548",
        "name": "Abuse Elevation Control Mechanism",
        "tactic": "Privilege Escalation",
        "description": "Adversaries attempt to gain higher-level permissions on a system by exploiting weaknesses in how operating systems handle privilege levels.",
        "keywords": ["privilege escalation", "root access", "admin privilege", "sudo", "elevation", "permission escalation"],
        "severity": "CRITICAL",
        "recommended_action": "Immediately revoke elevated privileges, audit all recent admin actions, review sudo logs, and apply the principle of least privilege.",
        "indicators": ["Unexpected privilege change", "Unusual admin account usage", "Access to restricted system areas"]
    },
    {
        "id": "T1041",
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "description": "Adversaries steal data by transferring it out of the victim network over an existing command and control channel.",
        "keywords": ["data exfiltration", "data theft", "file transfer", "data leak", "sensitive data", "unauthorized transfer"],
        "severity": "CRITICAL",
        "recommended_action": "Block outbound connections from the affected system, isolate it from the network, preserve logs for forensic analysis, and notify your data protection team.",
        "indicators": ["Large outbound data transfers", "Connections to unknown external IPs", "Unusual file access patterns"]
    },
    {
        "id": "T1486",
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "description": "Adversaries encrypt data on target systems or storage devices, typically as part of a ransomware attack to extort victims for payment.",
        "keywords": ["ransomware", "file encrypted", "encryption detected", "ransom", "files locked", "crypto locker"],
        "severity": "CRITICAL",
        "recommended_action": "IMMEDIATELY isolate the affected system from the network, do not pay the ransom, restore from clean backups, and report to cybersecurity authorities.",
        "indicators": ["Mass file encryption activity", "Ransom note files created", "Shadow copy deletion attempts"]
    },
    {
        "id": "T1498",
        "name": "Network Denial of Service",
        "tactic": "Impact",
        "description": "Adversaries flood network resources with traffic to degrade or block the availability of targeted resources to legitimate users.",
        "keywords": ["ddos", "denial of service", "flood attack", "traffic spike", "service unavailable", "bandwidth exhaustion"],
        "severity": "CRITICAL",
        "recommended_action": "Enable DDoS protection on your network edge, rate-limit incoming traffic, contact your ISP for upstream filtering, and activate your incident response plan.",
        "indicators": ["Unusual traffic volume spike", "Multiple sources sending identical requests", "Service response time degradation"]
    },
    {
        "id": "T1083",
        "name": "File and Directory Discovery",
        "tactic": "Discovery",
        "description": "Adversaries enumerate files and directories on a system to find sensitive information, configuration files, or credentials.",
        "keywords": ["file access", "directory listing", "file discovery", "unauthorized file", "sensitive file", "file enumeration"],
        "severity": "MEDIUM",
        "recommended_action": "Audit file access permissions, review what files were accessed, check if sensitive data was read, and monitor the user account for further suspicious activity.",
        "indicators": ["Accessing files outside normal working directory", "Bulk file read operations", "Access to configuration or credential files"]
    },
    {
        "id": "T1189",
        "name": "Drive-by Compromise",
        "tactic": "Initial Access",
        "description": "Adversaries compromise a system through a user visiting a malicious website or downloading a suspicious file from the internet.",
        "keywords": ["suspicious download", "malicious url", "drive by", "malware download", "suspicious file", "web download"],
        "severity": "HIGH",
        "recommended_action": "Quarantine the downloaded file, run a full malware scan on the system, block the source URL at the firewall, and check for signs of payload execution.",
        "indicators": ["Download from suspicious domain", "Executable file downloaded from web", "File with mismatched extension"]
    },
    {
        "id": "T1078.001",
        "name": "Default Accounts",
        "tactic": "Defense Evasion",
        "description": "Adversaries use default usernames and passwords that come pre-configured in systems to gain unauthorized access.",
        "keywords": ["default password", "default account", "admin admin", "login success after failure", "default credentials"],
        "severity": "HIGH",
        "recommended_action": "Change all default credentials immediately, disable unused default accounts, and conduct an audit of all system accounts.",
        "indicators": ["Login with default username patterns", "First-time login from default account after many failures"]
    },
    {
        "id": "T1071",
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "description": "Adversaries communicate with compromised systems using standard application layer protocols to blend in with normal network traffic.",
        "keywords": ["c2", "command control", "suspicious connection", "outbound connection", "beacon", "remote connection"],
        "severity": "HIGH",
        "recommended_action": "Block the suspicious outbound connection, analyze network traffic for C2 patterns, and scan the system for malware or backdoors.",
        "indicators": ["Regular beaconing at fixed intervals", "Connections to newly registered domains", "Encrypted traffic to unknown destinations"]
    },
]


def get_all_techniques():
    """Return all MITRE ATT&CK techniques"""
    return MITRE_TECHNIQUES


def get_technique_by_id(technique_id: str):
    """Get a specific technique by its ID"""
    for technique in MITRE_TECHNIQUES:
        if technique["id"] == technique_id:
            return technique
    return None