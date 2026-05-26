# Vulnerability Database
# Maps port numbers to known vulnerabilities, CVEs, and risk levels

VULN_DB = {
    21: {
        'service': 'FTP',
        'risk': 'HIGH',
        'description': 'FTP transmits data in cleartext including credentials. Anonymous login may be enabled.',
        'vulnerabilities': [
            'Cleartext credential transmission',
            'Potential anonymous login enabled',
            'Prone to brute-force attacks'
        ],
        'cves': ['CVE-1999-0497', 'CVE-2010-4221']
    },
    22: {
        'service': 'SSH',
        'risk': 'MEDIUM',
        'description': 'SSH is generally secure but may be vulnerable to brute force, outdated versions, or weak ciphers.',
        'vulnerabilities': [
            'Brute-force attacks on weak passwords',
            'Outdated SSH versions may have known exploits',
            'Username enumeration possible'
        ],
        'cves': ['CVE-2018-15473', 'CVE-2023-38408']
    },
    23: {
        'service': 'TELNET',
        'risk': 'CRITICAL',
        'description': 'Telnet is an unencrypted remote access protocol. All data including credentials are transmitted in cleartext.',
        'vulnerabilities': [
            'All data transmitted in cleartext',
            'Credentials visible in network traffic',
            'Should be replaced with SSH immediately'
        ],
        'cves': ['CVE-1999-0619']
    },
    25: {
        'service': 'SMTP',
        'risk': 'HIGH',
        'description': 'SMTP may be configured as an open relay, allowing spam and email spoofing.',
        'vulnerabilities': [
            'Potential open mail relay',
            'Email spoofing risk',
            'User enumeration via VRFY/EXPN'
        ],
        'cves': ['CVE-2002-1278', 'CVE-2011-1720']
    },
    53: {
        'service': 'DNS',
        'risk': 'MEDIUM',
        'description': 'DNS service exposed. May be vulnerable to zone transfers or amplification attacks.',
        'vulnerabilities': [
            'DNS zone transfer possible',
            'DNS amplification DDoS risk',
            'Cache poisoning vulnerabilities'
        ],
        'cves': ['CVE-2013-5211', 'CVE-2020-1350']
    },
    80: {
        'service': 'HTTP',
        'risk': 'MEDIUM',
        'description': 'Unencrypted web service. Data transmitted over HTTP is vulnerable to interception.',
        'vulnerabilities': [
            'Unencrypted web traffic',
            'Sensitive data exposure risk',
            'Potential for man-in-the-middle attacks'
        ],
        'cves': []
    },
    110: {
        'service': 'POP3',
        'risk': 'HIGH',
        'description': 'POP3 transmits email and credentials in cleartext.',
        'vulnerabilities': [
            'Cleartext credential transmission',
            'Email content exposed in transit',
            'Brute force attacks possible'
        ],
        'cves': ['CVE-2003-0143']
    },
    111: {
        'service': 'RPCBIND',
        'risk': 'HIGH',
        'description': 'RPC portmapper exposed. Can be used to enumerate RPC services and launch attacks.',
        'vulnerabilities': [
            'Service enumeration via RPC',
            'NFS exploitation possible',
            'Remote code execution in some versions'
        ],
        'cves': ['CVE-2017-8779']
    },
    135: {
        'service': 'MSRPC',
        'risk': 'HIGH',
        'description': 'Microsoft RPC endpoint mapper. Has been targeted by numerous worms and exploits.',
        'vulnerabilities': [
            'Remote code execution risk',
            'Buffer overflow vulnerabilities',
            'Targeted by MS Blaster worm'
        ],
        'cves': ['CVE-2003-0352', 'CVE-2003-0715']
    },
    139: {
        'service': 'NETBIOS',
        'risk': 'HIGH',
        'description': 'NetBIOS session service. Enables Windows file sharing and network browsing.',
        'vulnerabilities': [
            'Windows network enumeration',
            'Null session attacks possible',
            'SMB relay attacks'
        ],
        'cves': ['CVE-2017-0143']
    },
    143: {
        'service': 'IMAP',
        'risk': 'HIGH',
        'description': 'IMAP transmits email and credentials in cleartext.',
        'vulnerabilities': [
            'Cleartext credential transmission',
            'Email content exposed in transit'
        ],
        'cves': ['CVE-2021-38371']
    },
    443: {
        'service': 'HTTPS',
        'risk': 'LOW',
        'description': 'Encrypted web service. Verify SSL/TLS configuration and certificate validity.',
        'vulnerabilities': [
            'Weak SSL/TLS cipher suites possible',
            'Certificate misconfiguration',
            'HSTS not enforced'
        ],
        'cves': ['CVE-2014-3566']
    },
    445: {
        'service': 'SMB',
        'risk': 'CRITICAL',
        'description': 'SMB/Windows File Sharing exposed. Highly targeted by ransomware and worms including WannaCry.',
        'vulnerabilities': [
            'EternalBlue exploit (WannaCry ransomware)',
            'SMB relay attacks',
            'Credential theft via NTLM',
            'Remote code execution'
        ],
        'cves': ['CVE-2017-0144', 'CVE-2017-0145', 'CVE-2020-0796']
    },
    512: {
        'service': 'REXEC',
        'risk': 'CRITICAL',
        'description': 'Remote execution service transmits credentials in cleartext.',
        'vulnerabilities': [
            'Cleartext credential transmission',
            'Remote command execution',
            'Should be disabled immediately'
        ],
        'cves': []
    },
    513: {
        'service': 'RLOGIN',
        'risk': 'CRITICAL',
        'description': 'Remote login service. Insecure legacy protocol.',
        'vulnerabilities': [
            'IP-based authentication bypass',
            'Cleartext transmission',
            'Trust relationship exploitation'
        ],
        'cves': []
    },
    514: {
        'service': 'SYSLOG/RSHELL',
        'risk': 'HIGH',
        'description': 'Syslog or remote shell service. May allow command execution.',
        'vulnerabilities': [
            'Remote shell access without authentication',
            'Log injection attacks',
            'Information disclosure'
        ],
        'cves': []
    },
    993: {
        'service': 'IMAPS',
        'risk': 'LOW',
        'description': 'Encrypted IMAP service. Verify SSL/TLS configuration.',
        'vulnerabilities': [
            'Weak SSL/TLS configuration possible',
            'Brute force on authentication'
        ],
        'cves': []
    },
    995: {
        'service': 'POP3S',
        'risk': 'LOW',
        'description': 'Encrypted POP3 service. Verify SSL/TLS configuration.',
        'vulnerabilities': ['Weak SSL/TLS configuration possible'],
        'cves': []
    },
    1433: {
        'service': 'MSSQL',
        'risk': 'CRITICAL',
        'description': 'Microsoft SQL Server exposed to network. Database should not be publicly accessible.',
        'vulnerabilities': [
            'Database directly accessible from network',
            'Default credentials risk (sa/blank)',
            'Remote code execution via xp_cmdshell'
        ],
        'cves': ['CVE-2020-0618', 'CVE-2019-1068']
    },
    1521: {
        'service': 'ORACLE-DB',
        'risk': 'CRITICAL',
        'description': 'Oracle Database exposed to network.',
        'vulnerabilities': [
            'Database directly accessible from network',
            'Default credential risk',
            'TNS Poison attack'
        ],
        'cves': ['CVE-2012-1675']
    },
    2049: {
        'service': 'NFS',
        'risk': 'HIGH',
        'description': 'Network File System exposed. May allow unauthorized file access.',
        'vulnerabilities': [
            'Unauthenticated file system access',
            'Sensitive file exposure',
            'Write access to critical files possible'
        ],
        'cves': ['CVE-2017-7645']
    },
    2181: {
        'service': 'ZOOKEEPER',
        'risk': 'CRITICAL',
        'description': 'Apache Zookeeper exposed without authentication.',
        'vulnerabilities': [
            'No authentication by default',
            'Complete cluster configuration access',
            'Data extraction and modification'
        ],
        'cves': ['CVE-2019-0201']
    },
    3000: {
        'service': 'HTTP-DEV',
        'risk': 'MEDIUM',
        'description': 'Development web server exposed. Often used by Node.js/React apps.',
        'vulnerabilities': [
            'Development server should not be publicly exposed',
            'Debug mode may be enabled',
            'Unencrypted traffic'
        ],
        'cves': []
    },
    3306: {
        'service': 'MYSQL',
        'risk': 'CRITICAL',
        'description': 'MySQL database exposed to network. Should not be publicly accessible.',
        'vulnerabilities': [
            'Database directly accessible from network',
            'Brute force on root account',
            'Data exfiltration risk',
            'Default credentials may be set'
        ],
        'cves': ['CVE-2016-6662', 'CVE-2021-27928']
    },
    3389: {
        'service': 'RDP',
        'risk': 'CRITICAL',
        'description': 'Remote Desktop Protocol exposed. Highly targeted by ransomware and brute force attacks.',
        'vulnerabilities': [
            'BlueKeep - unauthenticated RCE',
            'DejaBlue remote code execution',
            'Brute force attacks on credentials',
            'Man-in-the-middle attacks'
        ],
        'cves': ['CVE-2019-0708', 'CVE-2019-1181', 'CVE-2019-1182']
    },
    4444: {
        'service': 'BACKDOOR/METASPLOIT',
        'risk': 'CRITICAL',
        'description': 'This port is commonly used by Metasploit reverse shells and malware backdoors.',
        'vulnerabilities': [
            'Possible active backdoor or malware',
            'Command and control channel',
            'Unauthorized remote access'
        ],
        'cves': []
    },
    5432: {
        'service': 'POSTGRESQL',
        'risk': 'CRITICAL',
        'description': 'PostgreSQL database exposed to network.',
        'vulnerabilities': [
            'Database directly accessible from network',
            'Default postgres user may have no password',
            'COPY TO/FROM PROGRAM RCE possible'
        ],
        'cves': ['CVE-2019-10164', 'CVE-2018-10915']
    },
    5900: {
        'service': 'VNC',
        'risk': 'HIGH',
        'description': 'VNC remote desktop exposed. Often has weak or no authentication.',
        'vulnerabilities': [
            'Weak or no authentication',
            'Screen capture and input injection',
            'Brute force attacks'
        ],
        'cves': ['CVE-2019-15694', 'CVE-2020-14397']
    },
    6379: {
        'service': 'REDIS',
        'risk': 'CRITICAL',
        'description': 'Redis database exposed without authentication.',
        'vulnerabilities': [
            'No authentication by default',
            'Arbitrary command execution via CONFIG SET',
            'SSH key injection for root access',
            'Complete data exfiltration'
        ],
        'cves': ['CVE-2015-8080', 'CVE-2022-0543']
    },
    7001: {
        'service': 'WEBLOGIC',
        'risk': 'CRITICAL',
        'description': 'Oracle WebLogic Server admin port. Repeatedly exploited for RCE.',
        'vulnerabilities': [
            'Deserialization remote code execution',
            'Authentication bypass',
            'SSRF attacks'
        ],
        'cves': ['CVE-2019-2729', 'CVE-2020-14882', 'CVE-2021-2394']
    },
    8080: {
        'service': 'HTTP-ALT',
        'risk': 'MEDIUM',
        'description': 'Alternative HTTP port. Often used for admin panels or development servers.',
        'vulnerabilities': [
            'Unencrypted web traffic',
            'Potential admin panel exposure',
            'Development environment may be accessible'
        ],
        'cves': []
    },
    8443: {
        'service': 'HTTPS-ALT',
        'risk': 'LOW',
        'description': 'Alternative HTTPS port.',
        'vulnerabilities': [
            'Weak SSL/TLS configuration possible',
            'Admin interface may be exposed'
        ],
        'cves': []
    },
    8888: {
        'service': 'JUPYTER/HTTP-ALT',
        'risk': 'HIGH',
        'description': 'Jupyter Notebook or alternative web service. Jupyter allows arbitrary code execution.',
        'vulnerabilities': [
            'Jupyter Notebook without authentication allows arbitrary Python execution',
            'File system access',
            'Unencrypted traffic'
        ],
        'cves': ['CVE-2022-24758']
    },
    9200: {
        'service': 'ELASTICSEARCH',
        'risk': 'CRITICAL',
        'description': 'Elasticsearch exposed without authentication. Full data access possible.',
        'vulnerabilities': [
            'No authentication by default',
            'Complete data exfiltration possible',
            'Index deletion and modification',
            'Script execution for RCE'
        ],
        'cves': ['CVE-2014-3120', 'CVE-2015-1427']
    },
    10000: {
        'service': 'WEBMIN',
        'risk': 'CRITICAL',
        'description': 'Webmin system administration panel. Critical vulnerabilities in recent versions.',
        'vulnerabilities': [
            'Remote code execution vulnerabilities',
            'Authentication bypass',
            'Full system control if exploited'
        ],
        'cves': ['CVE-2019-15107', 'CVE-2022-36446']
    },
    11211: {
        'service': 'MEMCACHED',
        'risk': 'HIGH',
        'description': 'Memcached exposed without authentication. Can be used for DDoS amplification.',
        'vulnerabilities': [
            'No authentication required',
            'DDoS amplification attacks',
            'Cache data poisoning and theft'
        ],
        'cves': ['CVE-2018-1000115']
    },
    27017: {
        'service': 'MONGODB',
        'risk': 'CRITICAL',
        'description': 'MongoDB exposed without authentication. Millions of databases breached via exposed MongoDB.',
        'vulnerabilities': [
            'No authentication by default',
            'Complete database access',
            'Data exfiltration and deletion',
            'Ransomware target'
        ],
        'cves': ['CVE-2013-4650', 'CVE-2015-7882']
    },
    50000: {
        'service': 'SAP/HTTP-ALT',
        'risk': 'HIGH',
        'description': 'SAP dispatcher or alternative web service port.',
        'vulnerabilities': [
            'SAP system exploitation risk',
            'Unencrypted traffic',
            'Default credentials possible'
        ],
        'cves': ['CVE-2020-6287']
    }
}

RISK_COLORS = {
    'CRITICAL': '#dc2626',
    'HIGH':     '#ea580c',
    'MEDIUM':   '#ca8a04',
    'LOW':      '#16a34a',
    'INFO':     '#2563eb'
}

RISK_SCORE = {
    'CRITICAL': 10,
    'HIGH': 7,
    'MEDIUM': 4,
    'LOW': 2,
    'INFO': 0
}
