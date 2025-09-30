QUESTION:Download OWSAP ZAP and perform a security scan on a website you have access to. 
Explain the steps you followed to set up and configure ZAP for the scan. Provide a 
detailed report highlighting any vulnerabilities or security issues identified during the 
scan. 

ANSWER;
 OWASP ZAP Scan Summary Report
Target: OWASP Juice Shop (Localhost)
OS Used: Kali Linux
Tool: OWASP ZAP,run via Docker
Scan Type: Automated Scan
Launched Juice Shop locally (usually runs on http://localhost:3000).
Entered the target URL in ZAP: http://localhost:3000
Date: 29-09-2025

Starting the Attack
   -Selected the target site in ZAP’s “Sites” tab.
   - Right-clicked the target → "Attack" → "Active Scan".
   - Chose default scan settings and launched the scan.
     
Monitoring the Scan
   - Watched alerts populate in real-time.
   - Waited for the scan to complete (note: system crashed once during the scan, had to resume)
     
Exporting the Report
   - After completion, exported the full scan report as an HTML/Markdown file (zap_scan_report.html).
   - Also documented a summary of key vulnerabilities for reporting.

📊Summary findings

The scan detected 14 types of vulnerabilities
NOTE: High Risk – needs urgent fixing
      Medium Risk – should be addressed soon
      Low Risk – not critical, but worth fixing
      Informational – things to be aware of, but not dangerous
      
1. SQL Injection - SQLite (High):  
   The app is vulnerable to SQL Injection, allowing attackers to manipulate queries, access sensitive data, or even corrupt the database.

2. Content Security Policy (CSP) Header Not Set (Medium):  
   Without a CSP header, the site is more vulnerable to Cross-Site Scripting (XSS) and other code injection attacks.

3. Cross-Domain Misconfiguration (Medium):  
   The app allows resources to be shared with untrusted or wildcard domains, increasing the risk of data leakage.

4. Missing Anti-clickjacking Header (Medium):  
   Absence of X-Frame-Options or Content-Security-Policy: frame-ancestors allows clickjacking attacks via embedded iframes.

5. Session ID in URL Rewrite (Medium):  
   Session identifiers are included in URLs, which can be logged, shared, or leaked — leading to session hijacking risks.

6. Vulnerable JavaScript Library (Medium):  
   A JS library used in the site is known to have public vulnerabilities that could be exploited by attackers.

7. Cross-Domain JavaScript Inclusion (Low):  
   Including JS files from external domains increases the chance of executing malicious scripts if the third-party source is compromised.

8. Private IP Disclosure (Low):Internal IPs were found in responses. This can help attackers map internal infrastructure.

9. Timestamp Disclosure - Unix (Low):  
   The app leaks Unix timestamps, which can help attackers understand app behavior or timing of events.

10. Missing X-Content-Type-Options Header (Low): 
    Without this header, browsers may incorrectly interpret MIME types, leading to content sniffing attacks.

11. Suspicious Comments (Informational):  
    HTML or JS files contain developer comments that may reveal sensitive or debugging information.

12. Modern Web Application (Informational):  
    ZAP identifies the app as using modern web features; not a vulnerability, but a scan artifact.

13. Retrieved from Cache (Informational):  
    Some resources are cached by browsers, which could allow attackers to serve stale or vulnerable content in certain scenarios.

14. User Agent Fuzzer (Informational):  
    ZAP’s user-agent fuzzer triggered multiple responses, suggesting the app responds differently to various user-agent strings.

✅ Recommendations

- Use parameterized queries to eliminate SQL Injection.
- Apply security headers (CSP, X-Frame-Options, X-Content-Type-Options).


