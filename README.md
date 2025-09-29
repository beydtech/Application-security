QUESTION:Research and explain the concept of SQL injection in the context of web application 
security. Provide examples of how SQL injection attacks can be exploited and discuss the 
potential consequences. Describe preventive measures that developers can implement to 
protect against SQL injection vulnerabilities.

ANSWER;
 OWASP ZAP Scan Summary Report
Target: OWASP Juice Shop (Localhost)
Tool: OWASP ZAP
Scan Type: Automated Scan
Date: 29-09-2025

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


SQL Injection (SQLi) is a critical vulnerability that allows attackers to manipulate SQL queries by injecting malicious input through user-facing fields. If not handled properly, it can lead to data breaches, unauthorized access, or complete system compromise

Exploitation Examples

1. *Authentication Bypass*
   sql
   ' OR '1'='1
   
   Bypasses login forms by tricking the query into always evaluating as true.

2. *Data Dumping*
   sql
   ' UNION SELECT username, password FROM users--
   
   Extracts data from other database tables by modifying the result set.

3. *Database Destruction*
   sql
   '; DROP TABLE users;--
   ```
  Deletes critical database tables if executed.
   
  Consequences of SQL Injection

- Data Theft – Unauthorized access to sensitive user or business data.
- Data Loss or Corruption – Malicious users can delete or alter database contents.
- Privilege Escalation – Gaining admin access through SQL-based manipulation.
- Reputation Damage – Users may lose trust in the platform.

Prevention Measures

1. Parameterized Queries / Prepared Statements
   - PHP (PDO):
      
2. Input Validation
   - Ensure input matches expected patterns (e.g., no special characters in usernames).

3. Use of ORMs
   - Frameworks like Django ORM, Laravel Eloquent, or SQLAlchemy abstract raw queries.

4. Stored Procedures
   - Execute fixed SQL logic inside the database with parameter passing.

5. Principle of Least Privilege
   - Limit database user permissions to reduce impact if exploited.

6. Web Application Firewall (WAF)
   - Use WAFs to detect and block common SQLi payloads before reaching the app.


