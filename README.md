# APPLICATION SECURITY
QUESTION:Research and explain the concept of SQL injection in the context of web application 
security. Provide examples of how SQL injection attacks can be exploited and discuss the 
potential consequences. Describe preventive measures that developers can implement to 
protect against SQL injection vulnerabilities.

ANSWER;
Research on SQL injection
The concept of SQL Injection (SQLi) is a type of cyber attack that allows an attacker to interfere with the queries that an application makes to its database. It occurs when user input is improperly sanitized and directly included in SQL statements.
How it owrks in webapplication: How it Works:  
Web applications often take user input (like login forms, search bars) and use it in SQL queries. If the input isn't properly validated, an attacker can insert malicious SQL code to manipulate the database.

Example:
A vulnerable login query:
sql
SELECT * FROM users WHERE username = 'admin' AND password = '1234';
If not protected, an attacker could enter:
- Username: admin' --
- Password: anything
Which changes the query to:
sql
SELECT * FROM users WHERE username = 'admin' --' AND password = 'anything';
The -- comments out the rest, bypassing password checking.

Consequences of SQL Injection:
- Bypassing authentication
- Viewing or modifying sensitive data
- Deleting or corrupting data
- Gaining full control of the server
  
Preventive Measures
1. Use Prepared Statements / Parameterized Queries
   - Ensures user inputs are treated as data, not code.
   - Example in Python (using SQLite):
     python
     cursor.execute("SELECT * FROM users WHERE username=? AND password=?", (user, pwd))
     

2. Input Validation
   - Allow only expected characters (e.g., for emails, numbers, etc.).
   - Reject input containing suspicious SQL keywords (SELECT, DROP, ', --, etc.)

3. Escaping User Input
   - Sanitize inputs using functions specific to the language/database (e.g., mysqli_real_escape_string in PHP).

4. Use ORM Tools
   - Frameworks like Django, SQLAlchemy, or Hibernate automatically handle safe queries.

5. Least Privilege Principle
   - Avoid giving the app’s database user full admin rights.

6. Web Application Firewalls (WAF)
   - Can detect and block SQLi attempts before they reach your app.

7. Regular Security Testing
   - Use tools like OWASP ZAP, Burp Suite, or sqlmap for vulnerability assessment.
   
   QUESTION 2

Write a Python script that demonstrates a simple cross-site scripting (XSS) attack. 
Provide a brief explanation of what cross-site scripting is and how it can be exploited. 
Execute the script against a vulnerable web application (you can create a basic web 
application for this purpose) and demonstrate the impact of the XSS attack. Explain the 
countermeasures that can be implemented to mitigate XSS vulnerabilities. 
