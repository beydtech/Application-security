# ZAP by Checkmarx Scanning Report

ZAP by [Checkmarx](https://checkmarx.com/).


## Summary of Alerts

| Risk Level | Number of Alerts |
| --- | --- |
| High | 1 |
| Medium | 5 |
| Low | 4 |
| Informational | 4 |




## Alerts

| Name | Risk Level | Number of Instances |
| --- | --- | --- |
| SQL Injection - SQLite | High | 1 |
| Content Security Policy (CSP) Header Not Set | Medium | 71 |
| Cross-Domain Misconfiguration | Medium | 99 |
| Missing Anti-clickjacking Header | Medium | 13 |
| Session ID in URL Rewrite | Medium | 57 |
| Vulnerable JS Library | Medium | 1 |
| Cross-Domain JavaScript Source File Inclusion | Low | 98 |
| Private IP Disclosure | Low | 1 |
| Timestamp Disclosure - Unix | Low | 162 |
| X-Content-Type-Options Header Missing | Low | 57 |
| Information Disclosure - Suspicious Comments | Informational | 4 |
| Modern Web Application | Informational | 50 |
| Retrieved from Cache | Informational | 6 |
| User Agent Fuzzer | Informational | 108 |




## Alert Detail



### [ SQL Injection - SQLite ](https://www.zaproxy.org/docs/alerts/40018/)



##### High (Medium)

### Description

SQL injection may be possible.

* URL: http://127.0.0.1:3000/rest/products/search%3Fq=%2527%2528
  * Method: `GET`
  * Parameter: `q`
  * Attack: `'(`
  * Evidence: `SQLITE_ERROR`
  * Other Info: `RDBMS [SQLite] likely, given error message regular expression [SQLITE_ERROR] matched by the HTML results.
The vulnerability was detected by manipulating the parameter to cause a database error message to be returned and recognised.`

Instances: 1

### Solution

Do not trust client side input, even if there is client side validation in place.
In general, type check all data on the server side.
If the application uses JDBC, use PreparedStatement or CallableStatement, with parameters passed by '?'
If the application uses ASP, use ADO Command Objects with strong type checking and parameterized queries.
If database Stored Procedures can be used, use them.
Do *not* concatenate strings into queries in the stored procedure, or use 'exec', 'exec immediate', or equivalent functionality!
Do not create dynamic SQL queries using simple string concatenation.
Escape all data received from the client.
Apply an 'allow list' of allowed characters, or a 'deny list' of disallowed characters in user input.
Apply the principle of least privilege by using the least privileged database user possible.
In particular, avoid using the 'sa' or 'db-owner' database users. This does not eliminate SQL injection, but minimizes its impact.
Grant the minimum database access that is necessary for the application.

### Reference


* [ https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html ](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)


#### CWE Id: [ 89 ](https://cwe.mitre.org/data/definitions/89.html)


#### WASC Id: 19

#### Source ID: 1

### [ Content Security Policy (CSP) Header Not Set ](https://www.zaproxy.org/docs/alerts/10038/)



##### Medium (High)

### Description

Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

* URL: http://127.0.0.1:3000
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/ftp
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/ftp/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/ftp/coupons_2013.md.bak
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/ftp/eastere.gg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/ftp/encrypt.pyc
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/ftp/package-lock.json.bak
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/ftp/package.json.bak
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/ftp/quarantine
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/ftp/suspicious_errors.yml
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/build/routes/assets/public/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/build/routes/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/build/routes/assets/public/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/build/routes/assets/public/polyfills.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/build/routes/assets/public/runtime.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/build/routes/assets/public/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/build/routes/assets/public/vendor.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/build/routes/fileServer.js:43:13
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/build/routes/fileServer.js:59:18
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/build/routes/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/build/routes/polyfills.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/build/routes/runtime.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/build/routes/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/build/routes/vendor.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/assets/public/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/assets/public/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/assets/public/polyfills.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/assets/public/runtime.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/assets/public/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/assets/public/vendor.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/index.js:280:10
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/index.js:286:9
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/index.js:328:13
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/index.js:365:14
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/index.js:376:14
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/index.js:421:3
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/layer.js:95:5
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/polyfills.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/runtime.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/vendor.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/assets/public/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/assets/public/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/assets/public/polyfills.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/assets/public/runtime.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/assets/public/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/assets/public/vendor.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/index.js:145:39
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/polyfills.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/runtime.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/vendor.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/sitemap.xml
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMa0Ja&sid=qQfQueeEGuMz9fSKAAAE
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMa36_&sid=NqETOJGvApfzDwPvAAAG
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMa9rO&sid=oTa6XcU8QElbk3JlAAAI
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaAc-&sid=KR9yDuQDehkegzI9AAAK
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaElN&sid=5hdpYM2r_uYY0RuZAAAM
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaIvB&sid=0XSIRM6mlayVv0HdAAAO
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaK4W&sid=POCvIh_D2tHMDEM3AAAQ
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaKwW&sid=TI7jVr2R2utL-lBEAAAS
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaMx9&sid=fZyRxinHb8bY7-R3AAAU
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaOlv&sid=WIl8IfScgXpvUYLhAAAW
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaOtk&sid=46pfbogOQn9Ng9PtAAAX
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaSX2&sid=-r-PQlEWqtbpiJIWAAAa
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaTQ2&sid=bqyxUstFNLii4UyQAAAc
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``

Instances: 71

### Solution

Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

### Reference


* [ https://developer.mozilla.org/en-US/docs/Web/Security/CSP/Introducing_Content_Security_Policy ](https://developer.mozilla.org/en-US/docs/Web/Security/CSP/Introducing_Content_Security_Policy)
* [ https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html ](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
* [ https://www.w3.org/TR/CSP/ ](https://www.w3.org/TR/CSP/)
* [ https://w3c.github.io/webappsec-csp/ ](https://w3c.github.io/webappsec-csp/)
* [ https://web.dev/articles/csp ](https://web.dev/articles/csp)
* [ https://caniuse.com/#feat=contentsecuritypolicy ](https://caniuse.com/#feat=contentsecuritypolicy)
* [ https://content-security-policy.com/ ](https://content-security-policy.com/)


#### CWE Id: [ 693 ](https://cwe.mitre.org/data/definitions/693.html)


#### WASC Id: 15

#### Source ID: 3

### [ Cross-Domain Misconfiguration ](https://www.zaproxy.org/docs/alerts/10098/)



##### Medium (Medium)

### Description

Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

* URL: http://127.0.0.1:3000
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/api/Challenges/%3Fname=Score%2520Board
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/api/Quantitys/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/assets/i18n/en.json
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/assets/public/images/hackingInstructor.png
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/assets/public/images/JuiceShop_Logo.png
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/assets/public/images/products/apple_juice.jpg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/assets/public/images/products/apple_pressings.jpg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/assets/public/images/products/artwork2.jpg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/assets/public/images/products/banana_juice.jpg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/assets/public/images/products/carrot_juice.jpeg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/assets/public/images/products/eggfruit_juice.jpg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/assets/public/images/products/fan_facemask.jpg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/assets/public/images/products/fruit_press.jpg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/assets/public/images/products/green_smoothie.jpg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/assets/public/images/products/lemon_juice.jpg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/assets/public/images/products/melon_bike.jpeg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/assets/public/images/products/permafrost.jpg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/ftp
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/ftp/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/ftp/acquisitions.md
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/ftp/announcement_encrypted.md
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/ftp/coupons_2013.md.bak
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/ftp/eastere.gg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/ftp/encrypt.pyc
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/ftp/incident-support.kdbx
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/ftp/legal.md
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/ftp/package-lock.json.bak
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/ftp/package.json.bak
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/ftp/quarantine
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/ftp/quarantine/juicy_malware_linux_amd_64.url
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/ftp/quarantine/juicy_malware_linux_arm_64.url
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/ftp/quarantine/juicy_malware_macos_64.url
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/ftp/quarantine/juicy_malware_windows_64.exe.url
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/ftp/suspicious_errors.yml
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/juice-shop/build/routes/assets/public/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/juice-shop/build/routes/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/juice-shop/build/routes/assets/public/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/juice-shop/build/routes/assets/public/polyfills.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/juice-shop/build/routes/assets/public/runtime.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/juice-shop/build/routes/assets/public/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/juice-shop/build/routes/assets/public/vendor.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/juice-shop/build/routes/fileServer.js:43:13
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/juice-shop/build/routes/fileServer.js:59:18
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/juice-shop/build/routes/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/juice-shop/build/routes/polyfills.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/juice-shop/build/routes/runtime.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/juice-shop/build/routes/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/juice-shop/build/routes/vendor.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/assets/public/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/assets/public/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/assets/public/polyfills.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/assets/public/runtime.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/assets/public/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/assets/public/vendor.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/index.js:280:10
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/index.js:286:9
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/index.js:328:13
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/index.js:365:14
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/index.js:376:14
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/index.js:421:3
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/layer.js:95:5
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/polyfills.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/runtime.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/vendor.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/assets/public/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/assets/public/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/assets/public/polyfills.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/assets/public/runtime.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/assets/public/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/assets/public/vendor.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/index.js:145:39
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/polyfills.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/runtime.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/vendor.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/MaterialIcons-Regular.woff2
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/polyfills.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/rest/admin/application-configuration
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/rest/admin/application-version
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/rest/languages
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/rest/products/search%3Fq=
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/robots.txt
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/runtime.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/sitemap.xml
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/tutorial.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://127.0.0.1:3000/vendor.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`

Instances: 99

### Solution

Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

### Reference


* [ https://vulncat.fortify.com/en/detail?id=desc.config.dotnet.html5_overly_permissive_cors_policy ](https://vulncat.fortify.com/en/detail?id=desc.config.dotnet.html5_overly_permissive_cors_policy)


#### CWE Id: [ 264 ](https://cwe.mitre.org/data/definitions/264.html)


#### WASC Id: 14

#### Source ID: 3

### [ Missing Anti-clickjacking Header ](https://www.zaproxy.org/docs/alerts/10020/)



##### Medium (Medium)

### Description

The response does not protect against 'ClickJacking' attacks. It should include either Content-Security-Policy with 'frame-ancestors' directive or X-Frame-Options.

* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMa0Ja&sid=qQfQueeEGuMz9fSKAAAE
  * Method: `POST`
  * Parameter: `x-frame-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMa36_&sid=NqETOJGvApfzDwPvAAAG
  * Method: `POST`
  * Parameter: `x-frame-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMa9rO&sid=oTa6XcU8QElbk3JlAAAI
  * Method: `POST`
  * Parameter: `x-frame-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaAc-&sid=KR9yDuQDehkegzI9AAAK
  * Method: `POST`
  * Parameter: `x-frame-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaElN&sid=5hdpYM2r_uYY0RuZAAAM
  * Method: `POST`
  * Parameter: `x-frame-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaIvB&sid=0XSIRM6mlayVv0HdAAAO
  * Method: `POST`
  * Parameter: `x-frame-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaK4W&sid=POCvIh_D2tHMDEM3AAAQ
  * Method: `POST`
  * Parameter: `x-frame-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaKwW&sid=TI7jVr2R2utL-lBEAAAS
  * Method: `POST`
  * Parameter: `x-frame-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaMx9&sid=fZyRxinHb8bY7-R3AAAU
  * Method: `POST`
  * Parameter: `x-frame-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaOlv&sid=WIl8IfScgXpvUYLhAAAW
  * Method: `POST`
  * Parameter: `x-frame-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaOtk&sid=46pfbogOQn9Ng9PtAAAX
  * Method: `POST`
  * Parameter: `x-frame-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaSX2&sid=-r-PQlEWqtbpiJIWAAAa
  * Method: `POST`
  * Parameter: `x-frame-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaTQ2&sid=bqyxUstFNLii4UyQAAAc
  * Method: `POST`
  * Parameter: `x-frame-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``

Instances: 13

### Solution

Modern Web browsers support the Content-Security-Policy and X-Frame-Options HTTP headers. Ensure one of them is set on all web pages returned by your site/app.
If you expect the page to be framed only by pages on your server (e.g. it's part of a FRAMESET) then you'll want to use SAMEORIGIN, otherwise if you never expect the page to be framed, you should use DENY. Alternatively consider implementing Content Security Policy's "frame-ancestors" directive.

### Reference


* [ https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options ](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options)


#### CWE Id: [ 1021 ](https://cwe.mitre.org/data/definitions/1021.html)


#### WASC Id: 15

#### Source ID: 3

### [ Session ID in URL Rewrite ](https://www.zaproxy.org/docs/alerts/3/)



##### Medium (High)

### Description

URL rewrite is used to track user session ID. The session ID may be disclosed via cross-site referer header. In addition, the session ID might be stored in browser history or server logs.

* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMa0Jx&sid=qQfQueeEGuMz9fSKAAAE
  * Method: `GET`
  * Parameter: `sid`
  * Attack: ``
  * Evidence: `qQfQueeEGuMz9fSKAAAE`
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMa0mF&sid=qQfQueeEGuMz9fSKAAAE
  * Method: `GET`
  * Parameter: `sid`
  * Attack: ``
  * Evidence: `qQfQueeEGuMz9fSKAAAE`
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMa375&sid=NqETOJGvApfzDwPvAAAG
  * Method: `GET`
  * Parameter: `sid`
  * Attack: ``
  * Evidence: `NqETOJGvApfzDwPvAAAG`
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMa3RC&sid=NqETOJGvApfzDwPvAAAG
  * Method: `GET`
  * Parameter: `sid`
  * Attack: ``
  * Evidence: `NqETOJGvApfzDwPvAAAG`
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMa9rb&sid=oTa6XcU8QElbk3JlAAAI
  * Method: `GET`
  * Parameter: `sid`
  * Attack: ``
  * Evidence: `oTa6XcU8QElbk3JlAAAI`
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaA-i&sid=KR9yDuQDehkegzI9AAAK
  * Method: `GET`
  * Parameter: `sid`
  * Attack: ``
  * Evidence: `KR9yDuQDehkegzI9AAAK`
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaADr&sid=oTa6XcU8QElbk3JlAAAI
  * Method: `GET`
  * Parameter: `sid`
  * Attack: ``
  * Evidence: `oTa6XcU8QElbk3JlAAAI`
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaAdT&sid=KR9yDuQDehkegzI9AAAK
  * Method: `GET`
  * Parameter: `sid`
  * Attack: ``
  * Evidence: `KR9yDuQDehkegzI9AAAK`
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaAKv&sid=oTa6XcU8QElbk3JlAAAI
  * Method: `GET`
  * Parameter: `sid`
  * Attack: ``
  * Evidence: `oTa6XcU8QElbk3JlAAAI`
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaB5W&sid=KR9yDuQDehkegzI9AAAK
  * Method: `GET`
  * Parameter: `sid`
  * Attack: ``
  * Evidence: `KR9yDuQDehkegzI9AAAK`
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaElO&sid=5hdpYM2r_uYY0RuZAAAM
  * Method: `GET`
  * Parameter: `sid`
  * Attack: ``
  * Evidence: `5hdpYM2r_uYY0RuZAAAM`
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaF4Z&sid=5hdpYM2r_uYY0RuZAAAM
  * Method: `GET`
  * Parameter: `sid`
  * Attack: ``
  * Evidence: `5hdpYM2r_uYY0RuZAAAM`
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaF8z&sid=5hdpYM2r_uYY0RuZAAAM
  * Method: `GET`
  * Parameter: `sid`
  * Attack: ``
  * Evidence: `5hdpYM2r_uYY0RuZAAAM`
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaIvJ&sid=0XSIRM6mlayVv0HdAAAO
  * Method: `GET`
  * Parameter: `sid`
  * Attack: ``
  * Evidence: `0XSIRM6mlayVv0HdAAAO`
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaJ5p&sid=0XSIRM6mlayVv0HdAAAO
  * Method: `GET`
  * Parameter: `sid`
  * Attack: ``
  * Evidence: `0XSIRM6mlayVv0HdAAAO`
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaK4h&sid=POCvIh_D2tHMDEM3AAAQ
  * Method: `GET`
  * Parameter: `sid`
  * Attack: ``
  * Evidence: `POCvIh_D2tHMDEM3AAAQ`
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaKQY&sid=POCvIh_D2tHMDEM3AAAQ
  * Method: `GET`
  * Parameter: `sid`
  * Attack: ``
  * Evidence: `POCvIh_D2tHMDEM3AAAQ`
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaKwb&sid=TI7jVr2R2utL-lBEAAAS
  * Method: `GET`
  * Parameter: `sid`
  * Attack: ``
  * Evidence: `TI7jVr2R2utL-lBEAAAS`
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaL6K&sid=TI7jVr2R2utL-lBEAAAS
  * Method: `GET`
  * Parameter: `sid`
  * Attack: ``
  * Evidence: `TI7jVr2R2utL-lBEAAAS`
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaLKS&sid=TI7jVr2R2utL-lBEAAAS
  * Method: `GET`
  * Parameter: `sid`
  * Attack: ``
  * Evidence: `TI7jVr2R2utL-lBEAAAS`
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaMxR&sid=fZyRxinHb8bY7-R3AAAU
  * Method: `GET`
  * Parameter: `sid`
  * Attack: ``
  * Evidence: `fZyRxinHb8bY7-R3AAAU`
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaNJW&sid=fZyRxinHb8bY7-R3AAAU
  * Method: `GET`
  * Parameter: `sid`
  * Attack: ``
  * Evidence: `fZyRxinHb8bY7-R3AAAU`
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaNOv&sid=fZyRxinHb8bY7-R3AAAU
  * Method: `GET`
  * Parameter: `sid`
  * Attack: ``
  * Evidence: `fZyRxinHb8bY7-R3AAAU`
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaOl-&sid=WIl8IfScgXpvUYLhAAAW
  * Method: `GET`
  * Parameter: `sid`
  * Attack: ``
  * Evidence: `WIl8IfScgXpvUYLhAAAW`
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaOtn&sid=46pfbogOQn9Ng9PtAAAX
  * Method: `GET`
  * Parameter: `sid`
  * Attack: ``
  * Evidence: `46pfbogOQn9Ng9PtAAAX`
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaP3h&sid=WIl8IfScgXpvUYLhAAAW
  * Method: `GET`
  * Parameter: `sid`
  * Attack: ``
  * Evidence: `WIl8IfScgXpvUYLhAAAW`
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaPIj&sid=46pfbogOQn9Ng9PtAAAX
  * Method: `GET`
  * Parameter: `sid`
  * Attack: ``
  * Evidence: `46pfbogOQn9Ng9PtAAAX`
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaPN0&sid=46pfbogOQn9Ng9PtAAAX
  * Method: `GET`
  * Parameter: `sid`
  * Attack: ``
  * Evidence: `46pfbogOQn9Ng9PtAAAX`
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaSqc&sid=-r-PQlEWqtbpiJIWAAAa
  * Method: `GET`
  * Parameter: `sid`
  * Attack: ``
  * Evidence: `-r-PQlEWqtbpiJIWAAAa`
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaSX9&sid=-r-PQlEWqtbpiJIWAAAa
  * Method: `GET`
  * Parameter: `sid`
  * Attack: ``
  * Evidence: `-r-PQlEWqtbpiJIWAAAa`
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaTQE&sid=bqyxUstFNLii4UyQAAAc
  * Method: `GET`
  * Parameter: `sid`
  * Attack: ``
  * Evidence: `bqyxUstFNLii4UyQAAAc`
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=websocket&sid=-r-PQlEWqtbpiJIWAAAa
  * Method: `GET`
  * Parameter: `sid`
  * Attack: ``
  * Evidence: `-r-PQlEWqtbpiJIWAAAa`
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=websocket&sid=0XSIRM6mlayVv0HdAAAO
  * Method: `GET`
  * Parameter: `sid`
  * Attack: ``
  * Evidence: `0XSIRM6mlayVv0HdAAAO`
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=websocket&sid=46pfbogOQn9Ng9PtAAAX
  * Method: `GET`
  * Parameter: `sid`
  * Attack: ``
  * Evidence: `46pfbogOQn9Ng9PtAAAX`
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=websocket&sid=5hdpYM2r_uYY0RuZAAAM
  * Method: `GET`
  * Parameter: `sid`
  * Attack: ``
  * Evidence: `5hdpYM2r_uYY0RuZAAAM`
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=websocket&sid=bqyxUstFNLii4UyQAAAc
  * Method: `GET`
  * Parameter: `sid`
  * Attack: ``
  * Evidence: `bqyxUstFNLii4UyQAAAc`
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=websocket&sid=fZyRxinHb8bY7-R3AAAU
  * Method: `GET`
  * Parameter: `sid`
  * Attack: ``
  * Evidence: `fZyRxinHb8bY7-R3AAAU`
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=websocket&sid=KR9yDuQDehkegzI9AAAK
  * Method: `GET`
  * Parameter: `sid`
  * Attack: ``
  * Evidence: `KR9yDuQDehkegzI9AAAK`
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=websocket&sid=NqETOJGvApfzDwPvAAAG
  * Method: `GET`
  * Parameter: `sid`
  * Attack: ``
  * Evidence: `NqETOJGvApfzDwPvAAAG`
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=websocket&sid=oTa6XcU8QElbk3JlAAAI
  * Method: `GET`
  * Parameter: `sid`
  * Attack: ``
  * Evidence: `oTa6XcU8QElbk3JlAAAI`
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=websocket&sid=POCvIh_D2tHMDEM3AAAQ
  * Method: `GET`
  * Parameter: `sid`
  * Attack: ``
  * Evidence: `POCvIh_D2tHMDEM3AAAQ`
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=websocket&sid=qQfQueeEGuMz9fSKAAAE
  * Method: `GET`
  * Parameter: `sid`
  * Attack: ``
  * Evidence: `qQfQueeEGuMz9fSKAAAE`
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=websocket&sid=TI7jVr2R2utL-lBEAAAS
  * Method: `GET`
  * Parameter: `sid`
  * Attack: ``
  * Evidence: `TI7jVr2R2utL-lBEAAAS`
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=websocket&sid=WIl8IfScgXpvUYLhAAAW
  * Method: `GET`
  * Parameter: `sid`
  * Attack: ``
  * Evidence: `WIl8IfScgXpvUYLhAAAW`
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMa0Ja&sid=qQfQueeEGuMz9fSKAAAE
  * Method: `POST`
  * Parameter: `sid`
  * Attack: ``
  * Evidence: `qQfQueeEGuMz9fSKAAAE`
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMa36_&sid=NqETOJGvApfzDwPvAAAG
  * Method: `POST`
  * Parameter: `sid`
  * Attack: ``
  * Evidence: `NqETOJGvApfzDwPvAAAG`
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMa9rO&sid=oTa6XcU8QElbk3JlAAAI
  * Method: `POST`
  * Parameter: `sid`
  * Attack: ``
  * Evidence: `oTa6XcU8QElbk3JlAAAI`
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaAc-&sid=KR9yDuQDehkegzI9AAAK
  * Method: `POST`
  * Parameter: `sid`
  * Attack: ``
  * Evidence: `KR9yDuQDehkegzI9AAAK`
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaElN&sid=5hdpYM2r_uYY0RuZAAAM
  * Method: `POST`
  * Parameter: `sid`
  * Attack: ``
  * Evidence: `5hdpYM2r_uYY0RuZAAAM`
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaIvB&sid=0XSIRM6mlayVv0HdAAAO
  * Method: `POST`
  * Parameter: `sid`
  * Attack: ``
  * Evidence: `0XSIRM6mlayVv0HdAAAO`
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaK4W&sid=POCvIh_D2tHMDEM3AAAQ
  * Method: `POST`
  * Parameter: `sid`
  * Attack: ``
  * Evidence: `POCvIh_D2tHMDEM3AAAQ`
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaKwW&sid=TI7jVr2R2utL-lBEAAAS
  * Method: `POST`
  * Parameter: `sid`
  * Attack: ``
  * Evidence: `TI7jVr2R2utL-lBEAAAS`
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaMx9&sid=fZyRxinHb8bY7-R3AAAU
  * Method: `POST`
  * Parameter: `sid`
  * Attack: ``
  * Evidence: `fZyRxinHb8bY7-R3AAAU`
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaOlv&sid=WIl8IfScgXpvUYLhAAAW
  * Method: `POST`
  * Parameter: `sid`
  * Attack: ``
  * Evidence: `WIl8IfScgXpvUYLhAAAW`
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaOtk&sid=46pfbogOQn9Ng9PtAAAX
  * Method: `POST`
  * Parameter: `sid`
  * Attack: ``
  * Evidence: `46pfbogOQn9Ng9PtAAAX`
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaSX2&sid=-r-PQlEWqtbpiJIWAAAa
  * Method: `POST`
  * Parameter: `sid`
  * Attack: ``
  * Evidence: `-r-PQlEWqtbpiJIWAAAa`
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaTQ2&sid=bqyxUstFNLii4UyQAAAc
  * Method: `POST`
  * Parameter: `sid`
  * Attack: ``
  * Evidence: `bqyxUstFNLii4UyQAAAc`
  * Other Info: ``

Instances: 57

### Solution

For secure content, put session ID in a cookie. To be even more secure consider using a combination of cookie and URL rewrite.

### Reference


* [ https://seclists.org/webappsec/2002/q4/111 ](https://seclists.org/webappsec/2002/q4/111)


#### CWE Id: [ 598 ](https://cwe.mitre.org/data/definitions/598.html)


#### WASC Id: 13

#### Source ID: 3

### [ Vulnerable JS Library ](https://www.zaproxy.org/docs/alerts/10003/)



##### Medium (Medium)

### Description

The identified library appears to be vulnerable.

* URL: http://cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `/2.2.4/jquery.min.js`
  * Other Info: `The identified library jquery, version 2.2.4 is vulnerable.
CVE-2020-11023
CVE-2020-11022
CVE-2015-9251
CVE-2019-11358
https://github.com/jquery/jquery/issues/2432
http://blog.jquery.com/2016/01/08/jquery-2-2-and-1-12-released/
http://research.insecurelabs.org/jquery/test/
https://blog.jquery.com/2019/04/10/jquery-3-4-0-released/
https://nvd.nist.gov/vuln/detail/CVE-2019-11358
https://github.com/advisories/GHSA-rmxg-73gg-4p98
https://nvd.nist.gov/vuln/detail/CVE-2015-9251
https://github.com/jquery/jquery/commit/753d591aea698e57d6db58c9f722cd0808619b1b
https://github.com/jquery/jquery.com/issues/162
https://bugs.jquery.com/ticket/11974
https://blog.jquery.com/2020/04/10/jquery-3-5-0-released/
`

Instances: 1

### Solution

Upgrade to the latest version of the affected library.

### Reference


* [ https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/ ](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/)


#### CWE Id: [ 1395 ](https://cwe.mitre.org/data/definitions/1395.html)


#### Source ID: 3

### [ Cross-Domain JavaScript Source File Inclusion ](https://www.zaproxy.org/docs/alerts/10017/)



##### Low (Medium)

### Description

The page includes one or more script files from a third-party domain.

* URL: http://127.0.0.1:3000
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/build/routes/assets/public/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/build/routes/assets/public/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/build/routes/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/build/routes/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/build/routes/assets/public/main.js
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/build/routes/assets/public/main.js
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/build/routes/assets/public/polyfills.js
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/build/routes/assets/public/polyfills.js
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/build/routes/assets/public/runtime.js
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/build/routes/assets/public/runtime.js
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/build/routes/assets/public/styles.css
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/build/routes/assets/public/styles.css
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/build/routes/assets/public/vendor.js
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/build/routes/assets/public/vendor.js
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/build/routes/fileServer.js:43:13
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/build/routes/fileServer.js:43:13
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/build/routes/fileServer.js:59:18
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/build/routes/fileServer.js:59:18
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/build/routes/main.js
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/build/routes/main.js
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/build/routes/polyfills.js
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/build/routes/polyfills.js
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/build/routes/runtime.js
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/build/routes/runtime.js
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/build/routes/styles.css
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/build/routes/styles.css
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/build/routes/vendor.js
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/build/routes/vendor.js
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/assets/public/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/assets/public/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/assets/public/main.js
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/assets/public/main.js
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/assets/public/polyfills.js
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/assets/public/polyfills.js
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/assets/public/runtime.js
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/assets/public/runtime.js
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/assets/public/styles.css
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/assets/public/styles.css
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/assets/public/vendor.js
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/assets/public/vendor.js
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/index.js:280:10
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/index.js:280:10
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/index.js:286:9
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/index.js:286:9
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/index.js:328:13
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/index.js:328:13
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/index.js:365:14
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/index.js:365:14
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/index.js:376:14
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/index.js:376:14
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/index.js:421:3
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/index.js:421:3
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/layer.js:95:5
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/layer.js:95:5
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/main.js
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/main.js
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/polyfills.js
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/polyfills.js
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/runtime.js
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/runtime.js
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/styles.css
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/styles.css
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/vendor.js
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/vendor.js
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/assets/public/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/assets/public/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/assets/public/main.js
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/assets/public/main.js
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/assets/public/polyfills.js
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/assets/public/polyfills.js
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/assets/public/runtime.js
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/assets/public/runtime.js
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/assets/public/styles.css
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/assets/public/styles.css
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/assets/public/vendor.js
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/assets/public/vendor.js
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/index.js:145:39
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/index.js:145:39
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/main.js
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/main.js
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/polyfills.js
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/polyfills.js
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/runtime.js
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/runtime.js
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/styles.css
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/styles.css
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/vendor.js
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/vendor.js
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/sitemap.xml
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: ``
* URL: http://127.0.0.1:3000/sitemap.xml
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js"></script>`
  * Other Info: ``

Instances: 98

### Solution

Ensure JavaScript source files are loaded from only trusted sources, and the sources can't be controlled by end users of the application.

### Reference



#### CWE Id: [ 829 ](https://cwe.mitre.org/data/definitions/829.html)


#### WASC Id: 15

#### Source ID: 3

### [ Private IP Disclosure ](https://www.zaproxy.org/docs/alerts/2/)



##### Low (Medium)

### Description

A private IP (such as 10.x.x.x, 172.x.x.x, 192.168.x.x) or an Amazon EC2 private hostname (for example, ip-10-0-56-78) has been found in the HTTP response body. This information might be helpful for further attacks targeting internal systems.

* URL: http://127.0.0.1:3000/rest/admin/application-configuration
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `192.168.99.100:3000`
  * Other Info: `192.168.99.100:3000
192.168.99.100:4200
`

Instances: 1

### Solution

Remove the private IP address from the HTTP response body. For comments, use JSP/ASP/PHP comment instead of HTML/JavaScript comment which can be seen by client browsers.

### Reference


* [ https://tools.ietf.org/html/rfc1918 ](https://tools.ietf.org/html/rfc1918)


#### CWE Id: [ 497 ](https://cwe.mitre.org/data/definitions/497.html)


#### WASC Id: 13

#### Source ID: 3

### [ Timestamp Disclosure - Unix ](https://www.zaproxy.org/docs/alerts/10096/)



##### Low (Low)

### Description

A timestamp was disclosed by the application/web server. - Unix

* URL: http://127.0.0.1:3000
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1650485437`
  * Other Info: `1650485437, which evaluates to: 2022-04-20 21:10:37.`
* URL: http://127.0.0.1:3000
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1981395349`
  * Other Info: `1981395349, which evaluates to: 2032-10-14 20:35:49.`
* URL: http://127.0.0.1:3000
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `2038834951`
  * Other Info: `2038834951, which evaluates to: 2034-08-10 16:02:31.`
* URL: http://127.0.0.1:3000/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1650485437`
  * Other Info: `1650485437, which evaluates to: 2022-04-20 21:10:37.`
* URL: http://127.0.0.1:3000/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1981395349`
  * Other Info: `1981395349, which evaluates to: 2032-10-14 20:35:49.`
* URL: http://127.0.0.1:3000/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `2038834951`
  * Other Info: `2038834951, which evaluates to: 2034-08-10 16:02:31.`
* URL: http://127.0.0.1:3000/juice-shop/build/routes/assets/public/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1650485437`
  * Other Info: `1650485437, which evaluates to: 2022-04-20 21:10:37.`
* URL: http://127.0.0.1:3000/juice-shop/build/routes/assets/public/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1981395349`
  * Other Info: `1981395349, which evaluates to: 2032-10-14 20:35:49.`
* URL: http://127.0.0.1:3000/juice-shop/build/routes/assets/public/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `2038834951`
  * Other Info: `2038834951, which evaluates to: 2034-08-10 16:02:31.`
* URL: http://127.0.0.1:3000/juice-shop/build/routes/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1650485437`
  * Other Info: `1650485437, which evaluates to: 2022-04-20 21:10:37.`
* URL: http://127.0.0.1:3000/juice-shop/build/routes/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1981395349`
  * Other Info: `1981395349, which evaluates to: 2032-10-14 20:35:49.`
* URL: http://127.0.0.1:3000/juice-shop/build/routes/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `2038834951`
  * Other Info: `2038834951, which evaluates to: 2034-08-10 16:02:31.`
* URL: http://127.0.0.1:3000/juice-shop/build/routes/assets/public/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1650485437`
  * Other Info: `1650485437, which evaluates to: 2022-04-20 21:10:37.`
* URL: http://127.0.0.1:3000/juice-shop/build/routes/assets/public/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1981395349`
  * Other Info: `1981395349, which evaluates to: 2032-10-14 20:35:49.`
* URL: http://127.0.0.1:3000/juice-shop/build/routes/assets/public/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `2038834951`
  * Other Info: `2038834951, which evaluates to: 2034-08-10 16:02:31.`
* URL: http://127.0.0.1:3000/juice-shop/build/routes/assets/public/polyfills.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1650485437`
  * Other Info: `1650485437, which evaluates to: 2022-04-20 21:10:37.`
* URL: http://127.0.0.1:3000/juice-shop/build/routes/assets/public/polyfills.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1981395349`
  * Other Info: `1981395349, which evaluates to: 2032-10-14 20:35:49.`
* URL: http://127.0.0.1:3000/juice-shop/build/routes/assets/public/polyfills.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `2038834951`
  * Other Info: `2038834951, which evaluates to: 2034-08-10 16:02:31.`
* URL: http://127.0.0.1:3000/juice-shop/build/routes/assets/public/runtime.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1650485437`
  * Other Info: `1650485437, which evaluates to: 2022-04-20 21:10:37.`
* URL: http://127.0.0.1:3000/juice-shop/build/routes/assets/public/runtime.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1981395349`
  * Other Info: `1981395349, which evaluates to: 2032-10-14 20:35:49.`
* URL: http://127.0.0.1:3000/juice-shop/build/routes/assets/public/runtime.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `2038834951`
  * Other Info: `2038834951, which evaluates to: 2034-08-10 16:02:31.`
* URL: http://127.0.0.1:3000/juice-shop/build/routes/assets/public/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1650485437`
  * Other Info: `1650485437, which evaluates to: 2022-04-20 21:10:37.`
* URL: http://127.0.0.1:3000/juice-shop/build/routes/assets/public/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1981395349`
  * Other Info: `1981395349, which evaluates to: 2032-10-14 20:35:49.`
* URL: http://127.0.0.1:3000/juice-shop/build/routes/assets/public/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `2038834951`
  * Other Info: `2038834951, which evaluates to: 2034-08-10 16:02:31.`
* URL: http://127.0.0.1:3000/juice-shop/build/routes/assets/public/vendor.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1650485437`
  * Other Info: `1650485437, which evaluates to: 2022-04-20 21:10:37.`
* URL: http://127.0.0.1:3000/juice-shop/build/routes/assets/public/vendor.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1981395349`
  * Other Info: `1981395349, which evaluates to: 2032-10-14 20:35:49.`
* URL: http://127.0.0.1:3000/juice-shop/build/routes/assets/public/vendor.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `2038834951`
  * Other Info: `2038834951, which evaluates to: 2034-08-10 16:02:31.`
* URL: http://127.0.0.1:3000/juice-shop/build/routes/fileServer.js:43:13
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1650485437`
  * Other Info: `1650485437, which evaluates to: 2022-04-20 21:10:37.`
* URL: http://127.0.0.1:3000/juice-shop/build/routes/fileServer.js:43:13
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1981395349`
  * Other Info: `1981395349, which evaluates to: 2032-10-14 20:35:49.`
* URL: http://127.0.0.1:3000/juice-shop/build/routes/fileServer.js:43:13
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `2038834951`
  * Other Info: `2038834951, which evaluates to: 2034-08-10 16:02:31.`
* URL: http://127.0.0.1:3000/juice-shop/build/routes/fileServer.js:59:18
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1650485437`
  * Other Info: `1650485437, which evaluates to: 2022-04-20 21:10:37.`
* URL: http://127.0.0.1:3000/juice-shop/build/routes/fileServer.js:59:18
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1981395349`
  * Other Info: `1981395349, which evaluates to: 2032-10-14 20:35:49.`
* URL: http://127.0.0.1:3000/juice-shop/build/routes/fileServer.js:59:18
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `2038834951`
  * Other Info: `2038834951, which evaluates to: 2034-08-10 16:02:31.`
* URL: http://127.0.0.1:3000/juice-shop/build/routes/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1650485437`
  * Other Info: `1650485437, which evaluates to: 2022-04-20 21:10:37.`
* URL: http://127.0.0.1:3000/juice-shop/build/routes/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1981395349`
  * Other Info: `1981395349, which evaluates to: 2032-10-14 20:35:49.`
* URL: http://127.0.0.1:3000/juice-shop/build/routes/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `2038834951`
  * Other Info: `2038834951, which evaluates to: 2034-08-10 16:02:31.`
* URL: http://127.0.0.1:3000/juice-shop/build/routes/polyfills.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1650485437`
  * Other Info: `1650485437, which evaluates to: 2022-04-20 21:10:37.`
* URL: http://127.0.0.1:3000/juice-shop/build/routes/polyfills.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1981395349`
  * Other Info: `1981395349, which evaluates to: 2032-10-14 20:35:49.`
* URL: http://127.0.0.1:3000/juice-shop/build/routes/polyfills.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `2038834951`
  * Other Info: `2038834951, which evaluates to: 2034-08-10 16:02:31.`
* URL: http://127.0.0.1:3000/juice-shop/build/routes/runtime.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1650485437`
  * Other Info: `1650485437, which evaluates to: 2022-04-20 21:10:37.`
* URL: http://127.0.0.1:3000/juice-shop/build/routes/runtime.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1981395349`
  * Other Info: `1981395349, which evaluates to: 2032-10-14 20:35:49.`
* URL: http://127.0.0.1:3000/juice-shop/build/routes/runtime.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `2038834951`
  * Other Info: `2038834951, which evaluates to: 2034-08-10 16:02:31.`
* URL: http://127.0.0.1:3000/juice-shop/build/routes/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1650485437`
  * Other Info: `1650485437, which evaluates to: 2022-04-20 21:10:37.`
* URL: http://127.0.0.1:3000/juice-shop/build/routes/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1981395349`
  * Other Info: `1981395349, which evaluates to: 2032-10-14 20:35:49.`
* URL: http://127.0.0.1:3000/juice-shop/build/routes/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `2038834951`
  * Other Info: `2038834951, which evaluates to: 2034-08-10 16:02:31.`
* URL: http://127.0.0.1:3000/juice-shop/build/routes/vendor.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1650485437`
  * Other Info: `1650485437, which evaluates to: 2022-04-20 21:10:37.`
* URL: http://127.0.0.1:3000/juice-shop/build/routes/vendor.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1981395349`
  * Other Info: `1981395349, which evaluates to: 2032-10-14 20:35:49.`
* URL: http://127.0.0.1:3000/juice-shop/build/routes/vendor.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `2038834951`
  * Other Info: `2038834951, which evaluates to: 2034-08-10 16:02:31.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/assets/public/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1650485437`
  * Other Info: `1650485437, which evaluates to: 2022-04-20 21:10:37.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/assets/public/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1981395349`
  * Other Info: `1981395349, which evaluates to: 2032-10-14 20:35:49.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/assets/public/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `2038834951`
  * Other Info: `2038834951, which evaluates to: 2034-08-10 16:02:31.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1650485437`
  * Other Info: `1650485437, which evaluates to: 2022-04-20 21:10:37.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1981395349`
  * Other Info: `1981395349, which evaluates to: 2032-10-14 20:35:49.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `2038834951`
  * Other Info: `2038834951, which evaluates to: 2034-08-10 16:02:31.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/assets/public/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1650485437`
  * Other Info: `1650485437, which evaluates to: 2022-04-20 21:10:37.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/assets/public/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1981395349`
  * Other Info: `1981395349, which evaluates to: 2032-10-14 20:35:49.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/assets/public/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `2038834951`
  * Other Info: `2038834951, which evaluates to: 2034-08-10 16:02:31.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/assets/public/polyfills.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1650485437`
  * Other Info: `1650485437, which evaluates to: 2022-04-20 21:10:37.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/assets/public/polyfills.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1981395349`
  * Other Info: `1981395349, which evaluates to: 2032-10-14 20:35:49.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/assets/public/polyfills.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `2038834951`
  * Other Info: `2038834951, which evaluates to: 2034-08-10 16:02:31.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/assets/public/runtime.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1650485437`
  * Other Info: `1650485437, which evaluates to: 2022-04-20 21:10:37.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/assets/public/runtime.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1981395349`
  * Other Info: `1981395349, which evaluates to: 2032-10-14 20:35:49.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/assets/public/runtime.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `2038834951`
  * Other Info: `2038834951, which evaluates to: 2034-08-10 16:02:31.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/assets/public/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1650485437`
  * Other Info: `1650485437, which evaluates to: 2022-04-20 21:10:37.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/assets/public/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1981395349`
  * Other Info: `1981395349, which evaluates to: 2032-10-14 20:35:49.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/assets/public/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `2038834951`
  * Other Info: `2038834951, which evaluates to: 2034-08-10 16:02:31.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/assets/public/vendor.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1650485437`
  * Other Info: `1650485437, which evaluates to: 2022-04-20 21:10:37.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/assets/public/vendor.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1981395349`
  * Other Info: `1981395349, which evaluates to: 2032-10-14 20:35:49.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/assets/public/vendor.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `2038834951`
  * Other Info: `2038834951, which evaluates to: 2034-08-10 16:02:31.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/index.js:280:10
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1650485437`
  * Other Info: `1650485437, which evaluates to: 2022-04-20 21:10:37.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/index.js:280:10
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1981395349`
  * Other Info: `1981395349, which evaluates to: 2032-10-14 20:35:49.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/index.js:280:10
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `2038834951`
  * Other Info: `2038834951, which evaluates to: 2034-08-10 16:02:31.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/index.js:286:9
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1650485437`
  * Other Info: `1650485437, which evaluates to: 2022-04-20 21:10:37.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/index.js:286:9
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1981395349`
  * Other Info: `1981395349, which evaluates to: 2032-10-14 20:35:49.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/index.js:286:9
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `2038834951`
  * Other Info: `2038834951, which evaluates to: 2034-08-10 16:02:31.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/index.js:328:13
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1650485437`
  * Other Info: `1650485437, which evaluates to: 2022-04-20 21:10:37.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/index.js:328:13
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1981395349`
  * Other Info: `1981395349, which evaluates to: 2032-10-14 20:35:49.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/index.js:328:13
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `2038834951`
  * Other Info: `2038834951, which evaluates to: 2034-08-10 16:02:31.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/index.js:365:14
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1650485437`
  * Other Info: `1650485437, which evaluates to: 2022-04-20 21:10:37.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/index.js:365:14
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1981395349`
  * Other Info: `1981395349, which evaluates to: 2032-10-14 20:35:49.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/index.js:365:14
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `2038834951`
  * Other Info: `2038834951, which evaluates to: 2034-08-10 16:02:31.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/index.js:376:14
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1650485437`
  * Other Info: `1650485437, which evaluates to: 2022-04-20 21:10:37.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/index.js:376:14
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1981395349`
  * Other Info: `1981395349, which evaluates to: 2032-10-14 20:35:49.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/index.js:376:14
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `2038834951`
  * Other Info: `2038834951, which evaluates to: 2034-08-10 16:02:31.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/index.js:421:3
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1650485437`
  * Other Info: `1650485437, which evaluates to: 2022-04-20 21:10:37.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/index.js:421:3
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1981395349`
  * Other Info: `1981395349, which evaluates to: 2032-10-14 20:35:49.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/index.js:421:3
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `2038834951`
  * Other Info: `2038834951, which evaluates to: 2034-08-10 16:02:31.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/layer.js:95:5
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1650485437`
  * Other Info: `1650485437, which evaluates to: 2022-04-20 21:10:37.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/layer.js:95:5
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1981395349`
  * Other Info: `1981395349, which evaluates to: 2032-10-14 20:35:49.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/layer.js:95:5
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `2038834951`
  * Other Info: `2038834951, which evaluates to: 2034-08-10 16:02:31.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1650485437`
  * Other Info: `1650485437, which evaluates to: 2022-04-20 21:10:37.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1981395349`
  * Other Info: `1981395349, which evaluates to: 2032-10-14 20:35:49.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `2038834951`
  * Other Info: `2038834951, which evaluates to: 2034-08-10 16:02:31.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/polyfills.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1650485437`
  * Other Info: `1650485437, which evaluates to: 2022-04-20 21:10:37.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/polyfills.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1981395349`
  * Other Info: `1981395349, which evaluates to: 2032-10-14 20:35:49.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/polyfills.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `2038834951`
  * Other Info: `2038834951, which evaluates to: 2034-08-10 16:02:31.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/runtime.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1650485437`
  * Other Info: `1650485437, which evaluates to: 2022-04-20 21:10:37.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/runtime.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1981395349`
  * Other Info: `1981395349, which evaluates to: 2032-10-14 20:35:49.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/runtime.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `2038834951`
  * Other Info: `2038834951, which evaluates to: 2034-08-10 16:02:31.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1650485437`
  * Other Info: `1650485437, which evaluates to: 2022-04-20 21:10:37.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1981395349`
  * Other Info: `1981395349, which evaluates to: 2032-10-14 20:35:49.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `2038834951`
  * Other Info: `2038834951, which evaluates to: 2034-08-10 16:02:31.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/vendor.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1650485437`
  * Other Info: `1650485437, which evaluates to: 2022-04-20 21:10:37.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/vendor.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1981395349`
  * Other Info: `1981395349, which evaluates to: 2032-10-14 20:35:49.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/vendor.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `2038834951`
  * Other Info: `2038834951, which evaluates to: 2034-08-10 16:02:31.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/assets/public/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1650485437`
  * Other Info: `1650485437, which evaluates to: 2022-04-20 21:10:37.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/assets/public/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1981395349`
  * Other Info: `1981395349, which evaluates to: 2032-10-14 20:35:49.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/assets/public/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `2038834951`
  * Other Info: `2038834951, which evaluates to: 2034-08-10 16:02:31.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1650485437`
  * Other Info: `1650485437, which evaluates to: 2022-04-20 21:10:37.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1981395349`
  * Other Info: `1981395349, which evaluates to: 2032-10-14 20:35:49.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `2038834951`
  * Other Info: `2038834951, which evaluates to: 2034-08-10 16:02:31.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/assets/public/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1650485437`
  * Other Info: `1650485437, which evaluates to: 2022-04-20 21:10:37.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/assets/public/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1981395349`
  * Other Info: `1981395349, which evaluates to: 2032-10-14 20:35:49.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/assets/public/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `2038834951`
  * Other Info: `2038834951, which evaluates to: 2034-08-10 16:02:31.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/assets/public/polyfills.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1650485437`
  * Other Info: `1650485437, which evaluates to: 2022-04-20 21:10:37.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/assets/public/polyfills.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1981395349`
  * Other Info: `1981395349, which evaluates to: 2032-10-14 20:35:49.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/assets/public/polyfills.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `2038834951`
  * Other Info: `2038834951, which evaluates to: 2034-08-10 16:02:31.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/assets/public/runtime.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1650485437`
  * Other Info: `1650485437, which evaluates to: 2022-04-20 21:10:37.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/assets/public/runtime.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1981395349`
  * Other Info: `1981395349, which evaluates to: 2032-10-14 20:35:49.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/assets/public/runtime.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `2038834951`
  * Other Info: `2038834951, which evaluates to: 2034-08-10 16:02:31.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/assets/public/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1650485437`
  * Other Info: `1650485437, which evaluates to: 2022-04-20 21:10:37.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/assets/public/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1981395349`
  * Other Info: `1981395349, which evaluates to: 2032-10-14 20:35:49.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/assets/public/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `2038834951`
  * Other Info: `2038834951, which evaluates to: 2034-08-10 16:02:31.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/assets/public/vendor.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1650485437`
  * Other Info: `1650485437, which evaluates to: 2022-04-20 21:10:37.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/assets/public/vendor.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1981395349`
  * Other Info: `1981395349, which evaluates to: 2032-10-14 20:35:49.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/assets/public/vendor.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `2038834951`
  * Other Info: `2038834951, which evaluates to: 2034-08-10 16:02:31.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/index.js:145:39
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1650485437`
  * Other Info: `1650485437, which evaluates to: 2022-04-20 21:10:37.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/index.js:145:39
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1981395349`
  * Other Info: `1981395349, which evaluates to: 2032-10-14 20:35:49.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/index.js:145:39
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `2038834951`
  * Other Info: `2038834951, which evaluates to: 2034-08-10 16:02:31.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1650485437`
  * Other Info: `1650485437, which evaluates to: 2022-04-20 21:10:37.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1981395349`
  * Other Info: `1981395349, which evaluates to: 2032-10-14 20:35:49.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `2038834951`
  * Other Info: `2038834951, which evaluates to: 2034-08-10 16:02:31.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/polyfills.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1650485437`
  * Other Info: `1650485437, which evaluates to: 2022-04-20 21:10:37.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/polyfills.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1981395349`
  * Other Info: `1981395349, which evaluates to: 2032-10-14 20:35:49.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/polyfills.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `2038834951`
  * Other Info: `2038834951, which evaluates to: 2034-08-10 16:02:31.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/runtime.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1650485437`
  * Other Info: `1650485437, which evaluates to: 2022-04-20 21:10:37.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/runtime.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1981395349`
  * Other Info: `1981395349, which evaluates to: 2032-10-14 20:35:49.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/runtime.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `2038834951`
  * Other Info: `2038834951, which evaluates to: 2034-08-10 16:02:31.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1650485437`
  * Other Info: `1650485437, which evaluates to: 2022-04-20 21:10:37.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1981395349`
  * Other Info: `1981395349, which evaluates to: 2032-10-14 20:35:49.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `2038834951`
  * Other Info: `2038834951, which evaluates to: 2034-08-10 16:02:31.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/vendor.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1650485437`
  * Other Info: `1650485437, which evaluates to: 2022-04-20 21:10:37.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/vendor.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1981395349`
  * Other Info: `1981395349, which evaluates to: 2032-10-14 20:35:49.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/vendor.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `2038834951`
  * Other Info: `2038834951, which evaluates to: 2034-08-10 16:02:31.`
* URL: http://127.0.0.1:3000/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1734944650`
  * Other Info: `1734944650, which evaluates to: 2024-12-23 10:04:10.`
* URL: http://127.0.0.1:3000/rest/admin/application-configuration
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1969196030`
  * Other Info: `1969196030, which evaluates to: 2032-05-26 15:53:50.`
* URL: http://127.0.0.1:3000/rest/admin/application-configuration
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1970691216`
  * Other Info: `1970691216, which evaluates to: 2032-06-12 23:13:36.`
* URL: http://127.0.0.1:3000/rest/products/search%3Fq=
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1969196030`
  * Other Info: `1969196030, which evaluates to: 2032-05-26 15:53:50.`
* URL: http://127.0.0.1:3000/rest/products/search%3Fq=
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1970691216`
  * Other Info: `1970691216, which evaluates to: 2032-06-12 23:13:36.`
* URL: http://127.0.0.1:3000/sitemap.xml
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1650485437`
  * Other Info: `1650485437, which evaluates to: 2022-04-20 21:10:37.`
* URL: http://127.0.0.1:3000/sitemap.xml
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1981395349`
  * Other Info: `1981395349, which evaluates to: 2032-10-14 20:35:49.`
* URL: http://127.0.0.1:3000/sitemap.xml
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `2038834951`
  * Other Info: `2038834951, which evaluates to: 2034-08-10 16:02:31.`
* URL: http://127.0.0.1:3000/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1650485437`
  * Other Info: `1650485437, which evaluates to: 2022-04-20 21:10:37.`
* URL: http://127.0.0.1:3000/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1680327869`
  * Other Info: `1680327869, which evaluates to: 2023-04-01 06:44:29.`
* URL: http://127.0.0.1:3000/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1701244813`
  * Other Info: `1701244813, which evaluates to: 2023-11-29 09:00:13.`
* URL: http://127.0.0.1:3000/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1818181818`
  * Other Info: `1818181818, which evaluates to: 2027-08-13 19:30:18.`
* URL: http://127.0.0.1:3000/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1839622642`
  * Other Info: `1839622642, which evaluates to: 2028-04-17 23:17:22.`
* URL: http://127.0.0.1:3000/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1863874346`
  * Other Info: `1863874346, which evaluates to: 2029-01-23 15:52:26.`
* URL: http://127.0.0.1:3000/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1917098446`
  * Other Info: `1917098446, which evaluates to: 2030-10-01 16:20:46.`
* URL: http://127.0.0.1:3000/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1981395349`
  * Other Info: `1981395349, which evaluates to: 2032-10-14 20:35:49.`
* URL: http://127.0.0.1:3000/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `2033195021`
  * Other Info: `2033195021, which evaluates to: 2034-06-06 09:23:41.`
* URL: http://127.0.0.1:3000/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `2038834951`
  * Other Info: `2038834951, which evaluates to: 2034-08-10 16:02:31.`

Instances: 162

### Solution

Manually confirm that the timestamp data is not sensitive, and that the data cannot be aggregated to disclose exploitable patterns.

### Reference


* [ https://cwe.mitre.org/data/definitions/200.html ](https://cwe.mitre.org/data/definitions/200.html)


#### CWE Id: [ 497 ](https://cwe.mitre.org/data/definitions/497.html)


#### WASC Id: 13

#### Source ID: 3

### [ X-Content-Type-Options Header Missing ](https://www.zaproxy.org/docs/alerts/10021/)



##### Low (Medium)

### Description

The Anti-MIME-Sniffing header X-Content-Type-Options was not set to 'nosniff'. This allows older versions of Internet Explorer and Chrome to perform MIME-sniffing on the response body, potentially causing the response body to be interpreted and displayed as a content type other than the declared content type. Current (early 2014) and legacy versions of Firefox will use the declared content type (if one is set), rather than performing MIME-sniffing.

* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMa0Jx&sid=qQfQueeEGuMz9fSKAAAE
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMa0mF&sid=qQfQueeEGuMz9fSKAAAE
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMa2U9
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMa375&sid=NqETOJGvApfzDwPvAAAG
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMa3RC&sid=NqETOJGvApfzDwPvAAAG
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMa9EA
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMa9rb&sid=oTa6XcU8QElbk3JlAAAI
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaA-i&sid=KR9yDuQDehkegzI9AAAK
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaADO
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaADr&sid=oTa6XcU8QElbk3JlAAAI
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaAdT&sid=KR9yDuQDehkegzI9AAAK
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaAKv&sid=oTa6XcU8QElbk3JlAAAI
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaB5W&sid=KR9yDuQDehkegzI9AAAK
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaElO&sid=5hdpYM2r_uYY0RuZAAAM
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaEUN
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaF4Z&sid=5hdpYM2r_uYY0RuZAAAM
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaF8z&sid=5hdpYM2r_uYY0RuZAAAM
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaIbA
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaIvJ&sid=0XSIRM6mlayVv0HdAAAO
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaJ5p&sid=0XSIRM6mlayVv0HdAAAO
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaJcn
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaK4h&sid=POCvIh_D2tHMDEM3AAAQ
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaKat
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaKQY&sid=POCvIh_D2tHMDEM3AAAQ
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaKwb&sid=TI7jVr2R2utL-lBEAAAS
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaL6K&sid=TI7jVr2R2utL-lBEAAAS
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaLKS&sid=TI7jVr2R2utL-lBEAAAS
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaMdw
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaMxR&sid=fZyRxinHb8bY7-R3AAAU
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaNJW&sid=fZyRxinHb8bY7-R3AAAU
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaNOv&sid=fZyRxinHb8bY7-R3AAAU
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaO8h
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaOl-&sid=WIl8IfScgXpvUYLhAAAW
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaOPs
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaOtn&sid=46pfbogOQn9Ng9PtAAAX
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaP3h&sid=WIl8IfScgXpvUYLhAAAW
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaPIj&sid=46pfbogOQn9Ng9PtAAAX
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaPN0&sid=46pfbogOQn9Ng9PtAAAX
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaSBo
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaSqc&sid=-r-PQlEWqtbpiJIWAAAa
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaSX9&sid=-r-PQlEWqtbpiJIWAAAa
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaT2F
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaTQE&sid=bqyxUstFNLii4UyQAAAc
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMZ_pU
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMa0Ja&sid=qQfQueeEGuMz9fSKAAAE
  * Method: `POST`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMa36_&sid=NqETOJGvApfzDwPvAAAG
  * Method: `POST`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMa9rO&sid=oTa6XcU8QElbk3JlAAAI
  * Method: `POST`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaAc-&sid=KR9yDuQDehkegzI9AAAK
  * Method: `POST`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaElN&sid=5hdpYM2r_uYY0RuZAAAM
  * Method: `POST`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaIvB&sid=0XSIRM6mlayVv0HdAAAO
  * Method: `POST`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaK4W&sid=POCvIh_D2tHMDEM3AAAQ
  * Method: `POST`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaKwW&sid=TI7jVr2R2utL-lBEAAAS
  * Method: `POST`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaMx9&sid=fZyRxinHb8bY7-R3AAAU
  * Method: `POST`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaOlv&sid=WIl8IfScgXpvUYLhAAAW
  * Method: `POST`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaOtk&sid=46pfbogOQn9Ng9PtAAAX
  * Method: `POST`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaSX2&sid=-r-PQlEWqtbpiJIWAAAa
  * Method: `POST`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaTQ2&sid=bqyxUstFNLii4UyQAAAc
  * Method: `POST`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`

Instances: 57

### Solution

Ensure that the application/web server sets the Content-Type header appropriately, and that it sets the X-Content-Type-Options header to 'nosniff' for all web pages.
If possible, ensure that the end user uses a standards-compliant and modern web browser that does not perform MIME-sniffing at all, or that can be directed by the web application/web server to not perform MIME-sniffing.

### Reference


* [ https://learn.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/compatibility/gg622941(v=vs.85) ](https://learn.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/compatibility/gg622941(v=vs.85))
* [ https://owasp.org/www-community/Security_Headers ](https://owasp.org/www-community/Security_Headers)


#### CWE Id: [ 693 ](https://cwe.mitre.org/data/definitions/693.html)


#### WASC Id: 15

#### Source ID: 3

### [ Information Disclosure - Suspicious Comments ](https://www.zaproxy.org/docs/alerts/10027/)



##### Informational (Low)

### Description

The response appears to contain suspicious comments which may help an attacker.

* URL: http://127.0.0.1:3000/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `query`
  * Other Info: `The following pattern was used: \bQUERY\b and was detected in likely comment: "//owasp.org' target='_blank'>Open Worldwide Application Security Project (OWASP)</a> and is developed and maintained by voluntee", see evidence field for the suspicious comment/snippet.`
* URL: http://127.0.0.1:3000/tutorial.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `query`
  * Other Info: `The following pattern was used: \bQUERY\b and was detected in likely comment: "//w.soundcloud.com/player/?url=https%3A//api.soundcloud.com/tracks/771984076&amp;color=%23ff5500&amp;auto&lowbar;play=true&amp;h", see evidence field for the suspicious comment/snippet.`
* URL: http://127.0.0.1:3000/vendor.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Query`
  * Other Info: `The following pattern was used: \bQUERY\b and was detected in likely comment: "//www.w3.org/2000/svg" viewBox="0 0 512 512"><path d="M0 256C0 397.4 114.6 512 256 512s256-114.6 256-256S397.4 0 256 0S0 114.6 0", see evidence field for the suspicious comment/snippet.`
* URL: http://cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Db`
  * Other Info: `The following pattern was used: \bDB\b and was detected in likely comment: "//,sb={},tb={},ub="*/".concat("*"),vb=d.createElement("a");vb.href=jb.href;function wb(a){return function(b,c){"string"!=typeof ", see evidence field for the suspicious comment/snippet.`

Instances: 4

### Solution

Remove all comments that return information that may help an attacker and fix any underlying problems they refer to.

### Reference



#### CWE Id: [ 615 ](https://cwe.mitre.org/data/definitions/615.html)


#### WASC Id: 13

#### Source ID: 3

### [ Modern Web Application ](https://www.zaproxy.org/docs/alerts/10109/)



##### Informational (Medium)

### Description

The application appears to be a modern web application. If you need to explore it automatically then the Ajax Spider may well be more effective than the standard one.

* URL: http://127.0.0.1:3000
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: http://127.0.0.1:3000/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: http://127.0.0.1:3000/ftp/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<a href="">ftp</a>`
  * Other Info: `Links have been found that do not have traditional href attributes, which is an indication that this is a modern web application.`
* URL: http://127.0.0.1:3000/juice-shop/build/routes/assets/public/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: http://127.0.0.1:3000/juice-shop/build/routes/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: http://127.0.0.1:3000/juice-shop/build/routes/assets/public/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: http://127.0.0.1:3000/juice-shop/build/routes/assets/public/polyfills.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: http://127.0.0.1:3000/juice-shop/build/routes/assets/public/runtime.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: http://127.0.0.1:3000/juice-shop/build/routes/assets/public/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: http://127.0.0.1:3000/juice-shop/build/routes/assets/public/vendor.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: http://127.0.0.1:3000/juice-shop/build/routes/fileServer.js:43:13
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: http://127.0.0.1:3000/juice-shop/build/routes/fileServer.js:59:18
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: http://127.0.0.1:3000/juice-shop/build/routes/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: http://127.0.0.1:3000/juice-shop/build/routes/polyfills.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: http://127.0.0.1:3000/juice-shop/build/routes/runtime.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: http://127.0.0.1:3000/juice-shop/build/routes/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: http://127.0.0.1:3000/juice-shop/build/routes/vendor.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/assets/public/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/assets/public/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/assets/public/polyfills.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/assets/public/runtime.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/assets/public/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/assets/public/vendor.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/index.js:280:10
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/index.js:286:9
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/index.js:328:13
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/index.js:365:14
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/index.js:376:14
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/index.js:421:3
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/layer.js:95:5
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/polyfills.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/runtime.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/express/lib/router/vendor.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/assets/public/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/assets/public/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/assets/public/polyfills.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/assets/public/runtime.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/assets/public/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/assets/public/vendor.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/index.js:145:39
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/polyfills.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/runtime.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: http://127.0.0.1:3000/juice-shop/node_modules/serve-index/vendor.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: http://127.0.0.1:3000/sitemap.xml
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`

Instances: 50

### Solution

This is an informational alert and so no changes are required.

### Reference




#### Source ID: 3

### [ Retrieved from Cache ](https://www.zaproxy.org/docs/alerts/10050/)



##### Informational (Medium)

### Description

The content was retrieved from a shared cache. If the response data is sensitive, personal or user-specific, this may result in sensitive information being leaked. In some cases, this may even result in a user gaining complete control of the session of another user, depending on the configuration of the caching components in use in their environment. This is primarily an issue where caching servers such as "proxy" caches are configured on the local network. This configuration is typically found in corporate or educational environments, for instance.

* URL: http://cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Age: 1138300`
  * Other Info: `The presence of the 'Age' header indicates that a HTTP/1.1 compliant caching server is in use.`
* URL: http://cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Age: 1138338`
  * Other Info: `The presence of the 'Age' header indicates that a HTTP/1.1 compliant caching server is in use.`
* URL: http://cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Age: 1534758`
  * Other Info: `The presence of the 'Age' header indicates that a HTTP/1.1 compliant caching server is in use.`
* URL: http://cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Age: 1534796`
  * Other Info: `The presence of the 'Age' header indicates that a HTTP/1.1 compliant caching server is in use.`
* URL: http://cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Age: 3716064`
  * Other Info: `The presence of the 'Age' header indicates that a HTTP/1.1 compliant caching server is in use.`
* URL: http://cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Age: 3716102`
  * Other Info: `The presence of the 'Age' header indicates that a HTTP/1.1 compliant caching server is in use.`

Instances: 6

### Solution

Validate that the response does not contain sensitive, personal or user-specific information. If it does, consider the use of the following HTTP response headers, to limit, or prevent the content being stored and retrieved from the cache by another user:
Cache-Control: no-cache, no-store, must-revalidate, private
Pragma: no-cache
Expires: 0
This configuration directs both HTTP 1.0 and HTTP 1.1 compliant caching servers to not store the response, and to not retrieve the response (without validation) from the cache, in response to a similar request.

### Reference


* [ https://tools.ietf.org/html/rfc7234 ](https://tools.ietf.org/html/rfc7234)
* [ https://tools.ietf.org/html/rfc7231 ](https://tools.ietf.org/html/rfc7231)
* [ https://www.rfc-editor.org/rfc/rfc9110.html ](https://www.rfc-editor.org/rfc/rfc9110.html)



#### Source ID: 3

### [ User Agent Fuzzer ](https://www.zaproxy.org/docs/alerts/10104/)



##### Informational (Medium)

### Description

Check for differences in response based on fuzzed User Agent (eg. mobile sites, access as a Search Engine Crawler). Compares the response statuscode and the hashcode of the response body with the original response.

* URL: http://127.0.0.1:3000/assets
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/assets
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/assets
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/assets
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/assets
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/assets
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/assets
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/assets
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/assets
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/assets
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/assets
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/assets
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/assets/i18n
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/assets/i18n
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/assets/i18n
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/assets/i18n
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/assets/i18n
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/assets/i18n
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/assets/i18n
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/assets/i18n
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/assets/i18n
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/assets/i18n
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/assets/i18n
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/assets/i18n
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/assets/public
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/assets/public
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/assets/public
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/assets/public
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/assets/public
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/assets/public
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/assets/public
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/assets/public
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/assets/public
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/assets/public
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/assets/public
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/assets/public
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/assets/public/images
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/assets/public/images
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/assets/public/images
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/assets/public/images
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/assets/public/images
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/assets/public/images
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/assets/public/images
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/assets/public/images
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/assets/public/images
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/assets/public/images
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/assets/public/images
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/assets/public/images
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/assets/public/images/products
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/assets/public/images/products
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/assets/public/images/products
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/assets/public/images/products
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/assets/public/images/products
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/assets/public/images/products
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/assets/public/images/products
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/assets/public/images/products
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/assets/public/images/products
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/assets/public/images/products
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/assets/public/images/products
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/assets/public/images/products
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaT2F
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaT2F
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaT2F
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaT2F
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaT2F
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaT2F
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaT2F
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaT2F
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaT2F
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaT2F
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaT2F
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaT2F
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaTQE&sid=bqyxUstFNLii4UyQAAAc
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaTQE&sid=bqyxUstFNLii4UyQAAAc
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaTQE&sid=bqyxUstFNLii4UyQAAAc
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaTQE&sid=bqyxUstFNLii4UyQAAAc
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaTQE&sid=bqyxUstFNLii4UyQAAAc
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaTQE&sid=bqyxUstFNLii4UyQAAAc
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaTQE&sid=bqyxUstFNLii4UyQAAAc
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaTQE&sid=bqyxUstFNLii4UyQAAAc
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaTQE&sid=bqyxUstFNLii4UyQAAAc
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaTQE&sid=bqyxUstFNLii4UyQAAAc
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaTQE&sid=bqyxUstFNLii4UyQAAAc
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaTQE&sid=bqyxUstFNLii4UyQAAAc
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=websocket&sid=bqyxUstFNLii4UyQAAAc
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=websocket&sid=bqyxUstFNLii4UyQAAAc
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=websocket&sid=bqyxUstFNLii4UyQAAAc
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=websocket&sid=bqyxUstFNLii4UyQAAAc
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=websocket&sid=bqyxUstFNLii4UyQAAAc
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=websocket&sid=bqyxUstFNLii4UyQAAAc
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=websocket&sid=bqyxUstFNLii4UyQAAAc
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=websocket&sid=bqyxUstFNLii4UyQAAAc
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=websocket&sid=bqyxUstFNLii4UyQAAAc
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=websocket&sid=bqyxUstFNLii4UyQAAAc
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=websocket&sid=bqyxUstFNLii4UyQAAAc
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=websocket&sid=bqyxUstFNLii4UyQAAAc
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaTQ2&sid=bqyxUstFNLii4UyQAAAc
  * Method: `POST`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaTQ2&sid=bqyxUstFNLii4UyQAAAc
  * Method: `POST`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaTQ2&sid=bqyxUstFNLii4UyQAAAc
  * Method: `POST`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaTQ2&sid=bqyxUstFNLii4UyQAAAc
  * Method: `POST`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaTQ2&sid=bqyxUstFNLii4UyQAAAc
  * Method: `POST`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaTQ2&sid=bqyxUstFNLii4UyQAAAc
  * Method: `POST`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaTQ2&sid=bqyxUstFNLii4UyQAAAc
  * Method: `POST`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaTQ2&sid=bqyxUstFNLii4UyQAAAc
  * Method: `POST`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaTQ2&sid=bqyxUstFNLii4UyQAAAc
  * Method: `POST`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaTQ2&sid=bqyxUstFNLii4UyQAAAc
  * Method: `POST`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaTQ2&sid=bqyxUstFNLii4UyQAAAc
  * Method: `POST`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:3000/socket.io/%3FEIO=4&transport=polling&t=PcMaTQ2&sid=bqyxUstFNLii4UyQAAAc
  * Method: `POST`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
  * Other Info: ``

Instances: 108

### Solution



### Reference


* [ https://owasp.org/wstg ](https://owasp.org/wstg)



#### Source ID: 1


