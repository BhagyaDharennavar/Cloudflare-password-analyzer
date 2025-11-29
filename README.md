# 🔐 Cloudflare-Style Password Breach & Strength Checker  
A privacy-preserving, real-time password analyzer built using Web Crypto API hashing, HaveIBeenPwned K-Anonymity breach checking, entropy estimation, and advanced pattern analysis.

This project replicates a Cloudflare-style security model and follows NIST SP 800-63B guidelines for password security. It provides an interactive tool that evaluates password strength, detects breach exposure, identifies predictable patterns, and educates users on creating stronger passwords.

---

## 📌 Overview  
This tool checks:

- Strength (with color meter)
- Entropy (bit measure)
- Whether your password appears in known breaches
- Predictable patterns attackers exploit
- Common password lists
- Keyboard sequences
- Sequential characters
- Repeated substrings
- Year/birthdate patterns
- Email/username-like patterns

All analysis happens **locally in the browser** except the K-Anonymity lookup (which only sends 5 hash characters).

---

## 🚀 Why This Project Matters  
Most “password strength checkers” only check length and character variety. They don’t catch real attacker patterns like:

- `qwerty`  
- `123456`  
- `Abc123`  
- `1999`, `2024`  
- repeated characters  
- common password dictionary  
- passwords found in data breaches  

This tool goes beyond that by simulating attacker behavior and applying real-world security heuristics.

---

## ⭐ Key Features  
### 🔐 1. Browser-Side Hashing (Web Crypto API)  
- Password never sent to any server.
- SHA-1 hash generated securely on device.
- Uses hardware-accelerated cryptography.

### 🛡 2. HIBP Breach Check (K-Anonymity)  
- Sends **first 5 characters** of SHA-1 hash only.
- Your password or full hash is never revealed.
- Shows whether the password appears in public breaches.

### 🧠 3. Entropy Estimation  
Entropy = `log2(charset_size) × length`  
Higher entropy = more secure password.

### ⚠ 4. Advanced Pattern Detection  
Detects:
- Sequential characters (`1234`, `abcd`)
- Keyboard patterns (`qwerty`, `asdfgh`)
- Repeated characters (`aaaaaa`)
- Repeated substrings (`abcabc`)
- Common passwords list (~200 entries)
- 4-digit birth years (`1999`, `2024`)
- Email/username-like passwords
- Breach flagged passwords

### 🎨 5. Visual Strength Meter  
Color-coded bar:
- Red → Weak
- Orange → Medium
- Green → Strong

### 💬 6. Smart Suggestions  
Provides tips on:
- Increasing length  
- Adding character variety  
- Removing predictable patterns  

---

## 🏗 Architecture

```
User Input
   ↓
Browser Hashes Password (SHA-1)
   ↓
Send Only First 5 Hex to HIBP (K-Anonymity)
   ↓
HIBP Returns All Possible Hash Suffixes
   ↓
Local Matching → Breach Count
   ↓
Pattern Detection → Attacker Heuristics
   ↓
Strength Meter + Warnings + Entropy + Suggestions
```

---

## 🔍 How It Works (Deep Explanation)

### 1. Web Crypto API (SHA-1 Hashing)  
Password is hashed on the client:

```js
crypto.subtle.digest("SHA-1", data)
```

- No external libraries
- No password sent to the internet
- Fast, secure, native implementation

---

### 2. K-Anonymity with HaveIBeenPwned  
Instead of sending your password, we send this:

```
first5 = SHA1(password).slice(0, 5)
```

HIBP returns hundreds of possible matches.

Your browser compares the suffix locally:

```
if (returnedSuffix === sha1.slice(5)):
    breached = true
```

Password never leaves your device.

---

### 3. Entropy Calculation  
Simple entropy model:

```
Entropy = log2(charset_size) × length
```

Charset size is based on:
- lowercase = 26  
- uppercase = 26  
- digits = 10  
- symbols ≈ 32  

---

### 4. Advanced Pattern Matching (Option B)  
Implemented patterns:

| Pattern Type | Example | Why It’s Weak |
|--------------|---------|----------------|
| Sequential | 1234, abcd | First guesses for attackers |
| Keyboard Patterns | qwerty, asdf | Auto-typed by users |
| Common Passwords | password, admin123 | Known in breach lists |
| Repeated Chars | aaaa, 1111 | Low complexity |
| Repeated Substrings | abcabc, testtest | Predictable |
| Year Pattern | 1999, 2024 | Birth years |
| Email/Username Style | john1234, abc@gmail | Often reused |

Each detected pattern reduces the password score.

---

## 🛡 Security Model  
- ✔ 100% privacy-preserving  
- ✔ No plaintext password ever transmitted  
- ✔ Only 5 SHA-1 characters shared with HIBP  
- ✔ Browser does all analysis  
- ✔ Safe for personal and enterprise demos  

---

## 🧰 Tech Stack  
- HTML  
- CSS  
- JavaScript  
- Web Crypto API  
- HaveIBeenPwned API  
- Custom pattern detection engine  

---

## 🖥 Screenshots  

### 🔴 Weak Password Detection
![Weak Password](https://github.com/BhagyaDharennavar/Cloudflare-password-analyzer/blob/main/Screenshot/Screenshot%202025-11-29%20192459.png)

---

### 🟠 Medium Password Detection
![Medium Password](https://raw.githubusercontent.com/BhagyaDharennavar/Cloudflare-password-analyzer/main/Screenshot/Medium%20password.png)

---

### 🟢 Strong Password Detection
![Strong Password](https://raw.githubusercontent.com/BhagyaDharennavar/Cloudflare-password-analyzer/main/Screenshot/Strong%20password.png)

---

### 🎹 Keyboard Pattern Detection
![Keyboard Pattern Detection](https://raw.githubusercontent.com/BhagyaDharennavar/Cloudflare-password-analyzer/main/Screenshot/Keyboard%20pattern.png)

---

### 🔢 Sequential Pattern Detection
![Sequence Pattern](https://raw.githubusercontent.com/BhagyaDharennavar/Cloudflare-password-analyzer/main/Screenshot/Sequence%20pattern.png)

---

### 📅 Year Pattern (Birth Year) Detection
![Year Detection](https://raw.githubusercontent.com/BhagyaDharennavar/Cloudflare-password-analyzer/main/Screenshot/year%20detection.png)

---

## 📂 File Structure  

```
password-checker/
│── index.html
│── style.css
│── app.js
│── README.md
```

---

## 🛠 Setup & Installation

Open directly  
Just open:

```
index.html
```
---

## 🌐 APIs Used  
### 🔸 HaveIBeenPwned API (K-Anonymity)  
```
GET https://api.pwnedpasswords.com/range/<first5hash>
```

### 🔸 Web Crypto API  
Used for hashing (SHA-1):

```
crypto.subtle.digest()
```

---

## 📊 Strength Scoring Logic  
Base score:  
- length ≥ 8  
- lowercase  
- uppercase  
- numbers  
- symbols  

Pattern penalties:  
- breach found → −2  
- common password → −2  
- sequential / repeated / keyboard patterns → −1  
- year pattern → −1  
- email-like pattern → −1  

Final score → strength meter.

---

## 🧩 Pattern Detection Logic

### Sequential  
Checks for consecutive ASCII codes:

```
a b c d
1 2 3 4
```

### Keyboard Patterns  
Matches common sequences:

```
qwerty, asdf, zxcvbn
```

### Repeated Characters  
Regex:

```
(.)\1{3,}
```

### Repeated Substrings  
Checks substring duplication like:

```
abcabc
111222
```

### Year Patterns  
Matches:

```
19xx
20xx
```

### Email/Username  
Matches:

```
john1234
example@gmail.com
``` 

---

## 👤 Author  
**Bhagya Dharennavar**  
Cybersecurity Enthusiast  
SOC | Network Security | Web Security Tools  

---

If you like this project, please ⭐ star the repository!
