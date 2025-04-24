# 📨 Email with Message Integrity Service (Multi-User)

A Streamlit web app that simulates an email system with **digital signature support**, allowing users to:

👉 Sign messages using RSA  
👉 Send signed messages via Gmail (OAuth2)  
👉 Verify the integrity of messages received  
👉 Support multiple users with individual key pairs

---

## 💠 Technologies Used

- **Python**
- **Streamlit** – for web UI  
- **Cryptography** – for RSA & SHA-256 digital signatures  
- **Gmail API (OAuth2)** – for sending real emails  
- **Google-auth / google-api-python-client**

---

## 📁 Project Structure

```
Email-with-Message-Integrity-Service/
├── app.py                  ← Streamlit web app
├── keygen.py         ← Generate keys for multiple users
├── users/                  ← Folder containing all user key folders
│   ├── Gong/
│   │   ├── private_key.pem
│   │   └── public_key.pem
│   └── Earth/
│       ├── ...
├── credentials.json        ← Gmail OAuth2 credentials
├── token.json              ← Auto-generated after first login
├── requirements.txt
└── README.md
```

---

## 🔐 Setup: Generate Key Pairs for Users

Edit the list of users in `keygen.py`, then run:

```bash
python keygen.py
```

This will create RSA key pairs for each user under `users/<username>/`

---

## ☁️ Setup: Gmail API (One-time)

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a project
3. Enable **Gmail API**
4. Create **OAuth2 Client ID** (type: Desktop app)
5. Download `credentials.json` and place it in the project folder

> On first use, the app will open a browser for Gmail login

---

## 🚀 Run the Web App

```bash
streamlit run app.py
```

---

## ✉️ How It Works

### 🔹 Send Tab

1. Select sender (user)
2. Type a message
3. App signs the message with that user’s private key
4. Sends email via Gmail with `.txt` and `.sig` attached

### 🔹 Verify Tab

1. Upload message `.txt` and signature `.sig`
2. Select the sender user (public key)
3. App verifies that the signature matches the message

---

## ✅ Features

- Multi-user key support (each user has their own key pair)
- Real message signing & verifying
- Gmail OAuth2 for sending signed messages
- Local verification without internet
- Simple UI built with Streamlit

---

## ⚠️ Limitations & Future Work

- Receiver must manually upload files to verify
- No encryption, only integrity check
- Future ideas:
  - Auto-verify signature when reading
  - QR code verification
  - Encrypted message + signature bundle

---

## 📬 Credits

Developed for ITCS461_Computer and Communication Security
Mahidol University, April 2025
