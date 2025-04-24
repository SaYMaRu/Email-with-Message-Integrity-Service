import streamlit as st
import os
import base64
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

# === Constants ===
USER_DIR = "users"  # Folder with key pairs per user
TOKEN_FILE = "token.json"
CREDENTIALS_FILE = "credentials.json"
SCOPES = ['https://www.googleapis.com/auth/gmail.send']

st.set_page_config(page_title="Email Integrity", page_icon="📨")
st.title("📨 Email with Message Integrity Service")

# === Key Functions ===

def load_private_key(user):
    path = os.path.join(USER_DIR, user, "private_key.pem")
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def load_public_key(user):
    path = os.path.join(USER_DIR, user, "public_key.pem")
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def sign_message(message: str, user: str) -> bytes:
    private_key = load_private_key(user)
    return private_key.sign(
        message.encode(),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )

def verify_signature(message: str, signature: bytes, user: str) -> bool:
    public_key = load_public_key(user)
    try:
        public_key.verify(
            signature,
            message.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False
# === Gmail API ===

def get_gmail_service():
    creds = None
    if os.path.exists(TOKEN_FILE):
        creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_FILE, SCOPES)
            creds = flow.run_local_server(port=0)
        with open(TOKEN_FILE, "w") as token:
            token.write(creds.to_json())
    return build("gmail", "v1", credentials=creds)

def send_email(recipient, subject, message_body, signature):
    service = get_gmail_service()
    message = MIMEMultipart()
    message["To"] = recipient
    message["Subject"] = subject
    message.attach(MIMEText("Signed message with attachments", "plain"))

    with open("message.txt", "w", encoding="utf-8") as f:
        f.write(message_body)
    with open("message.sig", "wb") as f:
        f.write(signature)

    for fname in ["message.txt", "message.sig"]:
        with open(fname, "rb") as f:
            part = MIMEBase("application", "octet-stream")
            part.set_payload(f.read())
            encoders.encode_base64(part)
            part.add_header("Content-Disposition", f"attachment; filename={fname}")
            message.attach(part)

    raw = base64.urlsafe_b64encode(message.as_bytes()).decode()
    service.users().messages().send(userId="me", body={"raw": raw}).execute()

# === Streamlit Tabs ===

tab1, tab2 = st.tabs(["✉️ Send Signed Email", "✅ Verify Signature"])

with tab1:
    st.subheader("Select Sender")
    user_list = [f.name for f in os.scandir(USER_DIR) if f.is_dir()]
    selected_user = st.selectbox("Sender Username", user_list)

    st.subheader("1️⃣ Recipient Info")
    recipient = st.text_input("Recipient Email")
    subject = st.text_input("Subject", "Signed Message")

    st.subheader("2️⃣ Message")
    message = st.text_area("Message", height=200)

    st.subheader("3️⃣ Sign and Send")
    if st.button("📤 Sign & Send Email"):
        if not all([selected_user, recipient, subject, message]):
            st.warning("Please complete all fields.")
        else:
            signature = sign_message(message, selected_user)
            send_email(recipient, subject, message, signature)
            st.success("✅ Email sent with signature!")

with tab2:
    st.subheader("Verify Signature")
    uploaded_msg = st.file_uploader("Upload Message (.txt)", type=["txt"])
    uploaded_sig = st.file_uploader("Upload Signature (.sig)", type=["sig"])
    verify_user = st.selectbox("Sender (Public Key)", user_list)

    if uploaded_msg and uploaded_sig and verify_user:
        msg = uploaded_msg.read().decode("utf-8")
        sig = uploaded_sig.read()
        if verify_signature(msg, sig, verify_user):
            st.success("✅ Signature is valid. Message is authentic.")
        else:
            st.error("❌ Invalid signature or modified message.")
