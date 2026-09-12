# 🛡️ CyberGuard AI & Emergency Recovery Hub

CyberGuard AI is an intelligent cybersecurity threat detection and incident response platform tailored for both everyday users and technical evaluators. Built with a hybrid security architecture, it combines fast local Python domain heuristics with LLM reasoning via Groq and lightweight local RAG (Retrieval-Augmented Generation) to analyze phishing attempts, guide hacked account recoveries, and run PC malware diagnostics.

---

## 🇵🇰 Hackathon Context & Real-World Pakistan Impact

This project was developed as a **Mid-Week Capstone Project for the GenAI Community Program in Pakistan**.

### The Problem in Local Context
In Pakistan, digital adoption across mobile banking (Easypaisa, NayaPay, JazzCash), messaging platforms (WhatsApp), and social media has skyrocketed. However, cyber literacy remains low, leading to widespread vulnerabilities:
* **WhatsApp OTP & Identity Scams:** Non-technical users frequently fall for WhatsApp OTP forwarding scams, losing complete access to their family and business communication.
* **Localized Financial Phishing:** Fraudulent SMS messages impersonating bank alerts, lottery schemes, or utility bill discounts trick users into clicking malicious IP links.
* **Panic & Zero First-Response:** When accounts get compromised, everyday users lack immediate, non-technical, Urdu-friendly or simple English step-by-step guidance on how to lock hackers out within the first 5 critical minutes.

CyberGuard AI directly addresses this regional gap by providing a localized **First-Responder Engine** that translates complex threat analysis into actionable, non-jargon recovery playbooks.

---

## ✨ Key Features

* **🏠 Prevention Guide (Landing Hub):** Minimalist overview cards highlighting core baseline security protocols (2FA, Password Managers, Session Audits).
* **🔍 Threat Inspector:** Analyzes suspicious URLs, emails, and SMS messages using local regex heuristics (raw IPs, high-risk TLDs like `.xyz`/`.top`, `@` redirects) combined with fast Groq LLM inference.
* **🚨 RAG-Powered Recovery Assistant:** Multi-turn conversational chat that retrieves emergency lockout steps directly from a local PDF Security Manual (`cyber_security_guide.pdf`). Includes fallback logic for out-of-context queries.
* **💻 System Health Audit:** Interactive symptom checker for diagnosing PC malware indicators (high idle CPU, disabled Windows Defender, rogue browser extensions).
* **📊 Modern Dark UI:** High-contrast, dark-mode styling optimized for readability without text overlap or screen clutter.

---

## 🛠️ Tech Stack & Architecture

* **Frontend & UI:** Streamlit
* **AI Engine:** Groq API (`openai/gpt-oss-120b` / `llama-3.1-8b-instant`)
* **RAG Pipeline:** `pypdf` (Text extraction), `sentence-transformers` (`all-MiniLM-L6-v2`), `faiss-cpu` (Vector indexing)
* **Performance Optimization:** `@st.cache_resource` for one-time startup vector indexing and cached API client setup.

---

## 🚀 Getting Started

### 1. Prerequisites
* Python 3.9 or higher
* A free API key from [Groq Console](https://console.groq.com)

### 2. Installation
Clone the repository and navigate into the project directory:
```bash
git clone https://github.com/your-username/cyberguard-ai.git
cd cyberguard-ai
```

Install the required dependencies:
```bash
pip install -r requirements.txt
```

### 3. Add Security Manual PDF (Optional)
Place your reference security manual in the root directory named `cyber_security_guide.pdf`. If no PDF is present, the app automatically initializes with built-in security knowledge chunks.

### 4. Configure Secrets
Create a `.streamlit/secrets.toml` file in the project root:
```toml
GROQ_API_KEY = "gsk_your_actual_groq_api_key_here"
```
*(Alternatively, you can enter your API Key directly in the app sidebar during runtime).*

### 5. Launch the Application
```bash
streamlit run app.py
```

---

## 🎯 Mid-Week Evaluation & Pitch Highlights

* **Zero External Security API Dependency:** Avoids strict rate limits of APIs like VirusTotal while enabling contextual text scanning.
* **Optimized RAG Architecture:** Demonstrates cached vector index generation to eliminate per-query PDF processing delays.
* **Human-Centric Security:** Shifts AI from passive text summaries to active emergency incident containment.
