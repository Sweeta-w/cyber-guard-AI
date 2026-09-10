import streamlit as st
import json
import re
from groq import Groq

# Page Configuration
st.set_page_config(
    page_title="CyberGuard AI & Recovery Hub",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for UI polish
st.markdown("""
<style>
    .main-header {
        font-size: 2.2rem;
        font-weight: 700;
        color: #1E293B;
        margin-bottom: 0px;
    }
    .sub-header {
        font-size: 1.0rem;
        color: #64748B;
        margin-bottom: 25px;
    }
    .stCard {
        background-color: #F8FAFC;
        padding: 20px;
        border-radius: 10px;
        border: 1px solid #E2E8F0;
        margin-bottom: 15px;
    }
    .risk-badge-critical {
        background-color: #FEE2E2;
        color: #991B1B;
        padding: 6px 12px;
        border-radius: 6px;
        font-weight: 600;
    }
    .risk-badge-high {
        background-color: #FFEDD5;
        color: #9A3412;
        padding: 6px 12px;
        border-radius: 6px;
        font-weight: 600;
    }
    .risk-badge-medium {
        background-color: #FEF3C7;
        color: #92400E;
        padding: 6px 12px;
        border-radius: 6px;
        font-weight: 600;
    }
    .risk-badge-low {
        background-color: #DCFCE7;
        color: #166534;
        padding: 6px 12px;
        border-radius: 6px;
        font-weight: 600;
    }
</style>
""", unsafe_allow_html=unsafe_allow_html)

# Sidebar Configuration
with st.sidebar:
    st.image("https://img.icons8.com/color/96/shield--v1.png", width=64)
    st.title("CyberGuard AI")
    st.markdown("**Version:** 1.0.0")
    st.markdown("**Engine:** Groq (Llama-3.3-70b)")
    st.divider()
    
    # API Key Input Handling
    api_key_from_secrets = st.secrets.get("GROQ_API_KEY", "")
    if api_key_from_secrets:
        groq_api_key = api_key_from_secrets
        st.success("✅ Groq API Key loaded from Secrets")
    else:
        groq_api_key = st.text_input("Enter Groq API Key:", type="password", help="Get your key from console.groq.com")
        if not groq_api_key:
            st.warning("⚠️ Please provide a Groq API Key to proceed.")

    st.divider()
    st.markdown("### Quick Emergency Help")
    st.info("If your bank details or primary email have been stolen, disconnect your Wi-Fi immediately and call your bank's helpline.")

# Initialize Groq Client
client = Groq(api_key=groq_api_key) if groq_api_key else None

# --- Helper Functions ---
def extract_url_heuristics(text):
    """Local Python heuristic checks for suspicious URL patterns."""
    findings = []
    
    # Extract URLs from text
    urls = re.findall(r'https?://[^\s]+', text)
    if not urls:
        urls = re.findall(r'www\.[^\s]+', text)
        
    for url in urls:
        # Check IP address usage
        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
            findings.append("Uses raw IP address instead of a standard domain name.")
        # Check suspicious TLDs
        suspicious_tlds = ['.xyz', '.top', '.work', '.cc', '.tk', '.ml', '.ga', '.cf', '.gq', '.zip', '.mov']
        if any(url.lower().endswith(tld) or tld + "/" in url.lower() for tld in suspicious_tlds):
            findings.append("Uses a high-risk suspicious top-level domain (TLD).")
        # Check excessive length
        if len(url) > 70:
            findings.append("URL length is unusually long (>70 characters).")
        # Check '@' symbol redirect trick
        if "@" in url:
            findings.append("Contains '@' symbol, often used to bypass browser URL checks.")
        # Check excessive subdomains/hyphens
        if url.count('-') > 3:
            findings.append("Multiple hyphens detected in domain name.")
        if url.count('.') > 4:
            findings.append("Excessive subdomains present.")
            
    return findings, urls

def analyze_threat_with_groq(user_input, heuristics):
    """Passes user input and local heuristics to Groq for structured JSON risk assessment."""
    system_prompt = """
    You are CyberGuard AI, an elite cybersecurity threat analyst.
    Analyze the user's input (suspicious link, email, SMS, or scam message) alongside pre-detected heuristic findings.
    
    Your task is to provide a comprehensive security evaluation.
    MUST respond strictly in valid JSON format with no markdown wrappers outside the JSON:
    {
        "risk_level": "Low" | "Medium" | "High" | "Critical",
        "threat_type": "Phishing" | "Financial Scam" | "Malware Link" | "Social Engineering" | "Safe / Legitimate",
        "confidence_score": 85,
        "summary": "Short 1-2 sentence executive summary of the threat.",
        "reasons": [
            "Specific reason 1 detailing why this is suspicious or safe.",
            "Specific reason 2."
        ],
        "tactics_detected": [
            "Urgency / Fear tactic",
            "Brand Impersonation"
        ],
        "immediate_actions": [
            "Do not click any links or open attachments.",
            "Report and block the sender."
        ]
    }
    """
    
    prompt = f"""User Input to Analyze:
{user_input}

Pre-extracted Heuristic Flags:
{json.dumps(heuristics)}"""
    
    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt}
        ],
        temperature=0.1,
        response_format={"type": "json_object"}
    )
    return json.loads(response.choices[0].message.content)

def generate_account_recovery_guide(platform, situation, extra_context):
    """Generates step-by-step account recovery guidance."""
    system_prompt = """
    You are an Emergency Incident Response Specialist.
    A non-technical user has had their account compromised or locked out.
    Provide an extremely clear, reassuring, zero-jargon, step-by-step recovery guide.
    Structure your response using clean Markdown formatting:
    
    ### 🚨 Emergency Response Checklist
    #### Phase 1: First 5 Minutes (Immediate Lockout & Containment)
    - [ ] Step 1
    - [ ] Step 2
    
    #### Phase 2: Next 24 Hours (Recovery & Support Escalation)
    - Step 1
    - Step 2
    
    #### Phase 3: Post-Incident Security Hardening
    - Bullet points on securing the account long-term.
    """
    
    user_prompt = f"Platform/Service: {platform}
Situation: {situation}
Additional Context: {extra_context}"
    
    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ],
        temperature=0.2
    )
    return response.choices[0].message.content

def analyze_pc_health(symptoms_list):
    """Generates diagnostic feedback for PC/Laptop health."""
    system_prompt = """
    You are a PC Malware & Security Specialist.
    Analyze the user-reported symptoms on their PC/Laptop and determine the likely threat level.
    Provide actionable, non-destructive troubleshooting steps for non-technical users.
    
    Structure your response with:
    1. **Estimated Threat Rating** (Clean / Suspicious / Likely Infected / Severe Breach)
    2. **Analysis of Symptoms** (Why these symptoms occur)
    3. **Step-by-Step Cleanup Protocol** (Safe Mode, Defender Scan, Task Scheduler check, Rogue Browser Extensions)
    4. **When to Seek Professional Repair**
    """
    
    user_prompt = f"Reported PC Symptoms:
- " + "
- ".join(symptoms_list)
    
    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ],
        temperature=0.2
    )
    return response.choices[0].message.content

# --- Main App Header ---
st.markdown('<div class="main-header">🛡️ CyberGuard AI & Recovery Hub</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-header">Intelligent Threat Detection • Emergency Account Recovery • PC Safety Audit</div>', unsafe_allow_html=True)

if not client:
    st.warning("👈 Please enter your **Groq API Key** in the sidebar to activate the platform.")
    st.stop()

# --- Tab Layout ---
tab1, tab2, tab3, tab4 = st.tabs([
    "🔍 Threat Detector", 
    "🚨 Hacked Account Recovery", 
    "💻 PC / Laptop Health Audit", 
    "📊 Prevention & Safety Scorecard"
])

# ==========================================
# TAB 1: THREAT DETECTOR
# ==========================================
with tab1:
    st.subheader("Analyze Suspicious Links, Emails, or SMS")
    st.write("Paste suspicious content below. CyberGuard AI will scan link structures and evaluate scam indicators.")
    
    # Sample Test Inputs Expander
    with st.expander("🧪 Need test samples? Click to copy demo scenarios"):
        st.code("Urgency Scam: URGENT: Your bank account is locked due to suspicious activity. Verify immediately at http://192.168.1.55/login-verify-account-security-update.xyz to prevent total lockout.", language="text")
        st.code("Package Tracking Phishing: Your parcel delivery failed today. Track and reschedule your shipment now at http://express-logistics-tracking-update.top/package/89421", language="text")

    user_input = st.text_area("Paste URL, email body, or message text:", height=130, placeholder="e.g., Dear user, your account has been suspended. Click http://...")
    
    if st.button("🔍 Analyze Threat Now", type="primary", use_container_width=True):
        if user_input.strip():
            with st.spinner("Analyzing message context & running heuristic checks..."):
                heuristics, detected_urls = extract_url_heuristics(user_input)
                result = analyze_threat_with_groq(user_input, heuristics)
                
                risk = result.get("risk_level", "Low")
                threat_type = result.get("threat_type", "Unknown")
                confidence = result.get("confidence_score", 0)
                
                st.divider()
                
                # Header Metrics
                m_col1, m_col2, m_col3 = st.columns(3)
                with m_col1:
                    if risk == "Critical":
                        st.markdown('### Threat Level: <span class="risk-badge-critical">CRITICAL</span>', unsafe_allow_html=True)
                    elif risk == "High":
                        st.markdown('### Threat Level: <span class="risk-badge-high">HIGH</span>', unsafe_allow_html=True)
                    elif risk == "Medium":
                        st.markdown('### Threat Level: <span class="risk-badge-medium">MEDIUM</span>', unsafe_allow_html=True)
                    else:
                        st.markdown('### Threat Level: <span class="risk-badge-low">LOW / SAFE</span>', unsafe_allow_html=True)
                with m_col2:
                    st.metric("Threat Category", threat_type)
                with m_col3:
                    st.metric("AI Confidence Score", f"{confidence}%")
                
                st.markdown(f"**Executive Summary:** {result.get('summary', '')}")
                st.write("")
                
                # Breakdown Columns
                c1, c2 = st.columns(2)
                with c1:
                    st.markdown("### ⚠️ Why It's Dangerous / Suspicious")
                    for reason in result.get("reasons", []):
                        st.write(f"- {reason}")
                        
                    if result.get("tactics_detected"):
                        st.markdown("**Social Engineering Tactics Detected:**")
                        for tactic in result.get("tactics_detected", []):
                            st.write(f"  • *{tactic}*")

                with c2:
                    st.markdown("### 🛡️ Recommended Immediate Actions")
                    for action in result.get("immediate_actions", []):
                        st.write(f"- {action}")
                        
                    if heuristics:
                        st.markdown("**Local Python Heuristic Flags:**")
                        for h in heuristics:
                            st.write(f"  🚩 {h}")
        else:
            st.warning("Please paste some text or a URL to analyze.")

# ==========================================
# TAB 2: HACKED ACCOUNT RECOVERY
# ==========================================
with tab2:
    st.subheader("Hacked Account Step-by-Step Emergency Guide")
    st.write("Select the compromised service and situation to get an immediate, plain-English recovery playbook.")
    
    col_a, col_b = st.columns(2)
    with col_a:
        platform = st.selectbox(
            "Select Compromised Platform:",
            ["WhatsApp", "Gmail / Google Account", "Instagram / Facebook", "Banking / Payment App (Easypaisa/NayaPay/Bank)", "Primary Email Address"]
        )
    with col_b:
        situation = st.selectbox(
            "What best describes your situation?",
            [
                "I entered my password on a suspicious phishing link",
                "Suddenly logged out & password was changed by hacker",
                "Received unexpected 2FA OTP codes on my phone",
                "Contacts are receiving scam messages sent from my account",
                "Lost phone with logged-in accounts"
            ]
        )
        
    extra_context = st.text_input("Additional details (optional):", placeholder="e.g., Hacker changed the recovery email address to an unknown domain.")
    
    if st.button("🚨 Generate Emergency Recovery Plan", type="primary"):
        with st.spinner("Generating emergency response checklist..."):
            recovery_guide = generate_account_recovery_guide(platform, situation, extra_context)
            st.markdown(recovery_guide)

# ==========================================
# TAB 3: PC / LAPTOP HEALTH AUDIT
# ==========================================
with tab3:
    st.subheader("PC / Laptop Security Symptom Diagnostic")
    st.write("Check any unusual behavior your computer is currently exhibiting:")
    
    sym1 = st.checkbox("System is unusually slow or CPU/Disk usage is at 100% when idle")
    sym2 = st.checkbox("Unknown browser extensions, default search engine, or pop-ups appeared automatically")
    sym3 = st.checkbox("Windows Defender, Firewall, or Antivirus is disabled and won't turn back on")
    sym4 = st.checkbox("Command prompt or terminal windows flash briefly on screen upon startup")
    sym5 = st.checkbox("Friends or colleagues report receiving automated spam/emails sent from my computer")
    sym6 = st.checkbox("Files have turned into shortcut icons or have strange file extensions")
    
    selected_symptoms = []
    if sym1: selected_symptoms.append("High idle CPU/Disk usage")
    if sym2: selected_symptoms.append("Unauthorized browser changes & pop-ups")
    if sym3: selected_symptoms.append("Disabled antivirus / firewall")
    if sym4: selected_symptoms.append("Brief terminal window flashes on boot")
    if sym5: selected_symptoms.append("Outbound spam sent from local machine")
    if sym6: selected_symptoms.append("Files converted to shortcuts / corrupted extensions")
    
    if st.button("💻 Run PC Health Diagnostic", type="primary"):
        if not selected_symptoms:
            st.success("✅ No threat symptoms selected! Your computer appears healthy based on checked parameters.")
        else:
            with st.spinner("Analyzing symptom combination..."):
                pc_analysis = analyze_pc_health(selected_symptoms)
                st.markdown(pc_analysis)

# ==========================================
# TAB 4: PREVENTION & HYGIENE SCORECARD
# ==========================================
with tab4:
    st.subheader("Personal Cyber Safety Scorecard")
    st.write("Evaluate your daily digital security habits to calculate your Cyber Safety Index.")
    
    q1 = st.checkbox("I use unique, complex passwords for every major account (or use a Password Manager).")
    q2 = st.checkbox("I have Two-Factor Authentication (2FA/MFA) enabled on WhatsApp, Google, and Social Media.")
    q3 = st.checkbox("My computer operating system, smartphone, and web browsers are up to date.")
    q4 = st.checkbox("I never download pirated software, cracked apps, or attachments from unknown emails.")
    q5 = st.checkbox("I regularly check active logged-in devices in my Google/WhatsApp settings.")
    
    score = sum([q1, q2, q3, q4, q5]) * 20
    
    st.divider()
    res_col1, res_col2 = st.columns([1, 2])
    
    with res_col1:
        st.metric("Your Cyber Safety Index", f"{score}%")
        if score == 100:
            st.balloons()
            st.success("🏆 Excellent Security Hygiene!")
        elif score >= 60:
            st.info("⚠️ Moderate Protection Level")
        else:
            st.error("🚨 High Vulnerability Risk")
            
    with res_col2:
        st.markdown("### Recommendations to Reach 100%:")
        if not q1:
            st.write("- **Install a Password Manager:** Stop reusing passwords. Use tools like Bitwarden or 1Password.")
        if not q2:
            st.write("- **Turn on 2FA:** Enable App-based Authenticator (e.g., Google Authenticator) rather than SMS where possible.")
        if not q3:
            st.write("- **Enable Automatic Updates:** Keep your OS and browsers updated to patch known vulnerabilities.")
        if not q4:
            st.write("- **Avoid Cracks/KMS:** Pirated software is the #1 vector for infostealer malware.")
        if not q5:
            st.write("- **Audit Sessions:** Go to WhatsApp Settings -> Linked Devices and remove unfamiliar sessions.")
