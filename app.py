import streamlit as st
import json
import re
import os
from groq import Groq
from pypdf import PdfReader
from sentence_transformers import SentenceTransformer
import faiss
import numpy as np

# 1. Page Setup
st.set_page_config(
    page_title="CyberGuard AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# 2. Restored Modern Dark Theme CSS (High Contrast & Clear Inputs)
st.markdown("""
<style>
    /* Global App Canvas (Dark Background) */
    .stApp {
        background-color: #0F172A;
        color: #F8FAFC;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    }
    
    /* Header Styling */
    .brand-title {
        font-size: 2.2rem;
        font-weight: 800;
        color: #F8FAFC;
        letter-spacing: -0.02em;
        margin-bottom: 4px;
    }
    .brand-subtitle {
        font-size: 1.0rem;
        color: #94A3B8;
        margin-bottom: 25px;
    }

    /* Minimalist Card Box (Dark Glassmorphism) */
    .feature-card {
        background: #1E293B;
        border: 1px solid #334155;
        border-radius: 12px;
        padding: 20px;
        margin-bottom: 20px;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.3);
    }
    .card-title {
        font-size: 1.1rem;
        font-weight: 700;
        color: #38BDF8;
        margin-bottom: 8px;
    }
    .card-desc {
        font-size: 0.9rem;
        color: #CBD5E1;
        line-height: 1.5;
    }

    /* Fix Navigation Tabs (High Contrast Visibility) */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
        background-color: #1E293B;
        padding: 8px;
        border-radius: 10px;
    }
    .stTabs [data-baseweb="tab"] {
        height: 45px;
        white-space: pre-wrap;
        background-color: transparent;
        border-radius: 8px;
        color: #94A3B8 !important;
        font-weight: 600;
    }
    .stTabs [aria-selected="true"] {
        background-color: #334155 !important;
        color: #38BDF8 !important;
    }

    /* Fix Input Fields & Chat Text Colors */
    .stTextInput input, .stTextArea textarea, .stChatInput input {
        background-color: #1E293B !important;
        color: #F8FAFC !important;
        border: 1px solid #475569 !important;
        border-radius: 8px;
    }
    
    /* Sidebar Styling */
    section[data-testid="stSidebar"] {
        background-color: #1E293B;
        border-right: 1px solid #334155;
    }
</style>
""", unsafe_allow_html=True)

MODEL_NAME = "openai/gpt-oss-120b"

# API Key Handling
api_key_from_secrets = st.secrets.get("GROQ_API_KEY", "")
with st.sidebar:
    st.markdown("### ⚙️ Engine Settings")
    if api_key_from_secrets:
        groq_api_key = api_key_from_secrets
        st.success("API Key Loaded", icon="✅")
    else:
        groq_api_key = st.text_input("Enter Groq API Key:", type="password")

client = Groq(api_key=groq_api_key) if groq_api_key else None

# 3. One-Time Cached RAG Initialization
@st.cache_resource(show_spinner="Loading Security Knowledge Base...")
def initialize_rag():
    pdf_filename = "cyber_security_guide.pdf"
    chunks = []
    
    if os.path.exists(pdf_filename):
        reader = PdfReader(pdf_filename)
        raw_text = ""
        for page in reader.pages:
            t = page.extract_text()
            if t: raw_text += t + "\n"
        chunk_size = 400
        for i in range(0, len(raw_text), chunk_size):
            chunks.append(raw_text[i:i+chunk_size])
    else:
        chunks = [
            "WhatsApp Security: Enable 2-Step Verification PIN immediately. Never share SMS OTP with anyone.",
            "Gmail Security: Remove unknown logged-in devices under Google Account -> Security -> Recent Activity.",
            "Phishing Detection: Beware of urgent messages asking for verification on non-official domains or raw IP links."
        ]
    
    embedder = SentenceTransformer('all-MiniLM-L6-v2')
    embeddings = embedder.encode(chunks)
    
    dimension = embeddings.shape[1]
    index = faiss.IndexFlatL2(dimension)
    index.add(np.array(embeddings).astype('float32'))
    
    return embedder, index, chunks

embedder, vector_index, pdf_chunks = initialize_rag()

def query_rag(query):
    query_vector = embedder.encode([query])
    distances, indices = vector_index.search(np.array(query_vector).astype('float32'), k=2)
    matched = []
    for dist, idx in zip(distances[0], indices[0]):
        if dist < 1.3:
            matched.append(pdf_chunks[idx])
    return "\n".join(matched) if matched else None

def get_concise_response(system_prompt, user_messages):
    messages = [{"role": "system", "content": system_prompt}] + user_messages
    response = client.chat.completions.create(
        model=MODEL_NAME,
        messages=messages,
        temperature=0.2
    )
    return response.choices[0].message.content

# Session State for Clean Conversations
if "detector_messages" not in st.session_state:
    st.session_state.detector_messages = []
if "recovery_messages" not in st.session_state:
    st.session_state.recovery_messages = []

# --- Header ---
st.markdown('<div class="brand-title">🛡️ CyberGuard AI</div>', unsafe_allow_html=True)
st.markdown('<div class="brand-subtitle">Intelligent Threat Prevention & Emergency Recovery Engine</div>', unsafe_allow_html=True)

if not client:
    st.info("👈 Please enter your Groq API Key in the sidebar to activate the AI platform.")
    st.stop()

# --- Main Navigation Tabs ---
tab_home, tab_scanner, tab_recovery, tab_audit = st.tabs([
    "🏠 Prevention Guide", 
    "🔍 Threat Scanner", 
    "🚨 Recovery Assistant", 
    "💻 System Health Audit"
])

# ==========================================
# DEFAULT PAGE: TAB HOME (PREVENTION & OVERVIEW)
# ==========================================
with tab_home:
    st.markdown("### 🛡️ Core Steps to Protect Your Accounts")
    st.caption("Baseline protocols to secure your accounts before an attack occurs.")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("""
        <div class="feature-card">
            <div class="card-title">1. Enable 2-Factor Auth</div>
            <div class="card-desc">
                Enable 2FA (Authenticator App / SMS) on WhatsApp, Gmail, and Social Media to block 99% of unauthorized logins.
            </div>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown("""
        <div class="feature-card">
            <div class="card-title">2. Use Password Managers</div>
            <div class="card-desc">
                Avoid password reuse across platforms. Use Bitwarden or 1Password to generate strong unique security keys.
            </div>
        </div>
        """, unsafe_allow_html=True)

    with col3:
        st.markdown("""
        <div class="feature-card">
            <div class="card-title">3. Audit Active Devices</div>
            <div class="card-desc">
                Review logged-in sessions in WhatsApp settings and Google Account monthly. Revoke unfamiliar devices immediately.
            </div>
        </div>
        """, unsafe_allow_html=True)

    st.divider()
    
    st.markdown("### 🚀 Module Overview")
    
    col_a, col_b, col_c = st.columns(3)
    with col_a:
        st.markdown("""
        **🔍 Threat Scanner**  
        Paste any suspicious link, SMS, or email to get instant risk scoring and phishing analysis.
        """)
    with col_b:
        st.markdown("""
        **🚨 Recovery Assistant**  
        Conversational RAG bot that guides you step-by-step if your WhatsApp, Gmail, or accounts are compromised.
        """)
    with col_c:
        st.markdown("""
        **💻 System Health Audit**  
        Check computer symptoms to diagnose malware infections or unauthorized background activity.
        """)

# ==========================================
# TAB 1: THREAT SCANNER (CONVERSATIONAL)
# ==========================================
with tab_scanner:
    st.markdown("#### 🔍 Real-Time Threat & Phishing Inspector")
    st.caption("Paste a link, SMS, or email body to evaluate potential scam indicators.")
    
    for msg in st.session_state.detector_messages:
        with st.chat_message(msg["role"]):
            st.write(msg["content"])
            
    if prompt := st.chat_input("Paste URL or suspicious text here..."):
        st.session_state.detector_messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.write(prompt)
            
        system_prompt = """
        You are a concise Cybersecurity Scanner. 
        Analyze the input for phishing or malware.
        Format response strictly as:
        - **Threat Level:** Safe / Low / Medium / High / Critical
        - **Category:** Phishing / Scam / Safe
        - **Why:** 2 short bullet points explaining why.
        - **Action:** 1-2 clear bullet points.
        Keep total output under 80 words. No long explanations.
        """
        
        with st.chat_message("assistant"):
            with st.spinner("Analyzing threat..."):
                reply = get_concise_response(system_prompt, st.session_state.detector_messages)
                st.write(reply)
                st.session_state.detector_messages.append({"role": "assistant", "content": reply})

# ==========================================
# TAB 2: RECOVERY ASSISTANT (CONVERSATIONAL RAG)
# ==========================================
with tab_recovery:
    st.markdown("#### 🚨 RAG-Powered Incident Recovery Assistant")
    st.caption("Ask questions about compromised accounts. Answers reference the PDF manual first.")
    
    if st.button("Clear Chat History", type="secondary"):
        st.session_state.recovery_messages = []
        st.rerun()

    for msg in st.session_state.recovery_messages:
        with st.chat_message(msg["role"]):
            st.write(msg["content"])
            
    if user_query := st.chat_input("e.g., My WhatsApp account was hacked today, what should I do?"):
        st.session_state.recovery_messages.append({"role": "user", "content": user_query})
        with st.chat_message("user"):
            st.write(user_query)
            
        retrieved_context = query_rag(user_query)
        
        if retrieved_context:
            system_prompt = f"""
            You are CyberGuard Support Specialist. 
            Answer strictly using the retrieved PDF context below.
            Prefix response with: "📄 **From Security Manual:**"
            Context: {retrieved_context}
            Rule: Provide step-by-step instructions under 100 words.
            """
        else:
            system_prompt = """
            You are CyberGuard Support Specialist. 
            The PDF manual does not contain specific info on this query.
            Prefix response with: "⚠️ *Info not in PDF manual. General steps:* "
            Rule: Provide clear emergency recovery steps under 100 words.
            """
            
        with st.chat_message("assistant"):
            with st.spinner("Retrieving guide..."):
                reply = get_concise_response(system_prompt, st.session_state.recovery_messages)
                st.write(reply)
                st.session_state.recovery_messages.append({"role": "assistant", "content": reply})

# ==========================================
# TAB 3: SYSTEM HEALTH AUDIT
# ==========================================
with tab_audit:
    st.markdown("#### 💻 PC / Laptop Malware Diagnostic")
    st.caption("Select observed symptoms to evaluate if your device is compromised.")
    
    c1 = st.checkbox("High CPU or RAM usage when idle")
    c2 = st.checkbox("Browser redirects, unknown extensions, or pop-ups")
    c3 = st.checkbox("Windows Defender or Antivirus turned off automatically")
    c4 = st.checkbox("Terminal or Command Prompt windows flash briefly on startup")
    
    selected_symptoms = []
    if c1: selected_symptoms.append("High idle CPU")
    if c2: selected_symptoms.append("Browser pop-ups/extensions")
    if c3: selected_symptoms.append("Disabled antivirus")
    if c4: selected_symptoms.append("Terminal window flashes")
    
    if st.button("Run Quick Diagnostic", type="primary"):
        if selected_symptoms:
            sys_prompt = "You are a PC Security Specialist. Give a 1-sentence risk rating and 3 concise cleanup steps. Keep total text under 80 words."
            user_msg = [{"role": "user", "content": f"Symptoms: {', '.join(selected_symptoms)}"}]
            with st.spinner("Evaluating symptoms..."):
                st.markdown(get_concise_response(sys_prompt, user_msg))
        else:
            st.success("✅ No threat symptoms selected. System appears healthy!")
