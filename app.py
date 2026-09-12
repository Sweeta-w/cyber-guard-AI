import streamlit as st
import json
import re
import os
from groq import Groq
from pypdf import PdfReader
from sentence_transformers import SentenceTransformer
import faiss
import numpy as np

# 1. Page Configuration
st.set_page_config(
    page_title="CyberGuard AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# 2. Minimalist Custom CSS
st.markdown("""
<style>
    /* Global Minimal Theme */
    .stApp {
        background-color: #FAFAFA;
    }
    .main-title {
        font-size: 1.8rem;
        font-weight: 700;
        color: #0F172A;
        margin-bottom: 2px;
    }
    .sub-title {
        font-size: 0.95rem;
        color: #64748B;
        margin-bottom: 20px;
    }
    /* Clean Sidebar */
    section[data-testid="stSidebar"] {
        background-color: #FFFFFF;
        border-right: 1px solid #F1F5F9;
    }
    /* Minimal Card Styles */
    .metric-card {
        background: #FFFFFF;
        padding: 15px;
        border-radius: 8px;
        border: 1px solid #E2E8F0;
        text-align: center;
    }
</style>
""", unsafe_allow_html=True)

MODEL_NAME = "openai/gpt-oss-120b"

# 3. Sidebar Configuration
with st.sidebar:
    st.markdown("### 🛡️ **CyberGuard AI**")
    st.caption("Minimalist AI Cybersecurity & Recovery Engine")
    st.divider()
    
    api_key_from_secrets = st.secrets.get("GROQ_API_KEY", "")
    if api_key_from_secrets:
        groq_api_key = api_key_from_secrets
        st.success("API Key Active", icon="✅")
    else:
        groq_api_key = st.text_input("Groq / OpenAI Key:", type="password")
        if not groq_api_key:
            st.warning("Enter API Key to run engine.")

client = Groq(api_key=groq_api_key) if groq_api_key else None

# 4. One-Time Cached RAG Engine Initialization
@st.cache_resource(show_spinner="Indexing Security Knowledge Base...")
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
            "WhatsApp Recovery: Re-install app, enter phone number, request SMS OTP. Enable 2-step verification PIN.",
            "Gmail Compromise: Go to Security -> Recent Activity -> Log out all devices. Change password immediately.",
            "Phishing Indicators: Check domain typos, raw IP links, unexpected attachments, and high urgency messaging.",
            "Malware Symptoms: High CPU usage on idle, unauthorized extension installs, disabled Windows Defender."
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

# 5. Core AI Helper Function
def get_concise_response(system_prompt, user_messages):
    messages = [{"role": "system", "content": system_prompt}] + user_messages
    response = client.chat.completions.create(
        model=MODEL_NAME,
        messages=messages,
        temperature=0.2
    )
    return response.choices[0].message.content

# 6. Session State Initialization for Chat Tabs
if "detector_messages" not in st.session_state:
    st.session_state.detector_messages = []
if "recovery_messages" not in st.session_state:
    st.session_state.recovery_messages = []

# 7. UI Main Structure
st.markdown('<div class="main-title">CyberGuard AI & Emergency Hub</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-title">Instant Threat Diagnostics • Conversational RAG Account Recovery</div>', unsafe_allow_html=True)

if not client:
    st.info("Please enter your API Key in the sidebar to start.")
    st.stop()

tab1, tab2, tab3, tab4 = st.tabs([
    "🔍 Threat Scanner", 
    "🚨 RAG Recovery Chat", 
    "💻 System Audit", 
    "📊 Safety Index"
])

# ==========================================
# TAB 1: THREAT SCANNER (CONVERSATIONAL)
# ==========================================
with tab1:
    st.caption("Paste a link, SMS, or suspicious text to analyze.")
    
    # Display Chat History
    for msg in st.session_state.detector_messages:
        with st.chat_message(msg["role"]):
            st.write(msg["content"])
            
    if prompt := st.chat_input("Paste URL or suspicious email/SMS here..."):
        st.session_state.detector_messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.write(prompt)
            
        system_prompt = """
        You are a concise Cybersecurity Scanner. 
        Analyze the input for phishing, scams, or malware.
        Provide a SHORT, direct answer with strictly:
        1. Threat Level (Safe/Low/Medium/High/Critical)
        2. Threat Type
        3. 2-3 Bullet points explaining why
        4. Immediate action (max 2 bullets)
        Keep total text under 100 words. Avoid generic fluff.
        """
        
        with st.chat_message("assistant"):
            with st.spinner("Scanning..."):
                reply = get_concise_response(system_prompt, st.session_state.detector_messages)
                st.write(reply)
                st.session_state.detector_messages.append({"role": "assistant", "content": reply})

# ==========================================
# TAB 2: RAG RECOVERY CHATBOX (MULTI-TURN)
# ==========================================
with tab2:
    st.caption("Ask anything about hacked accounts or security issues. Answers pull from the PDF manual first.")
    
    # Reset Chat Button
    if st.button("Clear Conversation", type="secondary"):
        st.session_state.recovery_messages = []
        st.rerun()

    # Display Recovery Chat History
    for msg in st.session_state.recovery_messages:
        with st.chat_message(msg["role"]):
            st.write(msg["content"])
            
    if user_query := st.chat_input("e.g., My WhatsApp is hacked, what should I do now?"):
        st.session_state.recovery_messages.append({"role": "user", "content": user_query})
        with st.chat_message("user"):
            st.write(user_query)
            
        retrieved_context = query_rag(user_query)
        
        if retrieved_context:
            system_prompt = f"""
            You are CyberGuard Emergency Support. 
            Answer strictly using the retrieved PDF context below.
            Prefix response with: "📄 **From Security Manual:**"
            Context: {retrieved_context}
            Rule: Keep instructions clear, bulleted, step-by-step, and under 120 words.
            """
        else:
            system_prompt = """
            You are CyberGuard Emergency Support. 
            The PDF manual does not contain specific info on this query.
            Prefix response with: "⚠️ *Information not in PDF manual, general recovery steps:* "
            Rule: Provide immediate, short, non-technical recovery steps under 120 words.
            """
            
        with st.chat_message("assistant"):
            with st.spinner("Searching manual & generating response..."):
                reply = get_concise_response(system_prompt, st.session_state.recovery_messages)
                st.write(reply)
                st.session_state.recovery_messages.append({"role": "assistant", "content": reply})

# ==========================================
# TAB 3: SYSTEM AUDIT
# ==========================================
with tab3:
    st.write("Select current symptoms observed on your computer:")
    
    s1 = st.checkbox("High CPU/Disk usage when idle")
    s2 = st.checkbox("Pop-ups or unfamiliar browser extensions")
    s3 = st.checkbox("Antivirus or Firewall disabled automatically")
    s4 = st.checkbox("Command prompt windows flashing on boot")
    
    selected = [s for s, checked in zip(
        ["High CPU", "Pop-ups/Extensions", "Disabled Antivirus", "Terminal Flashes"], 
        [s1, s2, s3, s4]
    ) if checked]
    
    if st.button("Diagnose System", type="primary"):
        if selected:
            sys_prompt = "You are a PC Security Auditor. Give a concise diagnostic rating and 3 plain-English cleanup steps. Keep response under 100 words."
            user_msg = [{"role": "user", "content": f"Symptoms detected: {', '.join(selected)}"}]
            with st.spinner("Analyzing..."):
                st.markdown(get_concise_response(sys_prompt, user_msg))
        else:
            st.success("No threat symptoms selected. System appears clean!")

# ==========================================
# TAB 4: SAFETY SCORECARD
# ==========================================
with tab4:
    st.write("Check your active security habits:")
    q1 = st.checkbox("Password Manager for unique passwords")
    q2 = st.checkbox("2-Factor Authentication (2FA) enabled on primary accounts")
    q3 = st.checkbox("OS and apps kept up to date")
    
    score = sum([q1, q2, q3]) * 33.33
    st.metric("Security Index Score", f"{int(score)}%")
    
    if score < 100:
        st.info("Tip: Enable 2FA and unique passwords on all primary accounts to reach 100%.")
