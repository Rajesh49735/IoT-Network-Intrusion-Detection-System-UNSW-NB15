import streamlit as st
import pickle
import numpy as np

# =====================================================
# PAGE CONFIG
# =====================================================
st.set_page_config(
    page_title="IoT Intrusion Detection",
    page_icon="🛡️",
    layout="centered"
)

# =====================================================
# ULTRA-PRO MAX CYBER CSS
# =====================================================
st.markdown("""
<style>
/* ---------- ROOT THEME ---------- */
.stApp{
  background:
    radial-gradient(1200px 600px at 20% -10%, #102a43 0%, transparent 60%),
    radial-gradient(1000px 500px at 90% 10%, #2a0d3a 0%, transparent 55%),
    linear-gradient(180deg, #060b12, #04070c);
  color:#e6f1ff;
  font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
}

/* ---------- HERO HEADING ---------- */
h1{
  font-size:3.2rem;
  letter-spacing:.5px;
  background: linear-gradient(90deg,#00e5ff,#7c4dff,#00ffa8,#00e5ff);
  background-size:300% 100%;
  -webkit-background-clip:text;
  -webkit-text-fill-color:transparent;
  animation: neonShift 6s linear infinite;
  text-shadow: 0 0 30px rgba(0,229,255,.65);
}
@keyframes neonShift{
  0%{background-position:0%}
  100%{background-position:300%}
}
h2{
  color:#bfe9ff;
  text-shadow:0 10px 30px rgba(0,0,0,.85);
}

/* ---------- GLASS PANELS (INPUTS) ---------- */
div[data-testid="stNumberInput"] > div{
  background: linear-gradient(180deg, rgba(255,255,255,.10), rgba(255,255,255,.04));
  backdrop-filter: blur(16px);
  border-radius:20px;
  padding:14px;
  box-shadow:
    inset 0 0 18px rgba(255,255,255,.14),
    0 20px 60px rgba(0,0,0,.75);
  transition: transform .35s ease, box-shadow .35s ease;
}
div[data-testid="stNumberInput"] > div:hover{
  transform: translateY(-8px) perspective(900px) rotateX(3deg);
  box-shadow:
    inset 0 0 22px rgba(255,255,255,.20),
    0 30px 90px rgba(0,229,255,.45);
}

/* ---------- ENHANCED +/- BUTTONS ---------- */
button[kind="secondary"]{
  background: linear-gradient(145deg,#1b3b6f,#2f6df6) !important;
  color:#e6f1ff !important;
  border-radius:12px !important;
  box-shadow:
    inset 0 0 12px rgba(255,255,255,.22),
    0 8px 22px rgba(0,0,0,.65) !important;
  transition: transform .2s ease, box-shadow .2s ease !important;
}
button[kind="secondary"]:hover{
  transform: scale(1.15);
  box-shadow:
    0 14px 36px rgba(0,229,255,.7),
    inset 0 0 14px rgba(255,255,255,.3);
}
button[kind="secondary"]:active{
  transform: scale(.95);
}

/* ---------- PRIMARY CTA ---------- */
.stButton button{
  background: linear-gradient(145deg,#00e5ff,#7c4dff);
  color:white;
  border-radius:26px;
  padding:16px 42px;
  font-size:18px;
  font-weight:700;
  box-shadow:
    0 18px 60px rgba(124,77,255,.85),
    inset 0 0 18px rgba(255,255,255,.35);
  transition: all .3s ease;
}
.stButton button:hover{
  transform: scale(1.1);
  background: linear-gradient(145deg,#7c4dff,#00e5ff);
  box-shadow:
    0 26px 90px rgba(0,229,255,.95),
    inset 0 0 22px rgba(255,255,255,.45);
}

/* ---------- OUTPUT CARDS ---------- */
.card{
  border-radius:26px;
  padding:26px;
  margin-top:10px;
  backdrop-filter: blur(14px);
  box-shadow: 0 28px 100px rgba(0,0,0,.8);
}
.card-normal{
  background: linear-gradient(135deg, rgba(0,255,170,.22), rgba(0,160,255,.22));
  box-shadow:
    inset 0 0 26px rgba(0,255,170,.55),
    0 30px 110px rgba(0,255,170,.55);
  animation: shimmer 2.6s ease-in-out infinite alternate;
}
.card-attack{
  background: linear-gradient(135deg, rgba(255,60,60,.28), rgba(255,150,0,.28));
  box-shadow:
    inset 0 0 30px rgba(255,80,80,.75),
    0 36px 130px rgba(255,60,60,.85);
  animation: pulse 1.4s infinite;
}
@keyframes shimmer{
  from{filter:brightness(1)}
  to{filter:brightness(1.15)}
}
@keyframes pulse{
  0%{transform:scale(1)}
  50%{transform:scale(1.03)}
  100%{transform:scale(1)}
}

/* ---------- ATTACK BADGE ---------- */
.badge{
  display:inline-block;
  margin-top:10px;
  padding:8px 16px;
  border-radius:999px;
  font-weight:700;
  letter-spacing:.4px;
  background: linear-gradient(145deg,#ff5252,#ff9800);
  box-shadow:
    0 10px 40px rgba(255,82,82,.85),
    inset 0 0 14px rgba(255,255,255,.35);
}

/* ---------- CLEAN ---------- */
footer{visibility:hidden;}
</style>
""", unsafe_allow_html=True)

# =====================================================
# LOAD MODEL
# =====================================================
model = pickle.load(open("models/mlp_multi.pkl", "rb"))

# Attack labels from UNSW-NB15
ATTACK_LABELS = [
    "Normal","Analysis","Backdoor","DoS","Exploits",
    "Fuzzers","Generic","Reconnaissance","Shellcode","Worms"
]

# =====================================================
# UI
# =====================================================
st.title("🛡️ IoT Network Intrusion Detection System")
st.subheader("Real-Time Intrusion Detection & Attack Classification")
st.write("Enter network traffic values:")

# Inputs
spkts = st.number_input("Source Packets", min_value=0, value=200)
dpkts = st.number_input("Destination Packets", min_value=0, value=180)
sbytes = st.number_input("Source Bytes", min_value=0, value=300)
dbytes = st.number_input("Destination Bytes", min_value=0, value=250)

# =====================================================
# DETECTION
# =====================================================
if st.button("Detect Traffic"):

    # Rule-based spike
    if spkts>1_000_000 or dpkts>1_000_000 or sbytes>1_000_000 or dbytes>1_000_000:
        st.markdown("""
        <div class="card card-attack">
          <h3>🚨 Intrusion Detected</h3>
          <p>High-volume traffic anomaly identified.</p>
          <span class="badge">DoS</span>
        </div>
        """, unsafe_allow_html=True)

    else:
        n_features = model.n_features_in_ if hasattr(model,"n_features_in_") else model.coefs_[0].shape[0]
        X = np.zeros((1,n_features))
        X[0,:4] = [spkts,dpkts,sbytes,dbytes]
        if n_features>4: X[0,4] = spkts + dpkts
        if n_features>5: X[0,5] = sbytes + dbytes
        if n_features>6: X[0,6] = sbytes/(spkts+1)
        if n_features>7: X[0,7] = dbytes/(dpkts+1)
        if n_features>8: X[0,8:] = np.random.normal(0,0.01,n_features-8)

        pred = int(model.predict(X)[0])

        if pred == 0:
            st.markdown("""
            <div class="card card-normal">
              <h3>✅ Normal Traffic</h3>
              <p>No anomalous or malicious patterns detected.</p>
            </div>
            """, unsafe_allow_html=True)
        else:
            atk = ATTACK_LABELS[pred] if pred < len(ATTACK_LABELS) else "Unknown"
            st.markdown(f"""
            <div class="card card-attack">
              <h3>🚨 Intrusion Detected</h3>
              <p>Malicious behavior identified by ML classifier.</p>
              <span class="badge">{atk}</span>
            </div>
            """, unsafe_allow_html=True)

