# app.py - Streamlit Cloud-Ready HID Guardian Application

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime, timedelta
import time
import json
import sqlite3
import hashlib
import numpy as np
from collections import deque
import threading

# ============================================================================
# PAGE CONFIGURATION
# ============================================================================

st.set_page_config(
    page_title="HID Guardian",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============================================================================
# CUSTOM CSS STYLING
# ============================================================================

st.markdown("""
<style>
    .main {
        background-color: #0e1117;
    }
    .stMetric {
        background-color: #1a1d29;
        padding: 15px;
        border-radius: 10px;
        border: 1px solid #2d3250;
    }
    .risk-high {
        color: #ff4444;
        font-weight: bold;
        font-size: 48px;
    }
    .risk-medium {
        color: #ffaa00;
        font-weight: bold;
        font-size: 48px;
    }
    .risk-low {
        color: #00ff00;
        font-weight: bold;
        font-size: 48px;
    }
    div[data-testid="stSidebar"] {
        background-color: #16213e;
    }
    h1, h2, h3 {
        color: #00d4ff;
    }
    .alert-high {
        background-color: #ff444420;
        padding: 10px;
        border-left: 4px solid #ff4444;
        margin: 5px 0;
    }
    .alert-medium {
        background-color: #ffaa0020;
        padding: 10px;
        border-left: 4px solid #ffaa00;
        margin: 5px 0;
    }
    .alert-low {
        background-color: #00ff0020;
        padding: 10px;
        border-left: 4px solid #00ff00;
        margin: 5px 0;
    }
</style>
""", unsafe_allow_html=True)

# ============================================================================
# DATABASE FUNCTIONS
# ============================================================================

@st.cache_resource
def init_database():
    conn = sqlite3.connect('hid_guardian_cloud.db', check_same_thread=False)
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password_hash TEXT,
            baseline_data TEXT,
            created_at TIMESTAMP
        )
    ''')
    
    # Alerts table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY,
            timestamp TIMESTAMP,
            severity TEXT,
            risk_score REAL,
            module TEXT,
            description TEXT,
            user_id INTEGER
        )
    ''')
    
    # Sessions table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            start_time TIMESTAMP,
            keystroke_count INTEGER,
            mouse_events INTEGER,
            avg_risk_score REAL
        )
    ''')
    
    # USB Devices table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS usb_devices (
            id INTEGER PRIMARY KEY,
            vid TEXT,
            pid TEXT,
            device_name TEXT,
            whitelisted INTEGER,
            last_seen TIMESTAMP
        )
    ''')
    
    conn.commit()
    return conn

def add_user(conn, username, password, baseline_data):
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    try:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO users (username, password_hash, baseline_data, created_at)
            VALUES (?, ?, ?, ?)
        ''', (username, password_hash, json.dumps(baseline_data), datetime.now()))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False

def verify_user(conn, username, password):
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    cursor = conn.cursor()
    cursor.execute('SELECT id, username FROM users WHERE username=? AND password_hash=?',
                  (username, password_hash))
    result = cursor.fetchone()
    return result if result else None

def add_alert(conn, severity, risk_score, module, description, user_id):
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO alerts (timestamp, severity, risk_score, module, description, user_id)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (datetime.now(), severity, risk_score, module, description, user_id))
    conn.commit()

def get_recent_alerts(conn, user_id, limit=50):
    cursor = conn.cursor()
    cursor.execute('''
        SELECT timestamp, severity, risk_score, module, description
        FROM alerts WHERE user_id=? ORDER BY timestamp DESC LIMIT ?
    ''', (user_id, limit))
    return cursor.fetchall()

def get_session_stats(conn, user_id):
    cursor = conn.cursor()
    cursor.execute('''
        SELECT COUNT(*) as total_sessions,
               SUM(keystroke_count) as total_keystrokes,
               SUM(mouse_events) as total_mouse,
               AVG(avg_risk_score) as avg_risk
        FROM sessions WHERE user_id=?
    ''', (user_id,))
    return cursor.fetchone()

# ============================================================================
# DETECTION ENGINES
# ============================================================================

class KeystrokeSimulator:
    """Simulates keystroke analysis for demo purposes"""
    def __init__(self):
        self.pattern_type = "normal"
        
    def get_risk_score(self):
        if self.pattern_type == "bot":
            return np.random.uniform(0.7, 0.95)
        elif self.pattern_type == "injection":
            return np.random.uniform(0.6, 0.85)
        else:
            return np.random.uniform(0.0, 0.3)
    
    def set_pattern(self, pattern_type):
        self.pattern_type = pattern_type

class CursorSimulator:
    """Simulates cursor analysis for demo purposes"""
    def __init__(self):
        self.pattern_type = "normal"
        
    def get_risk_score(self):
        if self.pattern_type == "scripted":
            return np.random.uniform(0.65, 0.9)
        elif self.pattern_type == "erratic":
            return np.random.uniform(0.5, 0.75)
        else:
            return np.random.uniform(0.0, 0.25)
    
    def set_pattern(self, pattern_type):
        self.pattern_type = pattern_type

class USBMonitor:
    """Monitors USB devices"""
    def __init__(self):
        self.devices = [
            {'vid': '046d', 'pid': 'c52b', 'name': 'Logitech Mouse', 'whitelisted': True},
            {'vid': '045e', 'pid': '07a5', 'name': 'Microsoft Keyboard', 'whitelisted': True},
            {'vid': '1234', 'pid': '5678', 'name': 'Unknown USB Device', 'whitelisted': False}
        ]
    
    def get_devices(self):
        return self.devices
    
    def get_risk_score(self):
        unknown_devices = [d for d in self.devices if not d['whitelisted']]
        return 0.8 if unknown_devices else 0.1

class RiskScoringEngine:
    """Combines risk scores from multiple modules"""
    def __init__(self):
        self.weights = {'keystroke': 0.4, 'cursor': 0.3, 'usb': 0.3}
    
    def calculate_risk(self, keystroke_score, cursor_score, usb_score):
        total = (
            keystroke_score * self.weights['keystroke'] +
            cursor_score * self.weights['cursor'] +
            usb_score * self.weights['usb']
        )
        return min(total, 1.0)
    
    def get_severity(self, risk_score):
        if risk_score >= 0.7:
            return "HIGH"
        elif risk_score >= 0.4:
            return "MEDIUM"
        else:
            return "LOW"

# ============================================================================
# SESSION STATE INITIALIZATION
# ============================================================================

if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.user_id = None
    st.session_state.username = None
    st.session_state.monitoring_active = False
    st.session_state.keystroke_analyzer = KeystrokeSimulator()
    st.session_state.cursor_analyzer = CursorSimulator()
    st.session_state.usb_monitor = USBMonitor()
    st.session_state.risk_engine = RiskScoringEngine()
    st.session_state.current_risk = 0.0
    st.session_state.keystroke_count = 0
    st.session_state.mouse_count = 0
    st.session_state.risk_history = deque(maxlen=50)

# Initialize database
conn = init_database()

# ============================================================================
# LOGIN / REGISTRATION PAGE
# ============================================================================

def login_page():
    st.markdown("<h1 style='text-align: center;'>🛡️ HID GUARDIAN</h1>", unsafe_allow_html=True)
    st.markdown("<h3 style='text-align: center; color: #aaa;'>Behavioral Biometrics Security System</h3>", unsafe_allow_html=True)
    
    st.markdown("<br>", unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        tab1, tab2 = st.tabs(["Login", "Register"])
        
        with tab1:
            st.subheader("Login to Dashboard")
            username = st.text_input("Username", key="login_user")
            password = st.text_input("Password", type="password", key="login_pass")
            
            if st.button("Login", type="primary", use_container_width=True):
                user = verify_user(conn, username, password)
                if user:
                    st.session_state.logged_in = True
                    st.session_state.user_id = user[0]
                    st.session_state.username = user[1]
                    st.success("Login successful!")
                    st.rerun()
                else:
                    st.error("Invalid credentials")
        
        with tab2:
            st.subheader("Create New Account")
            new_username = st.text_input("Choose Username", key="reg_user")
            new_password = st.text_input("Choose Password", type="password", key="reg_pass")
            confirm_password = st.text_input("Confirm Password", type="password", key="reg_confirm")
            
            if st.button("Register", type="primary", use_container_width=True):
                if len(new_username) < 3:
                    st.error("Username must be at least 3 characters")
                elif len(new_password) < 6:
                    st.error("Password must be at least 6 characters")
                elif new_password != confirm_password:
                    st.error("Passwords do not match")
                else:
                    baseline = {'avg_flight_time': 0.15, 'avg_dwell_time': 0.08}
                    if add_user(conn, new_username, new_password, baseline):
                        st.success("Registration successful! Please login.")
                    else:
                        st.error("Username already exists")

# ============================================================================
# MAIN DASHBOARD
# ============================================================================

def dashboard_page():
    # Header
    col1, col2 = st.columns([3, 1])
    with col1:
        st.title(f"🛡️ HID Guardian Dashboard")
        st.markdown(f"**User:** {st.session_state.username}")
    with col2:
        if st.button("Logout", type="secondary"):
            st.session_state.logged_in = False
            st.session_state.monitoring_active = False
            st.rerun()
    
    st.markdown("---")
    
    # Sidebar Controls
    with st.sidebar:
        st.header("⚙️ Control Panel")
        
        st.subheader("Monitoring Status")
        if not st.session_state.monitoring_active:
            if st.button("🟢 START MONITORING", type="primary", use_container_width=True):
                st.session_state.monitoring_active = True
                st.rerun()
        else:
            if st.button("🔴 STOP MONITORING", type="secondary", use_container_width=True):
                st.session_state.monitoring_active = False
                st.rerun()
        
        st.markdown("---")
        
        st.subheader("Simulation Controls")
        st.caption("⚠️ Demo Mode: Simulate different attack scenarios")
        
        keystroke_pattern = st.selectbox(
            "Keystroke Pattern",
            ["normal", "bot", "injection"],
            help="Simulate different keystroke behaviors"
        )
        st.session_state.keystroke_analyzer.set_pattern(keystroke_pattern)
        
        cursor_pattern = st.selectbox(
            "Cursor Pattern",
            ["normal", "scripted", "erratic"],
            help="Simulate different cursor behaviors"
        )
        st.session_state.cursor_analyzer.set_pattern(cursor_pattern)
        
        st.markdown("---")
        
        st.subheader("Session Statistics")
        st.metric("Keystrokes", st.session_state.keystroke_count)
        st.metric("Mouse Events", st.session_state.mouse_count)
        
        stats = get_session_stats(conn, st.session_state.user_id)
        if stats and stats[0]:
            st.metric("Total Sessions", stats[0] or 0)
            st.metric("Avg Risk Score", f"{stats[3]:.2f}" if stats[3] else "0.00")
    
    # Main Content Area
    if st.session_state.monitoring_active:
        # Update risk scores
        keystroke_risk = st.session_state.keystroke_analyzer.get_risk_score()
        cursor_risk = st.session_state.cursor_analyzer.get_risk_score()
        usb_risk = st.session_state.usb_monitor.get_risk_score()
        
        current_risk = st.session_state.risk_engine.calculate_risk(
            keystroke_risk, cursor_risk, usb_risk
        )
        
        # Smooth the risk score
        st.session_state.current_risk = (st.session_state.current_risk * 0.7 + current_risk * 0.3)
        st.session_state.risk_history.append(st.session_state.current_risk)
        
        # Update counters
        st.session_state.keystroke_count += np.random.randint(5, 15)
        st.session_state.mouse_count += np.random.randint(3, 10)
        
        # Generate alerts for high risk
        severity = st.session_state.risk_engine.get_severity(st.session_state.current_risk)
        if st.session_state.current_risk >= 0.4 and np.random.random() < 0.3:
            module = np.random.choice(['Keystroke', 'Cursor', 'USB'])
            description = f"Anomalous {module.lower()} behavior detected"
            add_alert(conn, severity, st.session_state.current_risk, module,
                     description, st.session_state.user_id)
    
    # Risk Score Display
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        risk_score = st.session_state.current_risk
        severity = st.session_state.risk_engine.get_severity(risk_score)
        
        if severity == "HIGH":
            risk_class = "risk-high"
        elif severity == "MEDIUM":
            risk_class = "risk-medium"
        else:
            risk_class = "risk-low"
        
        st.markdown(f"<div style='text-align: center;'><h3>Current Risk Score</h3><div class='{risk_class}'>{risk_score:.2f}</div><h4>{severity}</h4></div>", unsafe_allow_html=True)
    
    with col2:
        keystroke_risk = st.session_state.keystroke_analyzer.get_risk_score()
        st.metric("Keystroke Risk", f"{keystroke_risk:.2f}", delta=None)
    
    with col3:
        cursor_risk = st.session_state.cursor_analyzer.get_risk_score()
        st.metric("Cursor Risk", f"{cursor_risk:.2f}", delta=None)
    
    with col4:
        usb_risk = st.session_state.usb_monitor.get_risk_score()
        st.metric("USB Risk", f"{usb_risk:.2f}", delta=None)
    
    st.markdown("---")
    
    # Risk History Chart
    if len(st.session_state.risk_history) > 0:
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            y=list(st.session_state.risk_history),
            mode='lines',
            name='Risk Score',
            line=dict(color='#00d4ff', width=2),
            fill='tozeroy',
            fillcolor='rgba(0, 212, 255, 0.2)'
        ))
        
        fig.add_hline(y=0.7, line_dash="dash", line_color="red", annotation_text="HIGH")
        fig.add_hline(y=0.4, line_dash="dash", line_color="orange", annotation_text="MEDIUM")
        
        fig.update_layout(
            title="Risk Score Timeline",
            xaxis_title="Time Window",
            yaxis_title="Risk Score",
            height=300,
            template="plotly_dark",
            showlegend=False,
            yaxis=dict(range=[0, 1])
        )
        
        st.plotly_chart(fig, use_container_width=True)
    
    # Tabs for different sections
    tab1, tab2, tab3 = st.tabs(["🚨 Recent Alerts", "💾 USB Devices", "📊 Analytics"])
    
    with tab1:
        st.subheader("Recent Security Alerts")
        alerts = get_recent_alerts(conn, st.session_state.user_id, 20)
        
        if alerts:
            for alert in alerts:
                timestamp, severity, risk_score, module, description = alert
                time_str = datetime.fromisoformat(str(timestamp)).strftime('%Y-%m-%d %H:%M:%S')
                
                alert_class = f"alert-{severity.lower()}"
                st.markdown(f"""
                <div class='{alert_class}'>
                    <strong>{severity}</strong> | {time_str} | Score: {risk_score:.2f}<br>
                    <strong>{module}</strong>: {description}
                </div>
                """, unsafe_allow_html=True)
        else:
            st.info("No alerts recorded yet")
    
    with tab2:
        st.subheader("Connected USB Devices")
        devices = st.session_state.usb_monitor.get_devices()
        
        device_df = pd.DataFrame(devices)
        device_df['Status'] = device_df['whitelisted'].apply(lambda x: '✅ Trusted' if x else '⚠️ Unknown')
        
        st.dataframe(
            device_df[['vid', 'pid', 'name', 'Status']],
            use_container_width=True,
            hide_index=True
        )
    
    with tab3:
        st.subheader("Security Analytics")
        
        col1, col2 = st.columns(2)
        
        with col1:
            # Alert distribution by severity
            alerts_df = pd.DataFrame(get_recent_alerts(conn, st.session_state.user_id, 100),
                                    columns=['timestamp', 'severity', 'risk_score', 'module', 'description'])
            
            if not alerts_df.empty:
                severity_counts = alerts_df['severity'].value_counts()
                fig = px.pie(
                    values=severity_counts.values,
                    names=severity_counts.index,
                    title="Alerts by Severity",
                    color_discrete_map={'HIGH': '#ff4444', 'MEDIUM': '#ffaa00', 'LOW': '#00ff00'}
                )
                fig.update_layout(template="plotly_dark")
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No analytics data available yet")
        
        with col2:
            # Alert distribution by module
            if not alerts_df.empty:
                module_counts = alerts_df['module'].value_counts()
                fig = px.bar(
                    x=module_counts.index,
                    y=module_counts.values,
                    title="Alerts by Module",
                    labels={'x': 'Module', 'y': 'Count'}
                )
                fig.update_layout(template="plotly_dark")
                st.plotly_chart(fig, use_container_width=True)
    
    # Auto-refresh when monitoring is active
    if st.session_state.monitoring_active:
        time.sleep(1)
        st.rerun()

# ============================================================================
# MAIN APP ROUTING
# ============================================================================

if not st.session_state.logged_in:
    login_page()
else:
    dashboard_page()
