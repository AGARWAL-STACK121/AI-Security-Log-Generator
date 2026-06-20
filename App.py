"""
AI Security Log Analyzer — MEGA Edition
=========================================
Features:
  1. RAG-Powered MITRE ATT&CK Analysis
  2. AI Risk Meter
  3. IOC Extractor
  4. MITRE Technique Counter
  5. CSV Upload
  6. PDF Report Generator 
  7. Attack World Map
  8. Attack Chain Visualizer
  9. AI Chat Assistant
  10. API Key on Dashboard

Browser: http://localhost:8050
"""

import json
import os
import io
import base64
import numpy as np
from datetime import datetime
from dotenv import load_dotenv
load_dotenv()
import dash
from dash import dcc, html, Input, Output, State, dash_table
import plotly.graph_objects as go
import plotly.express as px
import dash_bootstrap_components as dbc
import pandas as pd
from mitre_knowledge_base import get_all_techniques

import os

embedding_model = None
EMBEDDINGS_ENABLED = False

try:
    from sentence_transformers import SentenceTransformer

    if os.environ.get("RENDER") == "true":
        print("⚠️ Render detected → embeddings disabled")
    else:
        embedding_model = SentenceTransformer("all-MiniLM-L6-v2")
        EMBEDDINGS_ENABLED = True
        print("✅ Sentence Transformer loaded!")

except Exception as e:
    embedding_model = None
    EMBEDDINGS_ENABLED = False
    print(f"⚠️ Embeddings disabled: {e}")

groq_client = None
LLM_ENABLED = False
def connect_groq(api_key: str) -> bool:
    global groq_client, LLM_ENABLED
    try:
        from groq import Groq
        groq_client = Groq(api_key=api_key)
        models = groq_client.models.list()
        
        LLM_ENABLED = True
        print("✅ Groq LLM connected!")
        return True
    except Exception as e:
        LLM_ENABLED = False
        return False

env_key = os.getenv("GROQ_API_KEY", "")
if env_key:
    connect_groq(env_key)

MITRE_TECHNIQUES = get_all_techniques()
TECHNIQUE_EMBEDDINGS = None

def build_mitre_index():
    global TECHNIQUE_EMBEDDINGS
    if not EMBEDDINGS_ENABLED:
        return
    print("📚 Building MITRE ATT&CK vector index...")
    texts = [f"{t['name']} {t['description']} {' '.join(t['keywords'])}" for t in MITRE_TECHNIQUES]
    TECHNIQUE_EMBEDDINGS = embedding_model.encode(texts, convert_to_numpy=True)
    print(f"✅ Indexed {len(MITRE_TECHNIQUES)} techniques!")

def retrieve_similar_techniques(log_text: str, top_k: int = 3) -> list:
    if not EMBEDDINGS_ENABLED or TECHNIQUE_EMBEDDINGS is None:
        return keyword_fallback(log_text, top_k)
    log_embedding = embedding_model.encode([log_text], convert_to_numpy=True)
    similarities = np.dot(TECHNIQUE_EMBEDDINGS, log_embedding.T).flatten()
    norms = np.linalg.norm(TECHNIQUE_EMBEDDINGS, axis=1) * np.linalg.norm(log_embedding)
    cosine_scores = similarities / (norms + 1e-8)
    top_indices = np.argsort(cosine_scores)[::-1][:top_k]
    return [{"technique": MITRE_TECHNIQUES[idx], "similarity_score": float(cosine_scores[idx]),
             "confidence": f"{float(cosine_scores[idx]) * 100:.1f}%"} for idx in top_indices]

def keyword_fallback(log_text: str, top_k: int = 3) -> list:
    log_lower = log_text.lower()
    scored = []
    for technique in MITRE_TECHNIQUES:
        score = sum(1 for kw in technique["keywords"] if kw in log_lower)
        if score > 0:
            scored.append({"technique": technique, "similarity_score": score / 10, "confidence": f"{score * 10}%"})
    scored.sort(key=lambda x: x["similarity_score"], reverse=True)
    return scored[:top_k] if scored else [{"technique": MITRE_TECHNIQUES[0], "similarity_score": 0.1, "confidence": "10%"}]

def generate_rag_analysis(log_data: dict, retrieved_techniques: list) -> str:
    if not LLM_ENABLED:
        top = retrieved_techniques[0]
        t = top["technique"]
        return f"""ATTACK IDENTIFICATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Detected Technique   : {t['name']}
MITRE ATT&CK ID      : {t['id']}
Tactic               : {t['tactic']}
Confidence Score     : {top['confidence']}

THREAT DESCRIPTION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{t['description']}

RECOMMENDED ACTION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{t['recommended_action']}

INDICATORS OF COMPROMISE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{chr(10).join(f'• {ind}' for ind in t['indicators'])}"""

    context = ""
    for i, item in enumerate(retrieved_techniques[:2], 1):
        t = item["technique"]
        context += f"\nTechnique {i} ({item['confidence']}): {t['id']} | {t['name']} | {t['tactic']}\n{t['description']}\nAction: {t['recommended_action']}\n"

    prompt = f"""You are a cybersecurity analyst. Analyze this security log using the retrieved MITRE ATT&CK context.

RETRIEVED MITRE ATT&CK CONTEXT:
{context}

LOG: User={log_data.get('user')} IP={log_data.get('source_ip')} Action={log_data.get('action')} Severity={log_data.get('severity')} Message={log_data.get('message')}

Respond in EXACTLY this format:
ATTACK IDENTIFICATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Detected Technique   : [name]
MITRE ATT&CK ID      : [ID]
Tactic               : [tactic]
Confidence Score     : [%]

THREAT ASSESSMENT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[2 sentences]

RECOMMENDED ACTION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[specific action]

INDICATORS OF COMPROMISE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
• [indicator 1]
• [indicator 2]
• [indicator 3]"""

    try:
        response = groq_client.chat.completions.create(
            model="llama3-8b-8192",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=400, temperature=0.2
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"Error: {str(e)}"

def rag_pipeline(log_data: dict) -> dict:
    search_text = f"{log_data.get('action','')} {log_data.get('message','')} {log_data.get('service','')}"
    retrieved = retrieve_similar_techniques(search_text, top_k=3)
    analysis = generate_rag_analysis(log_data, retrieved)
    return {
        "analysis": analysis,
        "top_technique": retrieved[0]["technique"]["id"],
        "top_technique_name": retrieved[0]["technique"]["name"],
        "confidence": retrieved[0]["confidence"],
        "all_retrieved": retrieved
    }

def chat_with_rag(question: str, logs_summary: str) -> str:
    if not LLM_ENABLED:
        return "⚠️ Please connect your Groq API key first."
    mitre_overview = "\n".join([f"• {t['id']} — {t['name']} ({t['tactic']})" for t in MITRE_TECHNIQUES[:8]])
    prompt = f"""You are a cybersecurity analyst. Answer based on dashboard data.

DASHBOARD DATA:
{logs_summary}

MITRE KNOWLEDGE BASE:
{mitre_overview}

QUESTION: {question}

Answer in clear English, 3-5 sentences. Be specific and professional."""

    try:
        response = groq_client.chat.completions.create(
            model="llama3-8b-8192",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=300, temperature=0.4
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"Error: {str(e)}"

# ============================================================
# IOC EXTRACTOR
# ============================================================
import re

def extract_iocs(logs: list) -> dict:
    """Extract Indicators of Compromise from logs"""
    ips, domains, emails, hashes = set(), set(), set(), set()
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    domain_pattern = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|ru|cn|tk|xyz)\b')
    email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
    hash_pattern = re.compile(r'\b[a-fA-F0-9]{32,64}\b')

    for log in logs:
        text = f"{log.get('message','')} {log.get('source_ip','')} {log.get('user','')}"
        ips.update(ip_pattern.findall(text))
        domains.update(domain_pattern.findall(text))
        emails.update(email_pattern.findall(text))
        hashes.update(hash_pattern.findall(text))

    return {
        "ips": list(ips)[:20],
        "domains": list(domains)[:10],
        "emails": list(emails)[:10],
        "hashes": list(hashes)[:10]
    }

# ============================================================
# RISK METER
# ============================================================
def calculate_risk_score(df: pd.DataFrame) -> dict:
    """Calculate overall risk score 0-100"""
    if df.empty:
        return {"score": 0, "level": "LOW", "color": "#44BB44"}

    score = 0
    total = len(df)

    critical_pct = len(df[df["severity"] == "CRITICAL"]) / total
    high_pct = len(df[df["severity"] == "HIGH"]) / total

    score += critical_pct * 50
    score += high_pct * 30

    dangerous_actions = ["RANSOMWARE_DETECTED", "DDOS_ATTACK", "DATA_EXFILTRATION", "PRIVILEGE_ESCALATION"]
    dangerous_count = len(df[df["action"].isin(dangerous_actions)])
    score += min(dangerous_count * 5, 20)

    score = min(int(score), 100)

    if score >= 75:
        level, color = "CRITICAL", "#FF4444"
    elif score >= 50:
        level, color = "HIGH", "#FF8800"
    elif score >= 25:
        level, color = "MEDIUM", "#FFCC00"
    else:
        level, color = "LOW", "#44BB44"

    return {"score": score, "level": level, "color": color}

# ============================================================
# ATTACK CHAIN VISUALIZER
# ============================================================
def create_attack_chain(df: pd.DataFrame):
    """Create attack chain visualization"""
    tactic_order = [
        "Reconnaissance", "Initial Access", "Execution", "Persistence",
        "Privilege Escalation", "Defense Evasion", "Credential Access",
        "Discovery", "Lateral Movement", "Collection", "Exfiltration", "Impact", "Command and Control"
    ]

    detected_tactics = {}
    for _, row in df.iterrows():
        if row.get("mitre_id"):
            for t in MITRE_TECHNIQUES:
                if t["id"] == row["mitre_id"]:
                    tactic = t["tactic"]
                    if tactic not in detected_tactics:
                        detected_tactics[tactic] = []
                    detected_tactics[tactic].append(row["mitre_id"])

    nodes_x, nodes_y, node_text, node_color, node_size = [], [], [], [], []
    for i, tactic in enumerate(tactic_order):
        nodes_x.append(i)
        nodes_y.append(0)
        detected = tactic in detected_tactics
        node_text.append(f"{tactic}<br>{'🔴 DETECTED' if detected else '⚪ Clean'}")
        node_color.append("#FF4444" if detected else "#333355")
        node_size.append(30 if detected else 20)

    edge_x, edge_y = [], []
    for i in range(len(tactic_order) - 1):
        edge_x.extend([i, i + 1, None])
        edge_y.extend([0, 0, None])

    fig = go.Figure()
    fig.add_trace(go.Scatter(x=edge_x, y=edge_y, mode="lines",
                              line=dict(color="#333355", width=2), hoverinfo="none"))
    fig.add_trace(go.Scatter(x=nodes_x, y=nodes_y, mode="markers+text",
                              marker=dict(size=node_size, color=node_color,
                                          line=dict(color="#00d4ff", width=2)),
                              text=[t.split("<br>")[0] for t in node_text],
                              textposition="top center",
                              hovertext=node_text, hoverinfo="text",
                              textfont=dict(color="#e0e0e0", size=9)))
    fig.update_layout(
        title="Attack Chain Visualizer — MITRE ATT&CK Kill Chain",
        paper_bgcolor="#1a1a2e", plot_bgcolor="#1a1a2e",
        font_color="#e0e0e0", title_font_size=14,
        showlegend=False, height=200,
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        margin=dict(l=20, r=20, t=40, b=20)
    )
    return fig

# ============================================================
# WORLD MAP
# ============================================================
def create_world_map(df: pd.DataFrame):
    """Create attack world map with random country assignments for demo"""
    country_map = {
        "10.": "India", "192.168.": "United States", "172.": "Russia",
        "203.": "China", "185.": "Germany", "194.": "United Kingdom",
        "45.": "Brazil", "91.": "Ukraine", "104.": "United States",
        "52.": "Canada"
    }

    suspicious = df[df["severity"].isin(["CRITICAL", "HIGH"])]
    country_counts = {}
    for ip in suspicious["source_ip"]:
        country = "Unknown"
        for prefix, c in country_map.items():
            if str(ip).startswith(prefix):
                country = c
                break
        country_counts[country] = country_counts.get(country, 0) + 1

    if not country_counts:
        country_counts = {"Unknown": 1}

    countries = list(country_counts.keys())
    counts = list(country_counts.values())

    fig = go.Figure(data=go.Choropleth(
        locations=countries,
        locationmode="country names",
        z=counts,
        colorscale=[[0, "#1a1a2e"], [0.5, "#FF8800"], [1, "#FF4444"]],
        showscale=True,
        colorbar=dict(title="Attacks", tickfont=dict(color="#e0e0e0", size=10), title_font=dict(color="#e0e0e0")),
        hovertemplate="<b>%{location}</b><br>Attacks: %{z}<extra></extra>"
    ))
    fig.update_layout(
        title="Attack World Map — Threat Origin",
        paper_bgcolor="#1a1a2e", plot_bgcolor="#1a1a2e",
        font_color="#e0e0e0", title_font_size=14, height=350,
        geo=dict(bgcolor="#0d0d1a", showframe=False,
                 showcoastlines=True, coastlinecolor="#333",
                 showland=True, landcolor="#16213e",
                 showocean=True, oceancolor="#0d0d1a"),
        margin=dict(l=0, r=0, t=40, b=0)
    )
    return fig

# ============================================================
# MITRE COUNTER
# ============================================================
def create_mitre_counter(df: pd.DataFrame):
    mitre_df = df[df["mitre_id"] != ""]
    if mitre_df.empty:
        fig = go.Figure()
        fig.update_layout(title="MITRE ATT&CK Technique Counter (Add logs to populate)",
                          paper_bgcolor="#1a1a2e", plot_bgcolor="#16213e", font_color="#555")
        return fig
    counts = mitre_df.groupby(["mitre_id", "mitre_name"]).size().reset_index(name="count")
    counts = counts.sort_values("count", ascending=True)
    labels = [f"{row['mitre_id']} — {row['mitre_name']}" for _, row in counts.iterrows()]
    fig = go.Figure(data=[go.Bar(
        x=counts["count"], y=labels, orientation="h",
        marker=dict(
            color=counts["count"],
            colorscale=[[0, "#7B2FBE"], [1, "#FF4444"]],
            showscale=False
        ),
        text=counts["count"], textposition="outside",
        textfont=dict(color="#e0e0e0")
    )])
    fig.update_layout(
        title="MITRE ATT&CK Technique Counter",
        paper_bgcolor="#1a1a2e", plot_bgcolor="#16213e",
        font_color="#e0e0e0", title_font_size=14,
        xaxis_title="Count", height=max(200, len(counts) * 40)
    )
    return fig

# ============================================================
# PDF REPORT
# ============================================================
def generate_pdf_report(df: pd.DataFrame, iocs: dict, risk: dict) -> bytes:
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.lib import colors
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.enums import TA_CENTER

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=0.5*inch)
        styles = getSampleStyleSheet()
        story = []

        title_style = ParagraphStyle('Title', parent=styles['Title'],
                                      fontSize=20, textColor=colors.HexColor('#00d4ff'),
                                      spaceAfter=10, alignment=TA_CENTER)
        h2_style = ParagraphStyle('H2', parent=styles['Heading2'],
                                   fontSize=14, textColor=colors.HexColor('#FF8800'), spaceAfter=6)
        normal_style = ParagraphStyle('Normal', parent=styles['Normal'],
                                       fontSize=10, textColor=colors.black, spaceAfter=4)

        story.append(Paragraph("🔒 AI Security Log Analyzer", title_style))
        story.append(Paragraph(f"Security Incident Report — Generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", normal_style))
        story.append(Spacer(1, 0.3*inch))

        story.append(Paragraph("Executive Summary", h2_style))
        story.append(Paragraph(f"Total Events: {len(df)}", normal_style))
        story.append(Paragraph(f"Critical Threats: {len(df[df['severity']=='CRITICAL'])}", normal_style))
        story.append(Paragraph(f"High Risk Events: {len(df[df['severity']=='HIGH'])}", normal_style))
        story.append(Paragraph(f"Unique Source IPs: {df['source_ip'].nunique()}", normal_style))
        story.append(Paragraph(f"Overall Risk Level: {risk['level']} ({risk['score']}/100)", normal_style))
        story.append(Spacer(1, 0.2*inch))

        story.append(Paragraph("MITRE ATT&CK Techniques Detected", h2_style))
        mitre_df = df[df["mitre_id"] != ""]
        if not mitre_df.empty:
            counts = mitre_df["mitre_id"].value_counts()
            for tid, count in counts.items():
                name = mitre_df[mitre_df["mitre_id"] == tid]["mitre_name"].iloc[0]
                story.append(Paragraph(f"• {tid} — {name}: {count} occurrence(s)", normal_style))
        else:
            story.append(Paragraph("No MITRE techniques mapped yet.", normal_style))
        story.append(Spacer(1, 0.2*inch))

        story.append(Paragraph("Indicators of Compromise (IOCs)", h2_style))
        if iocs["ips"]:
            story.append(Paragraph(f"Suspicious IPs: {', '.join(iocs['ips'][:10])}", normal_style))
        if iocs["emails"]:
            story.append(Paragraph(f"Suspicious Emails: {', '.join(iocs['emails'][:5])}", normal_style))
        story.append(Spacer(1, 0.2*inch))

        story.append(Paragraph("Recent Critical Events", h2_style))
        critical_df = df[df["severity"] == "CRITICAL"].head(10)
        if not critical_df.empty:
            table_data = [["Log ID", "Action", "User", "Source IP", "Service"]]
            for _, row in critical_df.iterrows():
                table_data.append([row["id"], row["action"], row["user"], row["source_ip"], row["service"]])
            t = Table(table_data, colWidths=[1*inch, 1.5*inch, 1.5*inch, 1.5*inch, 1.2*inch])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0f3460')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#00d4ff')),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f5f5f5')]),
            ]))
            story.append(t)

        doc.build(story)
        buffer.seek(0)
        return buffer.getvalue()
    except ImportError:
        return None

# ============================================================
# DATA FUNCTIONS
# ============================================================
def load_all_logs() -> list:
    all_logs = []
    for filepath in ["logs.json", "data/sample_logs.json"]:
        if os.path.exists(filepath):
            with open(filepath, "r") as f:
                all_logs.extend(json.load(f))
    return all_logs

def process_logs(logs: list) -> pd.DataFrame:
    def get_severity(log):
        level = log.get("level", "INFO").upper()
        action = log.get("action", "").upper()
        if level == "CRITICAL" or action in ["RANSOMWARE_DETECTED","DDOS_ATTACK","SQL_INJECTION","XSS_ATTACK","BRUTE_FORCE"]:
            return "CRITICAL"
        elif level == "ERROR" or action in ["UNAUTHORIZED_ACCESS","PRIVILEGE_ESCALATION","DATA_EXFILTRATION","SUSPICIOUS_DOWNLOAD"]:
            return "HIGH"
        elif level == "WARNING":
            return "MEDIUM"
        return "LOW"

    rows = []
    for log in logs:
        rows.append({
            "id": log.get("id","N/A"), "timestamp": log.get("timestamp",""),
            "level": log.get("level","INFO"), "severity": log.get("severity", get_severity(log)),
            "source_ip": log.get("source_ip","unknown"), "user": log.get("user","unknown"),
            "action": log.get("action","N/A"), "message": log.get("message",""),
            "service": log.get("service","unknown"), "attempts": log.get("attempts",1),
            "mitre_id": log.get("mitre_id",""), "mitre_name": log.get("mitre_name",""),
            "rag_confidence": log.get("rag_confidence",""),
        })
    return pd.DataFrame(rows)

def get_logs_summary(df: pd.DataFrame) -> str:
    return f"""
Total Events: {len(df)} | Critical: {len(df[df['severity']=='CRITICAL'])} | High: {len(df[df['severity']=='HIGH'])}
Unique IPs: {df['source_ip'].nunique()}
Top Attacks: {df['action'].value_counts().head(3).to_dict()}
Top IPs: {df[df['severity'].isin(['CRITICAL','HIGH'])]['source_ip'].value_counts().head(3).to_dict()}
Top Services: {df['service'].value_counts().head(3).to_dict()}
MITRE Detected: {df[df['mitre_id']!='']['mitre_id'].value_counts().head(3).to_dict()}
"""

# ============================================================
# CHARTS
# ============================================================
def create_severity_pie(df):
    counts = df["severity"].value_counts()
    colors_map = {"CRITICAL":"#FF4444","HIGH":"#FF8800","MEDIUM":"#FFCC00","LOW":"#44BB44"}
    fig = go.Figure(data=[go.Pie(labels=counts.index, values=counts.values, hole=0.4,
                                  marker_colors=[colors_map.get(s,"#888") for s in counts.index])])
    fig.update_layout(title="Threat Severity Distribution", paper_bgcolor="#1a1a2e",
                      plot_bgcolor="#1a1a2e", font_color="#e0e0e0", title_font_size=14)
    return fig

def create_action_bar(df):
    counts = df["action"].value_counts().head(8)
    fig = go.Figure(data=[go.Bar(x=counts.values, y=counts.index, orientation="h",
                                  marker_color=["#FF4444" if c>3 else "#FF8800" if c>1 else "#44BB44" for c in counts.values])])
    fig.update_layout(title="Top Security Events by Type", paper_bgcolor="#1a1a2e",
                      plot_bgcolor="#16213e", font_color="#e0e0e0", title_font_size=14)
    return fig

def create_service_chart(df):
    counts = df["service"].value_counts()
    fig = px.bar(x=counts.index, y=counts.values, color=counts.values, color_continuous_scale="Reds")
    fig.update_layout(title="Most Targeted Services", paper_bgcolor="#1a1a2e",
                      plot_bgcolor="#16213e", font_color="#e0e0e0", title_font_size=14, showlegend=False)
    return fig

def create_ip_chart(df):
    suspicious = df[df["severity"].isin(["CRITICAL","HIGH"])]
    counts = suspicious["source_ip"].value_counts().head(6)
    fig = go.Figure(data=[go.Bar(x=counts.index, y=counts.values, marker_color="#FF4444")])
    fig.update_layout(title="Top Suspicious IP Addresses", paper_bgcolor="#1a1a2e",
                      plot_bgcolor="#16213e", font_color="#e0e0e0", title_font_size=14)
    return fig

def make_table_rows(df):
    rows = []
    for i, (_, row) in enumerate(df.iterrows()):
        sev = row["severity"]
        color = "#FF4444" if sev=="CRITICAL" else "#FF8800" if sev=="HIGH" else "#FFCC00" if sev=="MEDIUM" else "#44BB44"
        msg = row["message"][:50]+"..." if len(row["message"])>50 else row["message"]
        mitre_badge = html.Span(f" [{row['mitre_id']}]",
                                style={"color":"#7B2FBE","fontSize":"10px","fontWeight":"bold"}) if row.get("mitre_id") else ""
        rows.append(html.Tr([
            html.Td(row["id"], style={"color":"#aaa","fontSize":"11px"}),
            html.Td(html.Span(sev, style={"color":color,"fontWeight":"bold","fontSize":"10px"})),
            html.Td(row["action"], style={"color":"#e0e0e0","fontSize":"11px"}),
            html.Td(row["user"], style={"color":"#aaa","fontSize":"11px"}),
            html.Td(row["source_ip"], style={"color":"#aaa","fontSize":"11px"}),
            html.Td(row["service"], style={"color":"#888","fontSize":"11px"}),
            html.Td([msg, mitre_badge], style={"color":"#888","fontSize":"10px"})
        ], style={"borderBottom":"1px solid #222","background":"#1e1e3e" if i%2==0 else "#1a1a2e"}))
    return rows

# ============================================================
# LAYOUT
# ============================================================
def create_layout(df):
    total = len(df)
    critical = len(df[df["severity"]=="CRITICAL"])
    high = len(df[df["severity"]=="HIGH"])
    unique_ips = df["source_ip"].nunique()
    risk = calculate_risk_score(df)
    iocs = extract_iocs(df.to_dict("records"))

    INPUT_STYLE = {"background":"#16213e","color":"#e0e0e0","border":"1px solid #0f3460",
                   "borderRadius":"6px","padding":"8px","width":"100%","marginBottom":"8px"}

    api_status = (html.Span("✅ Groq AI Connected", style={"color":"#44BB44","fontSize":"13px","fontWeight":"bold"})
                  if LLM_ENABLED else
                  html.Span("⚠️ Not Connected — Enter your Groq API key below", style={"color":"#FF8800","fontSize":"13px"}))

    return dbc.Container([

        # HEADER
        dbc.Row([dbc.Col([html.Div([
            html.H1("🔒 AI Security Log Analyzer", className="text-center",
                    style={"color":"#00d4ff","fontWeight":"bold","fontSize":"2rem"}),
            html.P("Real-time Threat Detection | RAG-Powered MITRE ATT&CK Analysis | Powered by Groq LLM",
                   className="text-center", style={"color":"#888","marginBottom":"0"})
        ], style={"padding":"20px 0","borderBottom":"1px solid #333"})])], className="mb-3"),

        # API KEY BOX
        dbc.Row([dbc.Col([dbc.Card([
            dbc.CardHeader(html.H6("🔑 Connect Groq AI — Enter your API key to enable all AI features",
                                   style={"color":"#FFD700","margin":"0"}),
                           style={"background":"#1a1200","border":"none"}),
            dbc.CardBody([
                dbc.Row([
                    dbc.Col([dcc.Input(id="api-key-input", type="password",
                                       placeholder="Enter Groq API key (gsk_...) — Get free key from groq.com",
                                       style={**INPUT_STYLE,"marginBottom":"0"})], width=9),
                    dbc.Col([html.Button("🔌 Connect AI", id="btn-connect-api", n_clicks=0,
                                         style={"background":"#FFD700","color":"#0d0d1a","border":"none",
                                                "borderRadius":"6px","padding":"9px 15px","fontWeight":"bold",
                                                "cursor":"pointer","width":"100%"})], width=3),
                ]),
                html.Div(id="api-status-msg", children=api_status, style={"marginTop":"8px"})
            ], style={"padding":"12px"})
        ], style={"background":"#0d0d00","border":"1px solid #FFD700"})])], className="mb-3"),

        # STATS + RISK METER
        dbc.Row([
            dbc.Col([dbc.Card([dbc.CardBody([
                html.H2(id="stat-total", children=str(total), style={"color":"#00d4ff","fontWeight":"bold"}),
                html.P("Total Events", style={"color":"#aaa","margin":"0"})
            ])], style={"background":"#16213e","border":"1px solid #0f3460","borderRadius":"10px"})], width=2),
            dbc.Col([dbc.Card([dbc.CardBody([
                html.H2(id="stat-critical", children=str(critical), style={"color":"#FF4444","fontWeight":"bold"}),
                html.P("🔴 Critical", style={"color":"#aaa","margin":"0"})
            ])], style={"background":"#16213e","border":"1px solid #FF4444","borderRadius":"10px"})], width=2),
            dbc.Col([dbc.Card([dbc.CardBody([
                html.H2(id="stat-high", children=str(high), style={"color":"#FF8800","fontWeight":"bold"}),
                html.P("🟡 High Risk", style={"color":"#aaa","margin":"0"})
            ])], style={"background":"#16213e","border":"1px solid #FF8800","borderRadius":"10px"})], width=2),
            dbc.Col([dbc.Card([dbc.CardBody([
                html.H2(id="stat-ips", children=str(unique_ips), style={"color":"#BB44BB","fontWeight":"bold"}),
                html.P("🌐 Unique IPs", style={"color":"#aaa","margin":"0"})
            ])], style={"background":"#16213e","border":"1px solid #BB44BB","borderRadius":"10px"})], width=2),

            # AI RISK METER
            dbc.Col([dbc.Card([dbc.CardBody([
                html.Div([
                    html.H3(id="risk-score", children=f"{risk['score']}/100",
                            style={"color":risk["color"],"fontWeight":"bold","margin":"0","fontSize":"1.5rem"}),
                    html.P(id="risk-level", children=f"🎯 Risk: {risk['level']}",
                           style={"color":risk["color"],"margin":"0","fontSize":"12px"}),
                    html.Div([
                        html.Div(style={
                            "width":f"{risk['score']}%","height":"8px",
                            "background":risk["color"],"borderRadius":"4px",
                            "transition":"width 0.5s ease"
                        })
                    ], style={"background":"#333","borderRadius":"4px","marginTop":"6px","overflow":"hidden"})
                ])
            ])], style={"background":"#16213e","border":f"1px solid {risk['color']}","borderRadius":"10px"})], width=4),
        ], className="mb-3"),

        # ATTACK CHAIN VISUALIZER
        dbc.Row([dbc.Col([dbc.Card([
            dbc.CardBody([dcc.Graph(id="chart-attack-chain",
                                    figure=create_attack_chain(df), style={"height":"220px"})])
        ], style={"background":"#1a1a2e","border":"1px solid #00d4ff"})])], className="mb-3"),

        # WORLD MAP
        dbc.Row([dbc.Col([dbc.Card([
            dbc.CardBody([dcc.Graph(id="chart-world-map",
                                    figure=create_world_map(df), style={"height":"350px"})])
        ], style={"background":"#1a1a2e","border":"1px solid #FF4444"})])], className="mb-3"),

        # CSV UPLOAD + IOC EXTRACTOR
        dbc.Row([
            dbc.Col([dbc.Card([
                dbc.CardHeader(html.H6("📂 Upload CSV Log File", style={"color":"#00d4ff","margin":"0"}),
                               style={"background":"#0f3460","border":"none"}),
                dbc.CardBody([
                    dcc.Upload(id="upload-csv",
                               children=html.Div(["📁 Drag & Drop or ", html.B("Click to Upload"), " CSV file"],
                                                  style={"color":"#aaa","fontSize":"13px"}),
                               style={"width":"100%","height":"80px","lineHeight":"80px","borderWidth":"2px",
                                      "borderStyle":"dashed","borderRadius":"8px","textAlign":"center",
                                      "borderColor":"#0f3460","background":"#16213e","cursor":"pointer"},
                               multiple=False),
                    html.Div(id="upload-status", style={"marginTop":"8px","fontSize":"12px","color":"#aaa"}),
                    html.P("CSV must have columns: id, user, source_ip, action, severity, service, message",
                           style={"color":"#555","fontSize":"10px","marginTop":"5px"})
                ], style={"padding":"12px"})
            ], style={"background":"#1a1a2e","border":"1px solid #0f3460"})], width=6),

            dbc.Col([dbc.Card([
                dbc.CardHeader(html.H6("🔍 IOC Extractor — Indicators of Compromise",
                                       style={"color":"#FF8800","margin":"0"}),
                               style={"background":"#1a0800","border":"none"}),
                dbc.CardBody([
                    html.Div(id="ioc-display", children=[
                        html.P(f"🖥️ Suspicious IPs ({len(iocs['ips'])}): {', '.join(iocs['ips'][:5]) or 'None detected'}",
                               style={"color":"#FF4444","fontSize":"11px","marginBottom":"4px"}),
                        html.P(f"📧 Suspicious Emails ({len(iocs['emails'])}): {', '.join(iocs['emails'][:3]) or 'None detected'}",
                               style={"color":"#FF8800","fontSize":"11px","marginBottom":"4px"}),
                        html.P(f"🌐 Suspicious Domains ({len(iocs['domains'])}): {', '.join(iocs['domains'][:3]) or 'None detected'}",
                               style={"color":"#FFCC00","fontSize":"11px","marginBottom":"4px"}),
                        html.P(f"🔑 File Hashes ({len(iocs['hashes'])}): {', '.join(iocs['hashes'][:2]) or 'None detected'}",
                               style={"color":"#44BB44","fontSize":"11px","marginBottom":"0"}),
                    ])
                ], style={"padding":"12px"})
            ], style={"background":"#1a0800","border":"1px solid #FF8800"})], width=6),
        ], className="mb-3"),

        # ADD LOG FORM
        dbc.Row([dbc.Col([dbc.Card([
            dbc.CardHeader(html.H6("➕ Add New Security Log", style={"color":"#00d4ff","margin":"0"}),
                           style={"background":"#0f3460","border":"none"}),
            dbc.CardBody([
                dbc.Row([
                    dbc.Col([html.Label("Log ID",style={"color":"#aaa","fontSize":"11px"}),
                             dcc.Input(id="input-id",type="text",placeholder="LOG020",style=INPUT_STYLE)],width=2),
                    dbc.Col([html.Label("User",style={"color":"#aaa","fontSize":"11px"}),
                             dcc.Input(id="input-user",type="text",placeholder="john.doe",style=INPUT_STYLE)],width=2),
                    dbc.Col([html.Label("Source IP",style={"color":"#aaa","fontSize":"11px"}),
                             dcc.Input(id="input-ip",type="text",placeholder="192.168.1.50",style=INPUT_STYLE)],width=2),
                    dbc.Col([html.Label("Action",style={"color":"#aaa","fontSize":"11px"}),
                             dcc.Dropdown(id="input-action",options=[
                                 {"label":"LOGIN_FAILED","value":"LOGIN_FAILED"},
                                 {"label":"BRUTE_FORCE","value":"BRUTE_FORCE"},
                                 {"label":"SQL_INJECTION","value":"SQL_INJECTION"},
                                 {"label":"XSS_ATTACK","value":"XSS_ATTACK"},
                                 {"label":"UNAUTHORIZED_ACCESS","value":"UNAUTHORIZED_ACCESS"},
                                 {"label":"PRIVILEGE_ESCALATION","value":"PRIVILEGE_ESCALATION"},
                                 {"label":"PORT_SCAN","value":"PORT_SCAN"},
                                 {"label":"DATA_EXFILTRATION","value":"DATA_EXFILTRATION"},
                                 {"label":"RANSOMWARE_DETECTED","value":"RANSOMWARE_DETECTED"},
                                 {"label":"DDOS_ATTACK","value":"DDOS_ATTACK"},
                                 {"label":"FILE_ACCESS","value":"FILE_ACCESS"},
                                 {"label":"LOGIN_SUCCESS","value":"LOGIN_SUCCESS"},
                                 {"label":"SUSPICIOUS_DOWNLOAD","value":"SUSPICIOUS_DOWNLOAD"},
                             ],placeholder="Select action...",style={"background":"#16213e","color":"#000"})],width=2),
                    dbc.Col([html.Label("Severity",style={"color":"#aaa","fontSize":"11px"}),
                             dcc.Dropdown(id="input-severity",options=[
                                 {"label":"🔴 CRITICAL","value":"CRITICAL"},
                                 {"label":"🟠 HIGH","value":"HIGH"},
                                 {"label":"🟡 MEDIUM","value":"MEDIUM"},
                                 {"label":"🟢 LOW","value":"LOW"},
                             ],placeholder="Select...",style={"background":"#16213e","color":"#000"})],width=2),
                    dbc.Col([html.Label("Service",style={"color":"#aaa","fontSize":"11px"}),
                             dcc.Dropdown(id="input-service",options=[
                                 {"label":"auth-service","value":"auth-service"},
                                 {"label":"web-app","value":"web-app"},
                                 {"label":"database","value":"database"},
                                 {"label":"firewall","value":"firewall"},
                                 {"label":"os-service","value":"os-service"},
                                 {"label":"file-system","value":"file-system"},
                                 {"label":"network","value":"network"},
                                 {"label":"antivirus","value":"antivirus"},
                             ],placeholder="Select...",style={"background":"#16213e","color":"#000"})],width=2),
                ]),
                dbc.Row([
                    dbc.Col([html.Label("Message",style={"color":"#aaa","fontSize":"11px"}),
                             dcc.Input(id="input-message",type="text",
                                       placeholder="e.g. Multiple failed login attempts detected from unknown IP",
                                       style={**INPUT_STYLE,"width":"100%"})],width=10),
                    dbc.Col([html.Br(),
                             html.Button("➕ Add Log",id="btn-add-log",n_clicks=0,
                                         style={"background":"#00d4ff","color":"#0d0d1a","border":"none",
                                                "borderRadius":"6px","padding":"9px 15px","fontWeight":"bold",
                                                "cursor":"pointer","width":"100%","marginTop":"4px"})],width=2),
                ]),
                html.Div(id="add-log-msg",style={"marginTop":"8px","fontSize":"12px"}),
                html.Div(id="rag-analysis-box",children=[])
            ],style={"padding":"12px"})
        ],style={"background":"#1a1a2e","border":"1px solid #00d4ff"})])],className="mb-3"),

        # AI CHAT
        dbc.Row([dbc.Col([dbc.Card([
            dbc.CardHeader(html.H6("🤖 AI Security Assistant — Ask Anything About Your Logs",
                                   style={"color":"#00d4ff","margin":"0"}),
                           style={"background":"#0f3460","border":"none"}),
            dbc.CardBody([
                dbc.Row([
                    dbc.Col([dcc.Input(id="chat-input",type="text",
                                       placeholder="e.g. 'Which IP is most dangerous?' or 'Summarize all threats'",
                                       style={**INPUT_STYLE,"marginBottom":"0"})],width=10),
                    dbc.Col([html.Button("🔍 Ask",id="btn-chat",n_clicks=0,
                                         style={"background":"#7B2FBE","color":"#fff","border":"none",
                                                "borderRadius":"6px","padding":"9px 15px","fontWeight":"bold",
                                                "cursor":"pointer","width":"100%"})],width=2),
                ]),
                html.Div(id="chat-response",style={"marginTop":"12px"})
            ],style={"padding":"12px"})
        ],style={"background":"#1a1a2e","border":"1px solid #7B2FBE"})])],className="mb-3"),

        # CHARTS ROW 1
        dbc.Row([
            dbc.Col([dbc.Card([dbc.CardBody([dcc.Graph(id="chart-pie",figure=create_severity_pie(df),style={"height":"280px"})])],
                              style={"background":"#1a1a2e","border":"1px solid #333"})],width=6),
            dbc.Col([dbc.Card([dbc.CardBody([dcc.Graph(id="chart-bar",figure=create_action_bar(df),style={"height":"280px"})])],
                              style={"background":"#1a1a2e","border":"1px solid #333"})],width=6),
        ],className="mb-3"),

        # CHARTS ROW 2
        dbc.Row([
            dbc.Col([dbc.Card([dbc.CardBody([dcc.Graph(id="chart-service",figure=create_service_chart(df),style={"height":"280px"})])],
                              style={"background":"#1a1a2e","border":"1px solid #333"})],width=6),
            dbc.Col([dbc.Card([dbc.CardBody([dcc.Graph(id="chart-ip",figure=create_ip_chart(df),style={"height":"280px"})])],
                              style={"background":"#1a1a2e","border":"1px solid #333"})],width=6),
        ],className="mb-3"),

        # MITRE COUNTER
        dbc.Row([dbc.Col([dbc.Card([
            dbc.CardBody([dcc.Graph(id="chart-mitre",figure=create_mitre_counter(df),style={"height":"280px"})])
        ],style={"background":"#1a1a2e","border":"1px solid #7B2FBE"})])],className="mb-3"),

        # PDF REPORT BUTTON
        dbc.Row([dbc.Col([dbc.Card([
            dbc.CardBody([
                dbc.Row([
                    dbc.Col([
                        html.H6("📄 Generate PDF Security Report", style={"color":"#00d4ff","marginBottom":"8px"}),
                        html.P("Download a complete security incident report with all findings, IOCs, and MITRE techniques.",
                               style={"color":"#aaa","fontSize":"12px","marginBottom":"10px"}),
                        html.Button("📥 Download PDF Report", id="btn-pdf", n_clicks=0,
                                    style={"background":"#FF4444","color":"#fff","border":"none",
                                           "borderRadius":"6px","padding":"10px 20px","fontWeight":"bold",
                                           "cursor":"pointer"}),
                        dcc.Download(id="download-pdf"),
                        html.Div(id="pdf-status", style={"marginTop":"8px","fontSize":"12px","color":"#aaa"})
                    ])
                ])
            ])
        ],style={"background":"#1a1a2e","border":"1px solid #FF4444"})])],className="mb-3"),

        # LOGS TABLE
        dbc.Row([dbc.Col([dbc.Card([
            dbc.CardHeader(html.H6("📋 Recent Security Events",style={"color":"#00d4ff","margin":"0"}),
                           style={"background":"#0f3460","border":"none"}),
            dbc.CardBody([html.Table([
                html.Thead([html.Tr([
                    html.Th("ID",style={"color":"#888","width":"8%"}),
                    html.Th("Severity",style={"color":"#888","width":"9%"}),
                    html.Th("Action",style={"color":"#888","width":"17%"}),
                    html.Th("User",style={"color":"#888","width":"12%"}),
                    html.Th("Source IP",style={"color":"#888","width":"12%"}),
                    html.Th("Service",style={"color":"#888","width":"10%"}),
                    html.Th("Message + MITRE ID",style={"color":"#888"})
                ])],style={"borderBottom":"1px solid #333"}),
                html.Tbody(id="logs-table-body",children=make_table_rows(df))
            ],style={"width":"100%","borderCollapse":"collapse"})])
        ],style={"background":"#1a1a2e","border":"1px solid #333"})])],className="mb-3"),

        dcc.Store(id="logs-store",data=df.to_dict("records")),

        dbc.Row([dbc.Col([html.P(
            f"🤖 AI Security Analyzer | RAG + MITRE ATT&CK | IOC Extractor | Attack Chain | World Map | PDF Reports | {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            className="text-center",
            style={"color":"#555","fontSize":"11px","borderTop":"1px solid #333","paddingTop":"12px"}
        )])])

    ],fluid=True,style={"background":"#0d0d1a","minHeight":"100vh","padding":"20px"})


# ============================================================
# MAIN + CALLBACKS
# ============================================================
def main():
    print("\n"+"="*55)
    print("  🔒 AI Security Dashboard — MEGA Edition")
    print("="*55)

    build_mitre_index()

    print("📂 Loading logs...")
    logs = load_all_logs()
    if not logs:
        print("❌ No logs found!")
        return

    print(f"✅ {len(logs)} logs loaded!")
    df = process_logs(logs)

    app = dash.Dash(__name__, external_stylesheets=[dbc.themes.CYBORG], title="AI Security Dashboard")
    app.layout = create_layout(df)
    server = app.server
   


    # CALLBACK 1: Connect API Key
    @app.callback(
        Output("api-status-msg","children"),
        Input("btn-connect-api","n_clicks"),
        State("api-key-input","value"),
        prevent_initial_call=True
    )
    def connect_api(n_clicks, api_key):
        if not api_key:
            return html.Span("⚠️ Please enter your API key!", style={"color":"#FF8800","fontSize":"12px"})
        if connect_groq(api_key.strip()):
            return html.Span("✅ Groq AI Connected! All AI features are now active.",
                             style={"color":"#44BB44","fontSize":"12px","fontWeight":"bold"})
        return html.Span("❌ Connection failed. Check your API key.", style={"color":"#FF4444","fontSize":"12px"})

    # CALLBACK 2: CSV Upload
    @app.callback(
        Output("logs-store","data"),
        Output("upload-status","children"),
        Input("upload-csv","contents"),
        State("upload-csv","filename"),
        State("logs-store","data"),
        prevent_initial_call=True
    )
    def upload_csv(contents, filename, current_logs):
        if contents is None:
            return current_logs, ""
        try:
            content_type, content_string = contents.split(",")
            decoded = base64.b64decode(content_string)
            csv_df = pd.read_csv(io.StringIO(decoded.decode("utf-8")))
            new_logs = csv_df.to_dict("records")
            updated = current_logs + new_logs
            return updated, html.Span(f"✅ {len(new_logs)} logs uploaded from {filename}!",
                                       style={"color":"#44BB44"})
        except Exception as e:
            return current_logs, html.Span(f"❌ Error: {str(e)}", style={"color":"#FF4444"})

    # CALLBACK 3: Add log + RAG
    @app.callback(
        Output("logs-store","data"),
        Output("add-log-msg","children"),
        Output("add-log-msg","style"),
        Output("rag-analysis-box","children"),
        Input("btn-add-log","n_clicks"),
        State("input-id","value"), State("input-user","value"),
        State("input-ip","value"), State("input-action","value"),
        State("input-severity","value"), State("input-service","value"),
        State("input-message","value"), State("logs-store","data"),
        prevent_initial_call=True
    )
    def add_log(n_clicks, log_id, user, ip, action, severity, service, message, current_logs):
        if not all([log_id, user, ip, action, severity, service, message]):
            return current_logs, "⚠️ Please fill in all fields!", \
                   {"color":"#FF8800","fontSize":"12px","marginTop":"8px"}, []

        new_log = {"id":log_id, "timestamp":datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                   "level":severity, "severity":severity, "source_ip":ip, "user":user,
                   "action":action, "message":message, "service":service, "attempts":1,
                   "mitre_id":"", "mitre_name":"", "rag_confidence":""}

        rag_result = rag_pipeline(new_log)
        new_log["mitre_id"] = rag_result["top_technique"]
        new_log["mitre_name"] = rag_result["top_technique_name"]
        new_log["rag_confidence"] = rag_result["confidence"]

        updated = current_logs + [new_log]

        save_path = "data/sample_logs.json"
        if os.path.exists(save_path):
            with open(save_path,"r") as f:
                existing = json.load(f)
            existing.append(new_log)
            with open(save_path,"w") as f:
                json.dump(existing, f, indent=2)

        retrieved = rag_result["all_retrieved"]
        badges = []
        for item in retrieved[:3]:
            t = item["technique"]
            c = "#FF4444" if float(item["similarity_score"])>0.7 else "#FF8800" if float(item["similarity_score"])>0.4 else "#FFCC00"
            badges.append(html.Span(f"{t['id']} — {t['name']} ({item['confidence']})",
                                    style={"background":"#1a1a2e","border":f"1px solid {c}","color":c,
                                           "padding":"2px 6px","borderRadius":"4px","fontSize":"10px","marginRight":"6px"}))

        analysis_box = dbc.Card([
            dbc.CardHeader([
                html.Span("🔍 RAG Analysis Result", style={"color":"#00d4ff","fontWeight":"bold"}),
                html.Span(" — MITRE ATT&CK Knowledge Base", style={"color":"#888","fontSize":"10px","marginLeft":"8px"})
            ], style={"background":"#0a1628","border":"none","padding":"6px 12px"}),
            dbc.CardBody([
                html.Div([html.P("Retrieved Techniques:", style={"color":"#888","fontSize":"10px","marginBottom":"4px"}),
                          html.Div(badges, style={"marginBottom":"10px"})]),
                html.Hr(style={"borderColor":"#333","margin":"6px 0"}),
                html.Pre(rag_result["analysis"], style={"color":"#00ff88","background":"#050d1a",
                                                         "padding":"12px","borderRadius":"6px",
                                                         "fontSize":"11px","whiteSpace":"pre-wrap","margin":"0"})
            ], style={"padding":"10px"})
        ], style={"background":"#0a1628","border":"1px solid #00ff88","marginTop":"8px"})

        return (updated,
                f"✅ Log '{log_id}' added! MITRE: {rag_result['top_technique']} — {rag_result['top_technique_name']}",
                {"color":"#44BB44","fontSize":"12px","marginTop":"8px"}, analysis_box)

    # CALLBACK 4: AI Chat
    @app.callback(
        Output("chat-response","children"),
        Input("btn-chat","n_clicks"),
        State("chat-input","value"), State("logs-store","data"),
        prevent_initial_call=True
    )
    def ai_chat(n_clicks, question, logs_data):
        if not question:
            return html.P("⚠️ Please enter a question!", style={"color":"#FF8800"})
        df = pd.DataFrame(logs_data)
        response = chat_with_rag(question, get_logs_summary(df))
        return dbc.Card([dbc.CardBody([
            html.P(f"❓ {question}", style={"color":"#aaa","fontSize":"11px","marginBottom":"6px"}),
            html.Pre(response, style={"color":"#e0e0e0","background":"#0a1628","padding":"10px",
                                       "borderRadius":"6px","fontSize":"12px","whiteSpace":"pre-wrap","margin":"0"})
        ])], style={"background":"#130b2b","border":"1px solid #7B2FBE"})

    # CALLBACK 5: PDF Report
    @app.callback(
        Output("download-pdf","data"),
        Output("pdf-status","children"),
        Input("btn-pdf","n_clicks"),
        State("logs-store","data"),
        prevent_initial_call=True
    )
    def download_pdf(n_clicks, logs_data):
        df = pd.DataFrame(logs_data)
        risk = calculate_risk_score(df)
        iocs = extract_iocs(logs_data)
        pdf_bytes = generate_pdf_report(df, iocs, risk)
        if pdf_bytes:
            return (dcc.send_bytes(pdf_bytes, f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"),
                    html.Span("✅ PDF downloaded!", style={"color":"#44BB44"}))
        return (None, html.Span("⚠️ Install reportlab: pip install reportlab", style={"color":"#FF8800"}))

    # CALLBACK 6: Update all dashboard
    @app.callback(
        Output("logs-table-body","children"),
        Output("stat-total","children"), Output("stat-critical","children"),
        Output("stat-high","children"), Output("stat-ips","children"),
        Output("risk-score","children"), Output("risk-level","children"),
        Output("risk-level","style"),
        Output("chart-pie","figure"), Output("chart-bar","figure"),
        Output("chart-service","figure"), Output("chart-ip","figure"),
        Output("chart-mitre","figure"),
        Output("chart-attack-chain","figure"), Output("chart-world-map","figure"),
        Output("ioc-display","children"),
        Input("logs-store","data")
    )
    def update_dashboard(logs_data):
        df = pd.DataFrame(logs_data)
        risk = calculate_risk_score(df)
        iocs = extract_iocs(logs_data)

        ioc_display = [
            html.P(f"🖥️ Suspicious IPs ({len(iocs['ips'])}): {', '.join(iocs['ips'][:5]) or 'None'}",
                   style={"color":"#FF4444","fontSize":"11px","marginBottom":"4px"}),
            html.P(f"📧 Emails ({len(iocs['emails'])}): {', '.join(iocs['emails'][:3]) or 'None'}",
                   style={"color":"#FF8800","fontSize":"11px","marginBottom":"4px"}),
            html.P(f"🌐 Domains ({len(iocs['domains'])}): {', '.join(iocs['domains'][:3]) or 'None'}",
                   style={"color":"#FFCC00","fontSize":"11px","marginBottom":"4px"}),
            html.P(f"🔑 Hashes ({len(iocs['hashes'])}): {', '.join(iocs['hashes'][:2]) or 'None'}",
                   style={"color":"#44BB44","fontSize":"11px","marginBottom":"0"}),
        ]

        return (
            make_table_rows(df),
            str(len(df)), str(len(df[df["severity"]=="CRITICAL"])),
            str(len(df[df["severity"]=="HIGH"])), str(df["source_ip"].nunique()),
            f"{risk['score']}/100", f"🎯 Risk: {risk['level']}",
            {"color":risk["color"],"margin":"0","fontSize":"12px"},
            create_severity_pie(df), create_action_bar(df),
            create_service_chart(df), create_ip_chart(df),
            create_mitre_counter(df), create_attack_chain(df),
            create_world_map(df), ioc_display
        )

def main():
    print("\n🚀 Dashboard is running!")
    print("🌐 Dashboard Started")

    # 🔥 APP MUST BE CREATED FIRST
    app = dash.Dash(__name__, external_stylesheets=[dbc.themes.CYBORG], title="AI Security Dashboard")

    df = process_logs(load_all_logs())  # agar df yahin banana hai

    app.layout = create_layout(df)
    server = app.server

    port = int(os.environ.get("PORT", 8050))

    app.run(
        host="0.0.0.0",
        port=port,
        debug=False
    )


if __name__ == "__main__":
    main()
