"""
AI Security Log Dashboard
=========================
Yeh file ek interactive web dashboard banati hai.
Browser mein: http://localhost:8050
"""

import json
import os
from datetime import datetime
from collections import Counter
import dash
from dash import dcc, html, Input, Output, State, callback
import plotly.graph_objects as go
import plotly.express as px
import dash_bootstrap_components as dbc
import pandas as pd


# ============================================================
# STEP 1: Data Load Function
# ============================================================
def load_all_logs() -> list:
    """Saare log files load karo"""
    all_logs = []
    
    files_to_load = [
        "logs.json",
        "data/sample_logs.json"
    ]
    
    for filepath in files_to_load:
        if os.path.exists(filepath):
            with open(filepath, "r") as f:
                data = json.load(f)
                all_logs.extend(data)
    
    return all_logs


# ============================================================
# STEP 2: Data Process Karo
# ============================================================
def process_logs(logs: list) -> pd.DataFrame:
    """Logs ko DataFrame mein convert karo"""
    
    def get_severity(log):
        level = log.get("level", "INFO").upper()
        action = log.get("action", "").upper()
        
        critical_actions = ["RANSOMWARE_DETECTED", "DDOS_ATTACK", "SQL_INJECTION",
                            "XSS_ATTACK", "BRUTE_FORCE"]
        warning_actions = ["UNAUTHORIZED_ACCESS", "PRIVILEGE_ESCALATION",
                           "DATA_EXFILTRATION", "SUSPICIOUS_DOWNLOAD"]
        
        if level == "CRITICAL" or action in critical_actions:
            return "CRITICAL"
        elif level == "ERROR" or action in warning_actions:
            return "HIGH"
        elif level == "WARNING":
            return "MEDIUM"
        else:
            return "LOW"
    
    rows = []
    for log in logs:
        rows.append({
            "id": log.get("id", "N/A"),
            "timestamp": log.get("timestamp", ""),
            "level": log.get("level", "INFO"),
            "severity": log.get("severity", get_severity(log)),
            "source_ip": log.get("source_ip", "unknown"),
            "user": log.get("user", "unknown"),
            "action": log.get("action", "N/A"),
            "message": log.get("message", ""),
            "service": log.get("service", "unknown"),
            "attempts": log.get("attempts", 1)
        })
    
    df = pd.DataFrame(rows)
    return df


# ============================================================
# STEP 3: Charts Banao
# ============================================================
def create_severity_pie(df):
    severity_counts = df["severity"].value_counts()
    colors = {
        "CRITICAL": "#FF4444",
        "HIGH": "#FF8800",
        "MEDIUM": "#FFCC00",
        "LOW": "#44BB44"
    }
    fig = go.Figure(data=[go.Pie(
        labels=severity_counts.index,
        values=severity_counts.values,
        hole=0.4,
        marker_colors=[colors.get(s, "#888") for s in severity_counts.index]
    )])
    fig.update_layout(
        title="Threat Severity Distribution",
        paper_bgcolor="#1a1a2e",
        plot_bgcolor="#1a1a2e",
        font_color="#e0e0e0",
        title_font_size=16
    )
    return fig


def create_action_bar(df):
    action_counts = df["action"].value_counts().head(8)
    fig = go.Figure(data=[go.Bar(
        x=action_counts.values,
        y=action_counts.index,
        orientation="h",
        marker_color=["#FF4444" if c > 3 else "#FF8800" if c > 1 else "#44BB44"
                     for c in action_counts.values]
    )])
    fig.update_layout(
        title="Top Security Events by Type",
        paper_bgcolor="#1a1a2e",
        plot_bgcolor="#16213e",
        font_color="#e0e0e0",
        xaxis_title="Count",
        yaxis_title="Action",
        title_font_size=16
    )
    return fig


def create_service_chart(df):
    service_counts = df["service"].value_counts()
    fig = px.bar(
        x=service_counts.index,
        y=service_counts.values,
        color=service_counts.values,
        color_continuous_scale="Reds"
    )
    fig.update_layout(
        title="Most Targeted Services",
        paper_bgcolor="#1a1a2e",
        plot_bgcolor="#16213e",
        font_color="#e0e0e0",
        xaxis_title="Service",
        yaxis_title="Attack Count",
        title_font_size=16,
        showlegend=False
    )
    return fig


def create_ip_chart(df):
    suspicious = df[df["severity"].isin(["CRITICAL", "HIGH"])]
    ip_counts = suspicious["source_ip"].value_counts().head(6)
    fig = go.Figure(data=[go.Bar(
        x=ip_counts.index,
        y=ip_counts.values,
        marker_color="#FF4444"
    )])
    fig.update_layout(
        title="Top Suspicious IP Addresses",
        paper_bgcolor="#1a1a2e",
        plot_bgcolor="#16213e",
        font_color="#e0e0e0",
        xaxis_title="IP Address",
        yaxis_title="Incidents",
        title_font_size=16
    )
    return fig


# ============================================================
# STEP 4: Table Rows Banao
# ============================================================
def make_table_rows(df):
    rows = []
    for i, (_, row) in enumerate(df.iterrows()):
        sev = row["severity"]
        color = (
            "#FF4444" if sev == "CRITICAL" else
            "#FF8800" if sev == "HIGH" else
            "#FFCC00" if sev == "MEDIUM" else
            "#44BB44"
        )
        msg = row["message"]
        if len(msg) > 60:
            msg = msg[:60] + "..."
        rows.append(
            html.Tr([
                html.Td(row["id"], style={"color": "#aaa", "fontSize": "12px"}),
                html.Td(html.Span(sev, style={"color": color, "fontWeight": "bold", "fontSize": "11px"})),
                html.Td(row["action"], style={"color": "#e0e0e0", "fontSize": "12px"}),
                html.Td(row["user"], style={"color": "#aaa", "fontSize": "12px"}),
                html.Td(row["source_ip"], style={"color": "#aaa", "fontSize": "12px"}),
                html.Td(row["service"], style={"color": "#888", "fontSize": "12px"}),
                html.Td(msg, style={"color": "#888", "fontSize": "11px"})
            ], style={
                "borderBottom": "1px solid #222",
                "background": "#1e1e3e" if i % 2 == 0 else "#1a1a2e"
            })
        )
    return rows


# ============================================================
# STEP 5: Dashboard Layout
# ============================================================
def create_layout(df):
    total = len(df)
    critical = len(df[df["severity"] == "CRITICAL"])
    high = len(df[df["severity"] == "HIGH"])
    unique_ips = df["source_ip"].nunique()

    INPUT_STYLE = {
        "background": "#16213e",
        "color": "#e0e0e0",
        "border": "1px solid #0f3460",
        "borderRadius": "6px",
        "padding": "8px",
        "width": "100%",
        "marginBottom": "8px"
    }

    layout = dbc.Container([

        # HEADER
        dbc.Row([
            dbc.Col([
                html.Div([
                    html.H1("🔒 AI Security Log Analyzer",
                            className="text-center",
                            style={"color": "#00d4ff", "fontWeight": "bold"}),
                    html.P("Real-time Security Threat Dashboard | Powered by AI",
                           className="text-center",
                           style={"color": "#888", "marginBottom": "0"})
                ], style={"padding": "20px 0", "borderBottom": "1px solid #333"})
            ])
        ], className="mb-4"),

        # STATS CARDS
        dbc.Row([
            dbc.Col([
                dbc.Card([dbc.CardBody([
                    html.H2(id="stat-total", children=str(total), style={"color": "#00d4ff", "fontWeight": "bold"}),
                    html.P("Total Events", style={"color": "#aaa", "margin": "0"})
                ])], style={"background": "#16213e", "border": "1px solid #0f3460", "borderRadius": "10px"})
            ], width=3),
            dbc.Col([
                dbc.Card([dbc.CardBody([
                    html.H2(id="stat-critical", children=str(critical), style={"color": "#FF4444", "fontWeight": "bold"}),
                    html.P("🔴 Critical Threats", style={"color": "#aaa", "margin": "0"})
                ])], style={"background": "#16213e", "border": "1px solid #FF4444", "borderRadius": "10px"})
            ], width=3),
            dbc.Col([
                dbc.Card([dbc.CardBody([
                    html.H2(id="stat-high", children=str(high), style={"color": "#FF8800", "fontWeight": "bold"}),
                    html.P("🟡 High Risk", style={"color": "#aaa", "margin": "0"})
                ])], style={"background": "#16213e", "border": "1px solid #FF8800", "borderRadius": "10px"})
            ], width=3),
            dbc.Col([
                dbc.Card([dbc.CardBody([
                    html.H2(id="stat-ips", children=str(unique_ips), style={"color": "#BB44BB", "fontWeight": "bold"}),
                    html.P("🌐 Unique IPs", style={"color": "#aaa", "margin": "0"})
                ])], style={"background": "#16213e", "border": "1px solid #BB44BB", "borderRadius": "10px"})
            ], width=3),
        ], className="mb-4"),

        # ---- NEW LOG ENTRY FORM ----
        dbc.Row([
            dbc.Col([
                dbc.Card([
                    dbc.CardHeader(
                        html.H5("➕ NEW LOG ADDED", style={"color": "#00d4ff", "margin": "0"}),
                        style={"background": "#0f3460", "border": "none"}
                    ),
                    dbc.CardBody([
                        dbc.Row([
                            dbc.Col([
                                html.Label("Log ID", style={"color": "#aaa", "fontSize": "12px"}),
                                dcc.Input(id="input-id", type="text", placeholder="e.g. LOG020",
                                          style=INPUT_STYLE),
                            ], width=2),
                            dbc.Col([
                                html.Label("User", style={"color": "#aaa", "fontSize": "12px"}),
                                dcc.Input(id="input-user", type="text", placeholder="e.g. rahul.sharma",
                                          style=INPUT_STYLE),
                            ], width=2),
                            dbc.Col([
                                html.Label("Source IP", style={"color": "#aaa", "fontSize": "12px"}),
                                dcc.Input(id="input-ip", type="text", placeholder="e.g. 192.168.1.50",
                                          style=INPUT_STYLE),
                            ], width=2),
                            dbc.Col([
                                html.Label("Action", style={"color": "#aaa", "fontSize": "12px"}),
                                dcc.Dropdown(
                                    id="input-action",
                                    options=[
                                        {"label": "LOGIN_FAILED", "value": "LOGIN_FAILED"},
                                        {"label": "BRUTE_FORCE", "value": "BRUTE_FORCE"},
                                        {"label": "SQL_INJECTION", "value": "SQL_INJECTION"},
                                        {"label": "XSS_ATTACK", "value": "XSS_ATTACK"},
                                        {"label": "UNAUTHORIZED_ACCESS", "value": "UNAUTHORIZED_ACCESS"},
                                        {"label": "PRIVILEGE_ESCALATION", "value": "PRIVILEGE_ESCALATION"},
                                        {"label": "PORT_SCAN", "value": "PORT_SCAN"},
                                        {"label": "DATA_EXFILTRATION", "value": "DATA_EXFILTRATION"},
                                        {"label": "RANSOMWARE_DETECTED", "value": "RANSOMWARE_DETECTED"},
                                        {"label": "DDOS_ATTACK", "value": "DDOS_ATTACK"},
                                        {"label": "FILE_ACCESS", "value": "FILE_ACCESS"},
                                        {"label": "LOGIN_SUCCESS", "value": "LOGIN_SUCCESS"},
                                        {"label": "LOGOUT", "value": "LOGOUT"},
                                        {"label": "SUSPICIOUS_DOWNLOAD", "value": "SUSPICIOUS_DOWNLOAD"},
                                    ],
                                    placeholder="Action chuno...",
                                    style={"background": "#16213e", "color": "#000"},
                                ),
                            ], width=2),
                            dbc.Col([
                                html.Label("Severity", style={"color": "#aaa", "fontSize": "12px"}),
                                dcc.Dropdown(
                                    id="input-severity",
                                    options=[
                                        {"label": "🔴 CRITICAL", "value": "CRITICAL"},
                                        {"label": "🟠 HIGH", "value": "HIGH"},
                                        {"label": "🟡 MEDIUM", "value": "MEDIUM"},
                                        {"label": "🟢 LOW", "value": "LOW"},
                                    ],
                                    placeholder="Severity chuno...",
                                    style={"background": "#16213e", "color": "#000"},
                                ),
                            ], width=2),
                            dbc.Col([
                                html.Label("Service", style={"color": "#aaa", "fontSize": "12px"}),
                                dcc.Dropdown(
                                    id="input-service",
                                    options=[
                                        {"label": "auth-service", "value": "auth-service"},
                                        {"label": "web-app", "value": "web-app"},
                                        {"label": "database", "value": "database"},
                                        {"label": "firewall", "value": "firewall"},
                                        {"label": "os-service", "value": "os-service"},
                                        {"label": "file-system", "value": "file-system"},
                                        {"label": "network", "value": "network"},
                                        {"label": "antivirus", "value": "antivirus"},
                                        {"label": "web-filter", "value": "web-filter"},
                                    ],
                                    placeholder="Service chuno...",
                                    style={"background": "#16213e", "color": "#000"},
                                ),
                            ], width=2),
                        ]),
                        dbc.Row([
                            dbc.Col([
                                html.Label("Message", style={"color": "#aaa", "fontSize": "12px"}),
                                dcc.Input(id="input-message", type="text",
                                          placeholder="? e.g. Failed login attempt from unknown IP",
                                          style={**INPUT_STYLE, "width": "100%"}),
                            ], width=10),
                            dbc.Col([
                                html.Br(),
                                html.Button("➕ Log Added ", id="btn-add-log", n_clicks=0,
                                            style={
                                                "background": "#00d4ff",
                                                "color": "#0d0d1a",
                                                "border": "none",
                                                "borderRadius": "6px",
                                                "padding": "10px 20px",
                                                "fontWeight": "bold",
                                                "cursor": "pointer",
                                                "width": "100%",
                                                "marginTop": "4px"
                                            }),
                            ], width=2),
                        ]),
                        html.Div(id="add-log-msg", style={"marginTop": "10px", "fontSize": "13px"})
                    ])
                ], style={"background": "#1a1a2e", "border": "1px solid #00d4ff"})
            ])
        ], className="mb-4"),

        # CHARTS ROW 1
        dbc.Row([
            dbc.Col([
                dbc.Card([dbc.CardBody([
                    dcc.Graph(id="chart-pie", figure=create_severity_pie(df), style={"height": "300px"})
                ])], style={"background": "#1a1a2e", "border": "1px solid #333"})
            ], width=6),
            dbc.Col([
                dbc.Card([dbc.CardBody([
                    dcc.Graph(id="chart-bar", figure=create_action_bar(df), style={"height": "300px"})
                ])], style={"background": "#1a1a2e", "border": "1px solid #333"})
            ], width=6),
        ], className="mb-4"),

        # CHARTS ROW 2
        dbc.Row([
            dbc.Col([
                dbc.Card([dbc.CardBody([
                    dcc.Graph(id="chart-service", figure=create_service_chart(df), style={"height": "300px"})
                ])], style={"background": "#1a1a2e", "border": "1px solid #333"})
            ], width=6),
            dbc.Col([
                dbc.Card([dbc.CardBody([
                    dcc.Graph(id="chart-ip", figure=create_ip_chart(df), style={"height": "300px"})
                ])], style={"background": "#1a1a2e", "border": "1px solid #333"})
            ], width=6),
        ], className="mb-4"),

        # LOGS TABLE
        dbc.Row([
            dbc.Col([
                dbc.Card([
                    dbc.CardHeader(
                        html.H5("📋 Recent Security Events", style={"color": "#00d4ff", "margin": "0"}),
                        style={"background": "#0f3460", "border": "none"}
                    ),
                    dbc.CardBody([
                        html.Table([
                            html.Thead([
                                html.Tr([
                                    html.Th("ID", style={"color": "#888", "width": "8%"}),
                                    html.Th("Severity", style={"color": "#888", "width": "10%"}),
                                    html.Th("Action", style={"color": "#888", "width": "18%"}),
                                    html.Th("User", style={"color": "#888", "width": "15%"}),
                                    html.Th("Source IP", style={"color": "#888", "width": "13%"}),
                                    html.Th("Service", style={"color": "#888", "width": "12%"}),
                                    html.Th("Message", style={"color": "#888"})
                                ])
                            ], style={"borderBottom": "1px solid #333"}),
                            html.Tbody(id="logs-table-body", children=make_table_rows(df))
                        ], style={"width": "100%", "borderCollapse": "collapse"})
                    ])
                ], style={"background": "#1a1a2e", "border": "1px solid #333"})
            ])
        ], className="mb-4"),

        # Hidden store for logs
        dcc.Store(id="logs-store", data=df.to_dict("records")),

        # FOOTER
        dbc.Row([
            dbc.Col([
                html.P(
                    f"🤖 AI Security Analyzer | Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                    className="text-center",
                    style={"color": "#555", "fontSize": "12px", "borderTop": "1px solid #333", "paddingTop": "15px"}
                )
            ])
        ])

    ], fluid=True, style={"background": "#0d0d1a", "minHeight": "100vh", "padding": "20px"})

    return layout


# ============================================================
# STEP 6: Dashboard Run Karo
# ============================================================
def main():
    print("\n" + "="*50)
    print("  🔒 AI Security Dashboard Starting...")
    print("="*50)

    print("📂 Logs load ho rahe hain...")
    logs = load_all_logs()

    if not logs:
        print("❌ Koi logs nahi mile!")
        return

    print(f"✅ {len(logs)} logs load hue!")
    df = process_logs(logs)

    app = dash.Dash(
        __name__,
        external_stylesheets=[dbc.themes.CYBORG],
        title="AI Security Dashboard"
    )

    app.layout = create_layout(df)

    # ---- CALLBACK: Naya log add karo ----
    @app.callback(
        Output("logs-store", "data"),
        Output("add-log-msg", "children"),
        Output("add-log-msg", "style"),
        Input("btn-add-log", "n_clicks"),
        State("input-id", "value"),
        State("input-user", "value"),
        State("input-ip", "value"),
        State("input-action", "value"),
        State("input-severity", "value"),
        State("input-service", "value"),
        State("input-message", "value"),
        State("logs-store", "data"),
        prevent_initial_call=True
    )
    def add_log(n_clicks, log_id, user, ip, action, severity, service, message, current_logs):
        if not all([log_id, user, ip, action, severity, service, message]):
            return current_logs, "⚠️ Fill all necessary details!", {"color": "#FF8800", "fontSize": "13px", "marginTop": "10px"}

        new_log = {
            "id": log_id,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "level": severity,
            "severity": severity,
            "source_ip": ip,
            "user": user,
            "action": action,
            "message": message,
            "service": service,
            "attempts": 1
        }
        updated = current_logs + [new_log]

        # JSON file mein bhi save karo
        save_path = "data/sample_logs.json"
        if os.path.exists(save_path):
            with open(save_path, "r") as f:
                existing = json.load(f)
            existing.append(new_log)
            with open(save_path, "w") as f:
                json.dump(existing, f, indent=2)

        return updated, f"✅ Log '{log_id}' successfully added !", {"color": "#44BB44", "fontSize": "13px", "marginTop": "10px"}

    # ---- CALLBACK: Table + Charts update karo ----
    @app.callback(
        Output("logs-table-body", "children"),
        Output("stat-total", "children"),
        Output("stat-critical", "children"),
        Output("stat-high", "children"),
        Output("stat-ips", "children"),
        Output("chart-pie", "figure"),
        Output("chart-bar", "figure"),
        Output("chart-service", "figure"),
        Output("chart-ip", "figure"),
        Input("logs-store", "data")
    )
    def update_dashboard(logs_data):
        df = pd.DataFrame(logs_data)
        total = len(df)
        critical = len(df[df["severity"] == "CRITICAL"])
        high = len(df[df["severity"] == "HIGH"])
        unique_ips = df["source_ip"].nunique()
        return (
            make_table_rows(df),
            str(total),
            str(critical),
            str(high),
            str(unique_ips),
            create_severity_pie(df),
            create_action_bar(df),
            create_service_chart(df),
            create_ip_chart(df),
        )

    print("\n🚀 Dashboard chal raha hai!")
    print("🌐 Browser mein kholo: http://localhost:8050")
    print("⏹️  Band karne ke liye: Ctrl+C\n")

    app.run(debug=False, host="0.0.0.0", port=8050)


if __name__ == "__main__":
    main()