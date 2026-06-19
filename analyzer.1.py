"""
AI Security Log Analyzer
========================
Yeh file Claude AI ka use karke security logs analyze karti hai.
Author: AI Security Project
"""
import os
import json
from dotenv import load_dotenv 
load_dotenv()
from datetime import datetime
from typing import Optional
import anthropic
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import print as rprint

# Rich console for beautiful output
console = Console()

# ============================================================
# STEP 1: Anthropic Client Setup
# ============================================================
def get_client():
    """Claude AI client banao"""
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        console.print("[red]❌ ERROR: ANTHROPIC_API_KEY environment variable set nahi hai![/red]")
        console.print("[yellow]➡️  Run karo: export ANTHROPIC_API_KEY='your-key-here'[/yellow]")
        raise ValueError("API Key missing!")
    return anthropic.Anthropic(api_key=api_key)


# ============================================================
# STEP 2: Logs Load Karna
# ============================================================
def load_logs(filepath: str) -> list:
    """JSON file se logs load karo"""
    try:
        with open(filepath, "r") as f:
            logs = json.load(f)
        console.print(f"[green]✅ {len(logs)} logs load hue: {filepath}[/green]")
        return logs
    except FileNotFoundError:
        console.print(f"[red]❌ File nahi mili: {filepath}[/red]")
        return []
    except json.JSONDecodeError:
        console.print(f"[red]❌ JSON format galat hai: {filepath}[/red]")
        return []


# ============================================================
# STEP 3: Log Severity Check (AI ke bina bhi)
# ============================================================
def classify_severity(log: dict) -> str:
    """Log ki severity classify karo"""
    level = log.get("level", "INFO").upper()
    action = log.get("action", "").upper()
    
    critical_actions = ["RANSOMWARE_DETECTED", "DDOS_ATTACK", "SQL_INJECTION", 
                        "XSS_ATTACK", "BRUTE_FORCE"]
    warning_actions = ["UNAUTHORIZED_ACCESS", "PRIVILEGE_ESCALATION", 
                       "DATA_EXFILTRATION", "SUSPICIOUS_DOWNLOAD"]
    
    if level == "CRITICAL" or action in critical_actions:
        return "🔴 CRITICAL"
    elif level == "ERROR" or action in warning_actions:
        return "🟡 HIGH"
    elif level == "WARNING":
        return "🟠 MEDIUM"
    else:
        return "🟢 LOW"


# ============================================================
# STEP 4: Claude AI se Analysis Karo (MAIN FUNCTION)
# ============================================================
def analyze_with_ai(logs: list, client) -> str:
    """
    Claude AI ko logs bhejo aur detailed security analysis lo.
    Yahi is project ka dil hai! 💡
    """
    
    # Logs ko readable format mein convert karo
    logs_text = json.dumps(logs, indent=2)
    
    # Claude ko prompt bhejo
    prompt = f"""
Tum ek expert Cybersecurity Analyst ho. Neeche diye gaye security logs analyze karo aur detailed report do.

SECURITY LOGS:
{logs_text}

Mujhe yeh batao:

1. 🚨 CRITICAL THREATS (Sabse khatarnak incidents):
   - Kya khatarnak hua?
   - Kaunsa IP/User involved hai?
   - Kitna serious hai?

2. 📊 ATTACK PATTERNS:
   - Koi pattern dikh raha hai kya? (jaise same IP se multiple attacks)
   - Kaunse attack types zyada ho rahe hain?

3. 🎯 AFFECTED SERVICES:
   - Kaunsi services most targeted hain?

4. ⚡ IMMEDIATE ACTIONS (Abhi kya karna chahiye):
   - Top 5 immediate steps jo security team ko lene chahiye

5. 🛡️ SECURITY RECOMMENDATIONS:
   - Long-term security improvements

6. 📈 RISK SCORE:
   - Overall risk score do: 1-10
   - Explanation ke saath

Hinglish mein simple language mein samjhao (Hindi + English mix).
    """
    
    console.print("\n[cyan]🤖 Claude AI se analysis ho rahi hai... Please wait...[/cyan]")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("AI thinking...", total=None)
        
        # Claude API call
        message = client.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=2000,
            messages=[
                {"role": "user", "content": prompt}
            ]
        )
        
        progress.stop()
    
    return message.content[0].text


# ============================================================
# STEP 5: Summary Table Print Karo
# ============================================================
def print_logs_table(logs: list):
    """Rich table mein logs dikhao"""
    
    table = Table(
        title="🔍 Security Logs Overview",
        show_header=True,
        header_style="bold magenta"
    )
    
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Time", style="blue")
    table.add_column("Severity", justify="center")
    table.add_column("User", style="green")
    table.add_column("Action", style="yellow")
    table.add_column("Source IP", style="white")
    table.add_column("Service", style="dim")
    
    for log in logs:
        # Timestamp format karo
        try:
            ts = datetime.fromisoformat(log["timestamp"].replace("Z", "+00:00"))
            time_str = ts.strftime("%H:%M:%S")
        except:
            time_str = log.get("timestamp", "N/A")
        
        severity = classify_severity(log)
        
        table.add_row(
            log.get("id", "N/A"),
            time_str,
            severity,
            log.get("user", "unknown"),
            log.get("action", "N/A"),
            log.get("source_ip", "N/A"),
            log.get("service", "N/A")
        )
    
    console.print(table)


# ============================================================
# STEP 6: Stats Generate Karo
# ============================================================
def generate_stats(logs: list) -> dict:
    """Log statistics calculate karo"""
    stats = {
        "total": len(logs),
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "unique_ips": set(),
        "unique_users": set(),
        "services": {}
    }
    
    for log in logs:
        severity = classify_severity(log)
        if "CRITICAL" in severity:
            stats["critical"] += 1
        elif "HIGH" in severity:
            stats["high"] += 1
        elif "MEDIUM" in severity:
            stats["medium"] += 1
        else:
            stats["low"] += 1
        
        stats["unique_ips"].add(log.get("source_ip", ""))
        stats["unique_users"].add(log.get("user", ""))
        
        service = log.get("service", "unknown")
        stats["services"][service] = stats["services"].get(service, 0) + 1
    
    stats["unique_ips"] = len(stats["unique_ips"])
    stats["unique_users"] = len(stats["unique_users"])
    
    return stats


# ============================================================
# STEP 7: Report Save Karo
# ============================================================
def save_report(analysis: str, stats: dict, filepath: str = "reports/analysis_report.txt"):
    """Analysis report file mein save karo"""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("=" * 60 + "\n")
        f.write("   AI SECURITY LOG ANALYSIS REPORT\n")
        f.write(f"   Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 60 + "\n\n")
        
        f.write("📊 STATISTICS:\n")
        f.write(f"  Total Logs: {stats['total']}\n")
        f.write(f"  Critical: {stats['critical']}\n")
        f.write(f"  High: {stats['high']}\n")
        f.write(f"  Medium: {stats['medium']}\n")
        f.write(f"  Low: {stats['low']}\n")
        f.write(f"  Unique IPs: {stats['unique_ips']}\n")
        f.write(f"  Unique Users: {stats['unique_users']}\n\n")
        
        f.write("🤖 AI ANALYSIS:\n")
        f.write("-" * 60 + "\n")
        f.write(analysis)
    
    console.print(f"\n[green]💾 Report saved: {filepath}[/green]")


# ============================================================
# STEP 8: MAIN PROGRAM
# ============================================================
def main():
    """Main function - poora program yahan se chalta hai"""
    
    # Welcome Banner
    console.print(Panel.fit(
        "[bold cyan]🔒 AI Security Log Analyzer[/bold cyan]\n"
        "[dim]Powered by Claude AI (Anthropic)[/dim]\n"
        "[yellow]Security ke liye AI ka use![/yellow]",
        border_style="cyan"
    ))
    
    print()
    
    # STEP 1: Logs load karo (dono files se)
    console.print("[bold]📂 Step 1: Logs Load Ho Rahe Hain...[/bold]")
    logs = load_logs("data/sample_logs.json")
    
    # Main logs bhi add karo agar mile
    main_logs = load_logs("logs.json")
    if main_logs:
        logs.extend(main_logs)
    
    if not logs:
        console.print("[red]❌ Koi logs nahi mile! Pehle logs.json check karo.[/red]")
        return
    
    print()
    
    # STEP 2: Table dikhao
    console.print("[bold]📊 Step 2: Logs Table...[/bold]")
    print_logs_table(logs)
    
    print()
    
    # STEP 3: Stats
    console.print("[bold]📈 Step 3: Statistics...[/bold]")
    stats = generate_stats(logs)
    
    stats_table = Table(title="📊 Quick Stats", show_header=False)
    stats_table.add_column("Metric", style="cyan")
    stats_table.add_column("Value", style="bold white")
    
    stats_table.add_row("Total Logs", str(stats["total"]))
    stats_table.add_row("🔴 Critical", str(stats["critical"]))
    stats_table.add_row("🟡 High", str(stats["high"]))
    stats_table.add_row("🟠 Medium", str(stats["medium"]))
    stats_table.add_row("🟢 Low", str(stats["low"]))
    stats_table.add_row("Unique IPs", str(stats["unique_ips"]))
    stats_table.add_row("Unique Users", str(stats["unique_users"]))
    
    console.print(stats_table)
    
    print()
    
    # STEP 4: AI Analysis
    console.print("[bold]🤖 Step 4: AI Analysis Shuru...[/bold]")
    
    try:
        client = get_client()
        analysis = analyze_with_ai(logs, client)
        
        # Analysis print karo
        console.print(Panel(
            analysis,
            title="[bold green]🤖 Claude AI Security Analysis[/bold green]",
            border_style="green",
            padding=(1, 2)
        ))
        
        # STEP 5: Report save karo
        save_report(analysis, stats)
        
    except Exception as e:
        console.print(f"[red]❌ AI Analysis failed: {e}[/red]")
        console.print("[yellow]💡 Check karo ki ANTHROPIC_API_KEY sahi hai.[/yellow]")
    
    print()
    console.print(Panel.fit(
        "[bold green]✅ Analysis Complete![/bold green]\n"
        "[dim]Dashboard ke liye: python dashboard.py[/dim]",
        border_style="green"
    ))


# Program run karo
if __name__ == "__main__":
    main()