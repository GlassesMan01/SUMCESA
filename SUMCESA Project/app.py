import os
import re
import json
import subprocess
import datetime
import asyncio
import aiohttp
import csv
import time
import platform
import socket
from flask import Flask, jsonify, render_template, request, flash, redirect, url_for, send_from_directory, make_response
from flask_sqlalchemy import SQLAlchemy
from apscheduler.schedulers.background import BackgroundScheduler
from datetime import timezone, datetime, timedelta
from typing import List, Dict, Optional, Tuple
from flask_migrate import Migrate
from werkzeug.utils import secure_filename
from urllib.parse import quote
from sqlalchemy import func
import logging
from groq import Groq
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_JUSTIFY
from reportlab.lib import colors
from io import BytesIO
from pathlib import Path
from dotenv import load_dotenv


load_dotenv()


# --------------------- Groq Configuration ---------------------
GROQ_API_KEY = os.environ.get('GROQ_API_KEY')
NVD_API_KEY = os.environ.get('NVD_API_KEY')
Flask_secret_key = os.environ.get('FLASK_SECRET_KEY', 'dev-secret-key-change-in-production')

client = Groq(api_key=GROQ_API_KEY)

# Configure logging
logging.basicConfig(level=logging.DEBUG)

def from_json(value):
    """Custom filter to parse JSON strings"""
    if value is None or value == '':
        return []
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return []

# --------------------- Application Setup ---------------------
# Use instance_relative_config so Flask sets up a stable instance folder
app = Flask(__name__, instance_relative_config=True)
basedir = os.path.abspath(os.path.dirname(__file__))
# Use a simple relative path that SQLAlchemy can handle
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sumcesa.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(basedir, 'uploads')
app.config['ALLOWED_EXTENSIONS'] = {'csv', 'json'}
app.config['TEMPLATES_AUTO_RELOAD'] = True

# Create upload folder if not exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Register Jinja filter to match template usage
@app.template_filter('fromjson')
def jinja_filter_fromjson(value):
    return from_json(value)

# Initialize extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
scheduler = BackgroundScheduler()


# Instance folder already ensured via app.instance_path above

# --------------------- Database Models ---------------------
class Machine(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    machine_id = db.Column(db.String(100), unique=True, nullable=False)
    hostname = db.Column(db.String(200))
    ip_address = db.Column(db.String(50))
    last_seen = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    os = db.Column(db.String(100))
    software = db.relationship('Software', backref='machine', lazy=True)

class Software(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    package_id = db.Column(db.String(100))  # Store winget package ID
    installed_version = db.Column(db.String(50))
    latest_version = db.Column(db.String(50))
    last_updated = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    last_checked = db.Column(db.DateTime)
    vulnerabilities = db.Column(db.Text)  # JSON formatted CVE data
    update_available = db.Column(db.Boolean, default=False)
    source = db.Column(db.String(50))
    risk_score = db.Column(db.Float, default=0.0)
    recommended_action = db.Column(db.String(200))
    history = db.relationship('SoftwareHistory', backref='software', lazy=True)
    machine_id = db.Column(db.Integer, db.ForeignKey('machine.id'), nullable=False)
    
    __table_args__ = (
        db.UniqueConstraint('name', 'machine_id', name='unique_software_per_machine'),
    )

    def __repr__(self):
        return f"<Software {self.name} v{self.installed_version}>"

class SoftwareHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    software_id = db.Column(db.Integer, db.ForeignKey('software.id'))
    date = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    version = db.Column(db.String(50))
    vulnerabilities = db.Column(db.Text)
    
    
# --------------------- Configuration ---------------------
INVENTORY_UPDATE_INTERVAL = 60  # minutes
CVE_CHECK_INTERVAL = 1440  # 24 hours
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Create upload folder if not exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# --------------------- Helper Functions ---------------------
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def get_severity_color(severity):
    if severity == 'CRITICAL':
        return 'danger'
    elif severity == 'HIGH':
        return 'warning'
    elif severity == 'MEDIUM':
        return 'info'
    elif severity == 'LOW':
        return 'primary'
    else:
        return 'secondary'
    

# --------------------- AI Report Generation ---------------------
def generate_pdf_report(content):
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, 
                          rightMargin=72, leftMargin=72, 
                          topMargin=72, bottomMargin=72)
    
    styles = getSampleStyleSheet()
    
    # Create unique style names
    styles.add(ParagraphStyle(
        name='ReportHeading1',
        parent=styles['Heading1'],
        fontSize=14,
        leading=16,
        fontName='Helvetica-Bold',
        spaceAfter=12
    ))
    
    styles.add(ParagraphStyle(
        name='ReportHeading2',
        parent=styles['Heading2'],
        fontSize=12,
        leading=14,
        fontName='Helvetica-Bold',
        spaceAfter=8
    ))
    
    story = []
    
    # Header
    story.append(Paragraph("SUMCESA Security Report", styles['ReportHeading1']))
    story.append(Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M')}", styles['Normal']))
    story.append(Spacer(1, 12))
    
    # Process content sections
    sections = content.split('\n\n')
    for section in sections:
        if not section.strip():
            continue
            
        if section.startswith('1. '):
            story.append(Paragraph(section[3:], styles['ReportHeading1']))
        elif section.startswith(('2. ', '3. ', '4. ', '5. ')):
            story.append(Paragraph(section[3:], styles['ReportHeading2']))
        else:
            story.append(Paragraph(section, styles['Normal']))
        story.append(Spacer(1, 8))
    
    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()


def generate_ai_report_content():
    """Generate an AI-powered vulnerability report using Groq Llama"""
    vulnerable_software = Software.query.filter(
    Software.vulnerabilities.isnot(None)
    ).order_by(
        Software.risk_score.desc()
    ).all()
    
    if not vulnerable_software:
        return None

    # Prepare structured data for AI
    report_data = []
    for software in vulnerable_software:
        vulns = json.loads(software.vulnerabilities)
        report_data.append({
            "software_name": software.name,
            "current_version": software.installed_version,
            "latest_version": software.latest_version,
            "critical_issues": len([v for v in vulns if v['severity'] == 'CRITICAL']),
            "high_issues": len([v for v in vulns if v['severity'] == 'HIGH']),
            "recommended_action": software.recommended_action
        })

    # AI Prompt Engineering
    system_prompt = """You are a cybersecurity expert helping small business owners understand 
    technical security issues. Create clear, actionable reports that:
    1. Explain risks in simple terms
    2. Prioritize critical issues
    3. Provide step-by-step remediation
    4. Use non-technical language
    5. Include maintenance tips"""
    
    user_prompt = f"""Generate a security report for these vulnerable applications:
    {json.dumps(report_data, indent=2)}
    
    Report structure:
    1. Executive Summary
    2. Critical Issues to Address Immediately
    3. Step-by-Step Remediation Guide
    4. Long-Term Maintenance Checklist
    5. Additional Security Recommendations
    
    DO NOT:
    - Use markdown (**bold**, *italics*)
    - Add extra line breaks within paragraphs
    - Deviate from the numbered section structure"""
    
    try:
        response = client.chat.completions.create(
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            model="llama-3.3-70b-versatile",
            temperature=0.3,
            max_tokens=2000
        )
        
        return {
            "content": response.choices[0].message.content,
            "date": datetime.now().strftime('%Y-%m-%d'),
            "critical_count": sum(s['critical_issues'] for s in report_data),
            "high_count": sum(s['high_issues'] for s in report_data)
        }
    except Exception as e:
        print(f"Groq API Error: {e}")
        return None

# --------------------- Report Route ---------------------
@app.route('/generate_ai_report')
def generate_ai_report():
    """Generate and download AI-powered security report as PDF"""
    report_data = generate_ai_report_content()
    
    if not report_data or not report_data.get('content'):
        flash("No vulnerabilities found or error generating report", "info")
        return redirect(url_for('cpe_details'))
    
    # Generate PDF
    pdf_content = generate_pdf_report(report_data['content'])
    
    # Create downloadable response
    filename = f"SUMCESA_Report_{datetime.now().strftime('%Y%m%d')}.pdf"
    response = make_response(pdf_content)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename={filename}'
    
    return response

# --------------------- Core Functions ---------------------
def get_installed_software() -> List[Dict]:
    """Robust software detection with error handling"""
    try:
        result = subprocess.run(
            ["winget", "list", "--disable-interactivity"],
            capture_output=True,
            text=True,
            shell=True,
            timeout=90
        )
        if result.returncode != 0:
            print(f"Winget error: {result.stderr}")
            return []
            
        return parse_winget_list(result.stdout)
        
    except Exception as e:
        print(f"Software detection failed: {str(e)}")
        return []
    

def clean_orphaned_entries():
    """Scheduled task to remove invalid entries"""
    with app.app_context():
        # Remove entries with invalid names
        Software.query.filter(
            (Software.name == '') |
            (Software.name.is_(None)) |
            (func.lower(Software.name) == 'n/a')
        ).delete()
        
        # Merge duplicates
        duplicates = db.session.query(
            Software.name,
            func.count(Software.name).label('count')
        ).group_by(Software.name).having(func.count(Software.name) > 1)
        
        for dup in duplicates:
            keep = Software.query.filter_by(name=dup.name).order_by(
                Software.last_updated.desc()
            ).first()
            
            Software.query.filter(
                (Software.name == dup.name) &
                (Software.id != keep.id)
            ).delete()
        
        db.session.commit()

@app.cli.command('validate-risks')
def validate_risks():
    """Force-correct risk scores in database"""
    with app.app_context():
        # Clear scores for software without vulnerabilities
        Software.query.filter(
            (Software.vulnerabilities.is_(None)) |
            (Software.vulnerabilities == '[]')  # New condition
        ).update({'risk_score': 0.0})
        
        # Recalculate scores for vulnerable software
        vulnerable_software = Software.query.filter(
            Software.vulnerabilities.isnot(None),
            Software.vulnerabilities != '[]'  # Exclude empty arrays
        ).all()
        
        for sw in vulnerable_software:
            vulns = json.loads(sw.vulnerabilities)
            sw.risk_score = calculate_risk_score(vulns)
        
        db.session.commit()
    print("Risk validation completed")
def parse_winget_list(output: str) -> List[Dict]:
    """Robust winget list parser"""
    software_list = []
    lines = [line.strip() for line in output.split('\n') if line.strip()]
    
    # Find header line index
    try:
        header_idx = next(i for i, line in enumerate(lines) 
                        if line.startswith("Name") and "Id" in line and "Version" in line)
    except StopIteration:
        return []
    
    # Process data lines
    for line in lines[header_idx+1:]:
        parts = re.split(r'\s{2,}', line)
        if len(parts) < 3:
            continue
            
        name = parts[0].strip()
        pkg_id = parts[1].strip()
        version = parts[2].split()[0]  # Get first part of version column
        
        software_list.append({
            'name': clean_software_name(name),
            'id': pkg_id,
            'version': version
        })
    
    return software_list

def get_windows_software() -> List[Dict]:
    """Get installed software on Windows using winget"""
    try:
        result = subprocess.run(
            ["winget", "list"],
            capture_output=True,
            text=True,
            shell=True
        )
        return parse_winget_output(result.stdout)
    except Exception as e:
        print(f"Windows software detection failed: {e}")
        return []

def parse_winget_output(output: str) -> List[Dict]:
    """Parse winget list output with improved version extraction"""
    software_list = []
    lines = output.split('\n')
    
    if len(lines) < 3:
        return software_list
    
    # Skip header lines and look for the data rows
    for line in lines[2:]:
        if not line.strip() or line.strip().startswith('---'):
            continue
        
        # Split on multiple spaces but handle version numbers carefully
        parts = re.split(r'\s{2,}', line.strip())
        
        # The format is typically: Name Version Source
        if len(parts) >= 3:
            name = parts[0].strip()
            version = parts[1].strip()
            source = parts[2].strip()
            
            # Clean up version string (remove architecture if present)
            version = re.sub(r'\s*\(.*\)$', '', version)
            
            software_list.append({
                'name': name,
                'version': version,
                'source': source
            })
    
    return software_list


def get_linux_software() -> List[Dict]:
    """Get installed software on Linux using package manager"""
    try:
        if os.path.exists('/etc/debian_version'):
            return get_apt_packages()
        else:
            return get_rpm_packages()
    except Exception as e:
        print(f"Linux software detection failed: {e}")
        return []

def get_apt_packages() -> List[Dict]:
    """Get installed packages on Debian/Ubuntu"""
    try:
        result = subprocess.run(
            ["apt", "list", "--installed"],
            capture_output=True,
            text=True
        )
        return parse_apt_output(result.stdout)
    except Exception as e:
        print(f"APT package detection failed: {e}")
        return []

def parse_apt_output(output: str) -> List[Dict]:
    """Parse apt list output"""
    packages = []
    for line in output.split('\n')[1:]:  # Skip header
        if not line.strip() or 'now' not in line:
            continue
        name = line.split('/')[0]
        version = line.split('now ')[1].split(' ')[0]
        packages.append({'name': name, 'version': version})
    return packages


def get_rpm_packages() -> List[Dict]:
    """Get installed packages on RHEL/CentOS/Fedora using rpm"""
    try:
        # Query package name and version
        result = subprocess.run(
            ["rpm", "-qa", "--qf", "%{NAME} %{VERSION}\n"],
            capture_output=True,
            text=True
        )
        return parse_rpm_output(result.stdout)
    except Exception as e:
        print(f"RPM package detection failed: {e}")
        return []


def parse_rpm_output(output: str) -> List[Dict]:
    """Parse rpm -qa output formatted as 'NAME VERSION' per line"""
    packages: List[Dict] = []
    for line in output.splitlines():
        if not line.strip():
            continue
        parts = line.strip().split()
        if len(parts) >= 2:
            name = parts[0]
            version = parts[1]
            packages.append({"name": name, "version": version})
    return packages

def update_inventory(machine_id):
    software_items = get_installed_software()
    
    with app.app_context():
        machine = Machine.query.get(machine_id)
        if not machine:
            return
        
        for sw in software_items:
            clean_name = clean_software_name(sw.get('name', ''))
            if not clean_name or clean_name == 'n/a':
                continue

            existing = Software.query.filter(
                (Software.name == clean_name) &
                (Software.machine_id == machine_id)
            ).first()

            if existing:
                existing.installed_version = sw.get('version', existing.installed_version)
                existing.last_updated = datetime.now(timezone.utc)
                existing.source = sw.get('source', 'winget')
            else:
                db.session.add(Software(
                    name=clean_name,
                    package_id=sw.get('id'),
                    installed_version=sw.get('version', 'Unknown'),
                    source=sw.get('source', 'winget'),
                    machine_id=machine_id
                ))
        
        db.session.commit()
        print(f"Inventory updated for machine {machine_id} with {len(software_items)} items")
        

# Vendor-Product mapping for accurate CPE generation
CPE_MAPPINGS = {
    'vlc media player': ('videolan', 'vlc_media_player'),
    'microsoft visual studio': ('microsoft', 'visual_studio'),
    'google chrome': ('google', 'chrome'),
    'mozilla firefox': ('mozilla', 'firefox'),
    'python': ('python', 'python'),
    # Add more mappings as discovered
}

def generate_cpe(software_name: str, version: str) -> str:
    """Generate accurate CPE 2.3 string matching NVD standards"""
    # Check for known mappings first
    lower_name = software_name.lower()
    for pattern, (vendor, product) in CPE_MAPPINGS.items():
        if pattern in lower_name:
            return f"cpe:2.3:a:{vendor}:{product}:{sanitize_version(version)}:*:*:*:*:*:*:*"
    
    # Default generation for unknown software
    vendor = re.sub(r'[^a-z0-9]', '_', software_name.split()[0].lower())
    product = re.sub(r'[^a-z0-9]', '_', software_name.lower().replace(' ', '_'))
    return f"cpe:2.3:a:{vendor}:{product}:{sanitize_version(version)}:*:*:*:*:*:*:*"


def sanitize_version(version: str) -> str:
    """Clean version string for CPE compatibility"""
    return re.sub(r'[^a-zA-Z0-9._-]', '', version.split()[0])


async def get_official_cpe(software_name: str, version: str) -> Optional[str]:
    """Get official CPE from NVD using correct API endpoint"""
    generated_cpe = generate_cpe(software_name, version)
    url = f"https://services.nvd.nist.gov/rest/json/cpes/2.0?cpeMatchString={quote(generated_cpe)}"
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    if data['totalResults'] > 0:
                        return data['products'][0]['cpe']['cpeName']
    except Exception as e:
        print(f"Error fetching official CPE: {e}")
    return None


async def get_cves_by_cpe(cpe: str) -> List[Dict]:
    """Get CVEs with retry logic and rate limiting"""
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={quote(cpe)}"
    
    try:
        async with aiohttp.ClientSession() as session:
            for attempt in range(3):  # Retry up to 3 times
                try:
                    async with session.get(url) as response:
                        if response.status == 200:
                            data = await response.json()
                            return parse_cve_response(data)
                        elif response.status == 403:
                            print("Rate limit exceeded, waiting...")
                            await asyncio.sleep(5)
                            continue
                        else:
                            print(f"NVD API error: {response.status}")
                            return []
                except aiohttp.ClientError as e:
                    print(f"Network error (attempt {attempt+1}): {e}")
                    if attempt < 2:
                        await asyncio.sleep(2)
                        continue
                    return []
    except Exception as e:
        print(f"Error in get_cves_by_cpe: {e}")
    return []


async def get_cpe_from_nvd(software_name: str) -> Optional[str]:
    """Search NVD for official CPE"""
    url = f"https://services.nvd.nist.gov/rest/json/cpes/1.0?keyword={quote(software_name)}"
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    if data['totalResults'] > 0:
                        return data['result']['cpes'][0]['cpe23Uri']
    except Exception as e:
        print(f"Error fetching CPE: {e}")
    return 



async def check_software_cves(software: Software) -> List[Dict]:
    """Comprehensive CVE check using CPE"""
    if not software.installed_version or software.installed_version.lower() == 'unknown':
        return []

    # Try to get official CPE first
    official_cpe = await get_cpe_from_nvd(software.name)
    
    if official_cpe:
        return await get_cves_by_cpe(official_cpe)
    
    # Fallback to generated CPE if no official one found
    generated_cpe = generate_cpe(software.name, software.installed_version)
    return await get_cves_by_cpe(generated_cpe)

# --------------------- CVE Functions ---------------------
async def fetch_cve_for_software(name: str, version: str) -> List[Dict]:
    """Enhanced CVE checking with version comparison"""
    base_url = "https://services.nvd.nist.gov/rest/json/cves/1.0"
    params = {'keyword': name}
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(base_url, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    return filter_cves_by_version(data, version)
                return []
    except Exception as e:
        print(f"Error fetching CVEs: {e}")
        return []

def filter_cves_by_version(cves: List[Dict], version: str) -> List[Dict]:
    """Filter CVEs based on version ranges (if needed)"""
    filtered = []
    for cve in cves:
        # Add any version-specific filtering logic here
        # For now, we'll keep all CVEs since they should already be version-filtered
        filtered.append(cve)
    return filtered


def is_vulnerable_version(installed_version: str, cve_item: Dict) -> bool:
    """Check if installed version falls within vulnerable range"""
    try:
        # Get version ranges from CVE item
        nodes = cve_item.get('configurations', {}).get('nodes', [])
        for node in nodes:
            for cpe_match in node.get('cpe_match', []):
                if not cpe_match.get('vulnerable', True):
                    continue
                
                # Check version ranges
                version_start = cpe_match.get('versionStartIncluding') or cpe_match.get('versionStartExcluding')
                version_end = cpe_match.get('versionEndIncluding') or cpe_match.get('versionEndExcluding')
                
                if version_start and compare_versions(installed_version, version_start) < 0:
                    continue
                if version_end and compare_versions(installed_version, version_end) > 0:
                    continue
                    
                return True
    except Exception:
        pass
    return False


def compare_versions(v1: str, v2: str) -> int:
    """Compare version strings (1 if v1 > v2, -1 if v1 < v2, 0 if equal)"""
    # Remove non-version characters
    v1 = re.sub(r'[^\d.]', '', v1)
    v2 = re.sub(r'[^\d.]', '', v2)
    
    # Split into components
    v1_parts = list(map(int, v1.split('.')))
    v2_parts = list(map(int, v2.split('.')))
    
    # Compare each component
    for i in range(max(len(v1_parts), len(v2_parts))):
        v1_part = v1_parts[i] if i < len(v1_parts) else 0
        v2_part = v2_parts[i] if i < len(v2_parts) else 0
        
        if v1_part > v2_part:
            return 1
        if v1_part < v2_part:
            return -1
    return 0


def parse_cve_response(data: Dict) -> List[Dict]:
    """Parse CVE response from NVD 2.0 API"""
    cves = []
    for vuln in data.get('vulnerabilities', []):
        cve = vuln.get('cve', {})
        cve_id = cve.get('id', '')
        
        # Get description
        description = next(
            (desc['value'] for desc in cve.get('descriptions', []) 
             if desc['lang'] == 'en'),
            'No description available'
        )
        
        # Get severity (CVSS v3 if available)
        metrics = cve.get('metrics', {})
        if 'cvssMetricV31' in metrics:
            severity = metrics['cvssMetricV31'][0]['cvssData']['baseSeverity']
        elif 'cvssMetricV30' in metrics:
            severity = metrics['cvssMetricV30'][0]['cvssData']['baseSeverity']
        else:
            severity = 'UNKNOWN'
        
        cves.append({
            'cve_id': cve_id,
            'description': description,
            'severity': severity
        })
    
    return cves


def export_report_to_csv():
    """Export vulnerability report to CSV"""
    software_list = Software.query.all()
    filename = f"vulnerability_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    try:
        with open(filepath, mode='w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['Software', 'Version', 'Vulnerabilities', 'Severity', 'Last Updated'])
            
            for software in software_list:
                vuln_count = 0
                severity = 'None'
                if software.vulnerabilities:
                    vulns = json.loads(software.vulnerabilities)
                    vuln_count = len(vulns)
                    severity = max([v['severity'] for v in vulns], default='None')
                
                writer.writerow([
                    software.name,
                    software.installed_version,
                    vuln_count,
                    severity,
                    software.last_updated.strftime('%Y-%m-%d %H:%M:%S')
                ])
        return filename
    except Exception as e:
        print(f"Error exporting report: {e}")
        return None


def parse_winget_upgrade(output: str) -> List[Dict]:
    """Improved version detection with regex patterns"""
    updates = []
    version_pattern = re.compile(r'(\d+\.\d+\.?\d*[a-z0-9]*)')
    
    for line in output.split('\n'):
        if not line.strip() or '---' in line:
            continue
            
        # Split on multiple whitespace while preserving version numbers
        parts = re.split(r'\s{2,}', line.strip())
        
        if len(parts) >= 4:
            name = parts[0].strip()
            pkg_id = parts[1].strip()
            current = version_pattern.search(parts[2])
            available = version_pattern.search(parts[3])
            
            updates.append({
                'name': clean_software_name(name),
                'id': pkg_id,
                'current_version': current.group(0) if current else 'Unknown',
                'available_version': available.group(0) if available else 'Unknown'
            })
    
    return updates
    
    # Process each data line
    for line in lines[i+1:]:
        line = line.strip()
        if not line or line.startswith('---'):
            continue
            
        # Split using multiple spaces but preserve version numbers
        parts = re.split(r'\s{2,}', line)
        
        # Handle different output formats
        if len(parts) >= 4:
            name = parts[0].strip()
            pkg_id = parts[1].strip()
            current_version = parts[2].strip()
            available_version = parts[3].strip()
        else:
            continue
        
        # Clean version strings
        current_version = re.sub(r'\s*\(.*\)$', '', current_version)
        available_version = re.sub(r'\s*\(.*\)$', '', available_version)
        
        updates.append({
            'name': name,
            'id': pkg_id,
            'current_version': current_version or 'Unknown',
            'available_version': available_version or 'Unknown'
        })
    
    return updates


def clean_software_name(name: str) -> str:
    """More thorough cleaning of software names for matching"""
    # Remove version numbers
    name = re.sub(r'[\d.]+(?:-\w+)*$', '', name).strip()
    # Remove architecture/bitness indicators
    name = re.sub(r'\(x86\)|\(x64\)|\(ARM\)|\(64-bit\)|\(32-bit\)', '', name, flags=re.IGNORECASE).strip()
    # Remove beta/preview tags
    name = re.sub(r'\b(beta|preview|alpha|rc|release candidate)\b', '', name, flags=re.IGNORECASE).strip()
    # Remove trailing special characters
    return re.sub(r'[-()\s]+$', '', name)


# --------------------- Web Interface ---------------------
@app.route('/')
def index():
    machines = Machine.query.all()
    # Compute dashboard stats across all machines
    total_software = Software.query.count()
    needs_update = Software.query.filter_by(update_available=True).count()
    # Count critical vulns across all software entries
    critical_vulns = 0
    for sw in Software.query.filter(
        Software.vulnerabilities.isnot(None),
        Software.vulnerabilities != '[]'
    ).all():
        try:
            vulns = json.loads(sw.vulnerabilities)
            critical_vulns += sum(1 for v in vulns if isinstance(v, dict) and v.get('severity') == 'CRITICAL')
        except Exception:
            continue

    # Highest risk software list (top 10)
    high_risk_software = Software.query.filter(Software.risk_score >= 1.0)\
        .order_by(Software.risk_score.desc())\
        .limit(10).all()

    stats = {
        'total_machines': len(machines),
        'total_software': total_software,
        'needs_update': needs_update,
        'critical_vulns': critical_vulns,
    }
    
    return render_template('index.html', stats=stats, machines=machines, high_risk_software=high_risk_software)


@app.route('/machines')
def list_machines():
    machines = Machine.query.order_by(Machine.last_seen.desc()).all()
    return render_template('machines.html', machines=machines)


@app.route('/machines/<int:machine_id>/inventory')
def machine_inventory(machine_id: int):
    machine = Machine.query.get_or_404(machine_id)
    return redirect(url_for('view_inventory', machine_id=machine.id))


@app.route('/connect')
def connect_guide():
    """Show connection guide and provide downloadable agent script"""
    server_url = _get_external_server_url(request)
    # Extract IP/host and port for display
    host = server_url.replace('http://', '').replace('https://', '').split('/')
    host_port = host[0]
    parts = host_port.split(':')
    server_ip = parts[0]
    server_port = parts[1] if len(parts) > 1 else ('443' if server_url.startswith('https://') else '80')
    
    return render_template('connect.html', 
                         server_ip=server_ip, 
                         server_port=server_port,
                         server_url=server_url)


@app.route('/download_agent')
def download_agent():
    """Download the agent script for client machines"""
    # Use external-facing URL in the agent script
    server_url = _get_external_server_url(request)
    
    agent_script = f'''#!/usr/bin/env python3
"""
SUMCESA Agent Script
Connects to SUMCESA server and reports installed software.

Usage:
    python sumcesa_agent.py

Requirements:
    - Python 3.6+
    - requests library (pip install requests)
    - Windows: winget command available
    - Linux: apt or rpm package manager
"""

import os
import sys
import json
import platform
import subprocess
import requests
from datetime import datetime
import socket

# Configuration
SERVER_URL = "{server_url}"
MACHINE_ID = platform.node()  # Use hostname as machine ID

def get_installed_software():
    """Get installed software based on platform"""
    if platform.system() == "Windows":
        return get_windows_software()
    elif platform.system() == "Linux":
        return get_linux_software()
    else:
        print(f"Unsupported platform: {{platform.system()}}")
        return []

def get_windows_software():
    """Get installed software on Windows using winget"""
    try:
        result = subprocess.run(
            ["winget", "list", "--disable-interactivity"],
            capture_output=True,
            text=True,
            shell=True,
            timeout=90
        )
        if result.returncode != 0:
            print(f"Winget error: {{result.stderr}}")
            return []
        
        return parse_winget_output(result.stdout)
    except Exception as e:
        print(f"Error getting Windows software: {{e}}")
        return []

def parse_winget_output(output):
    """Parse winget list output"""
    software_list = []
    lines = [line.strip() for line in output.split('\\n') if line.strip()]
    
    # Find header line
    try:
        header_idx = next(i for i, line in enumerate(lines) 
                        if line.startswith("Name") and "Id" in line and "Version" in line)
    except StopIteration:
        return []
    
    # Process data lines
    for line in lines[header_idx+1:]:
        parts = line.split('  ')
        if len(parts) >= 3:
            name = parts[0].strip()
            pkg_id = parts[1].strip()
            version = parts[2].split()[0]
            
            software_list.append({{
                'name': name,
                'id': pkg_id,
                'version': version,
                'source': 'winget'
            }})
    
    return software_list

def get_linux_software():
    """Get installed software on Linux"""
    try:
        if os.path.exists('/etc/debian_version'):
            return get_apt_packages()
        else:
            return get_rpm_packages()
    except Exception as e:
        print(f"Error getting Linux software: {{e}}")
        return []

def get_apt_packages():
    """Get installed packages on Debian/Ubuntu"""
    try:
        result = subprocess.run(
            ["apt", "list", "--installed"],
            capture_output=True,
            text=True
        )
        packages = []
        for line in result.stdout.split('\\n')[1:]:
            if not line.strip() or 'now' not in line:
                continue
            name = line.split('/')[0]
            version = line.split('now ')[1].split(' ')[0]
            packages.append({{'name': name, 'version': version, 'source': 'apt'}})
        return packages
    except Exception as e:
        print(f"APT package detection failed: {{e}}")
        return []

def get_rpm_packages():
    """Get installed packages on RHEL/CentOS/Fedora"""
    try:
        result = subprocess.run(
            ["rpm", "-qa", "--qf", "%{{NAME}} %{{VERSION}}\\n"],
            capture_output=True,
            text=True
        )
        packages = []
        for line in result.stdout.splitlines():
            if not line.strip():
                continue
            parts = line.strip().split()
            if len(parts) >= 2:
                packages.append({{
                    'name': parts[0],
                    'version': parts[1],
                    'source': 'rpm'
                }})
        return packages
    except Exception as e:
        print(f"RPM package detection failed: {{e}}")
        return []

def register_machine():
    """Register this machine with the SUMCESA server"""
    try:
        response = requests.post(f"{{SERVER_URL}}/api/register", json={{
            'machine_id': MACHINE_ID,
            'hostname': platform.node(),
            'os': f"{{platform.system()}} {{platform.release()}}"
        }}, timeout=10)
        
        if response.status_code == 200:
            print(f"✓ Machine registered successfully")
            return True
        else:
            print(f"✗ Registration failed: {{response.status_code}}")
            return False
    except Exception as e:
        print(f"✗ Registration error: {{e}}")
        return False

def report_software(software_list):
    """Report software inventory to the server"""
    try:
        response = requests.post(f"{{SERVER_URL}}/api/report", json={{
            'machine_id': MACHINE_ID,
            'software': software_list
        }}, timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            print(f"✓ Reported {{data.get('processed', 0)}} software items")
            return True
        else:
            print(f"✗ Report failed: {{response.status_code}}")
            return False
    except Exception as e:
        print(f"✗ Report error: {{e}}")
        return False

def main():
    print("SUMCESA Agent - Software Inventory Reporter")
    print("=" * 50)
    print(f"Server: {{SERVER_URL}}")
    print(f"Machine ID: {{MACHINE_ID}}")
    print(f"Platform: {{platform.system()}} {{platform.release()}}")
    print()
    
    # Step 1: Register machine
    print("Step 1: Registering machine...")
    if not register_machine():
        print("Failed to register machine. Exiting.")
        sys.exit(1)
    
    # Step 2: Get software inventory
    print("\\nStep 2: Scanning installed software...")
    software_list = get_installed_software()
    print(f"Found {{len(software_list)}} installed applications")
    
    if not software_list:
        print("No software found. Exiting.")
        sys.exit(1)
    
    # Step 3: Report to server
    print("\\nStep 3: Reporting to server...")
    if report_software(software_list):
        print("\\n✓ Successfully connected to SUMCESA server!")
        print(f"View your machine at: {{SERVER_URL}}/machines")
    else:
        print("\\n✗ Failed to report to server.")
        print("\\n✗ Allow firewall exceptions for SUMCESA server.")
        sys.exit(1)

if __name__ == "__main__":
    main()
'''
    
    response = make_response(agent_script)
    response.headers['Content-Type'] = 'text/plain'
    response.headers['Content-Disposition'] = 'attachment; filename=sumcesa_agent.py'
    return response

@app.route('/download_agent_ps1')
def download_agent_ps1():
    """Download the PowerShell agent script"""
    server_url = _get_external_server_url(request)
    
    ps_script = f'''# SUMCESA PowerShell Agent
param(
    [string]$ServerUrl = "{server_url}"
)

$ErrorActionPreference = "Stop"

function Write-Log {{
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp $Level] $Message"
}}

function Register-Machine {{
    param([string]$MachineId, [string]$Hostname, [string]$OS)
    
    $body = @{{
        machine_id = $MachineId
        hostname = $Hostname
        os = $OS
    }} | ConvertTo-Json
    
    try {{
        $response = Invoke-RestMethod -Uri "$ServerUrl/api/register" -Method Post -Body $body -ContentType "application/json" -TimeoutSec 30
        Write-Log "Machine registered successfully"
        return $true
    }}
    catch {{
        Write-Log "Registration failed: $($_.Exception.Message)" "ERROR"
        return $false
    }}
}}

function Get-SoftwareInventory {{
    Write-Log "Scanning installed software..."
    
    try {{
        $output = winget list --disable-interactivity
        $software = @()
        $lines = $output -split "\r?\n"
        $headerFound = $false
        
        foreach ($line in $lines) {{
            if (-not $headerFound -and $line -match "Name\s+Id\s+Version") {{
                $headerFound = $true
                continue
            }}
            
            if ($headerFound -and $line.Trim() -and $line -notmatch "^-+$") {{
                $parts = $line.Trim() -split "\s{{2,}}"

                # Columns: Name | Id | Version | Available | (Source is ignored)
                $name      = $parts[0]
                $id        = if ($parts.Count -ge 2) {{ $parts[1] }} else {{ "" }}
                $version   = if ($parts.Count -ge 3) {{ $parts[2] }} else {{ "" }}
                $available = if ($parts.Count -ge 4 -and $parts[3] -ne "winget") {{ $parts[3].Trim() }} else {{ "" }}
                
                # If "winget" is in 4th or 5th column, treat it as source
                $source = if ($parts -contains "winget") {{ "winget" }} else {{ "unknown" }}


                $software += @{{
                    name = $name
                    id = $id
                    version = $version
                    available = $available
                    source = $source
                }}
            }}
        }}
        
        Write-Log "Found $($software.Count) installed applications"
        return $software
    }}
    catch {{
        Write-Log "Software scan failed: $($_.Exception.Message)" "ERROR"
        return @()
    }}
}}

function Report-Software {{
    param($MachineId, $Software)
    
    $body = @{{
        machine_id = $MachineId
        software = $Software
    }} | ConvertTo-Json -Depth 10
    
    try {{
        $response = Invoke-RestMethod -Uri "$ServerUrl/api/report" -Method Post -Body $body -ContentType "application/json" -TimeoutSec 60
        Write-Log "Reported $($response.processed) software items"
        return $true
    }}
    catch {{
        Write-Log "Report failed: $($_.Exception.Message)" "ERROR"
        return $false
    }}
}}

# Main execution
Write-Log "SUMCESA PowerShell Agent Started"
Write-Log "Server: $ServerUrl"

$machineId = $env:COMPUTERNAME
$hostname = $env:COMPUTERNAME
$os = (Get-WmiObject -Class Win32_OperatingSystem).Caption

# Register machine
if (-not (Register-Machine -MachineId $machineId -Hostname $hostname -OS $os)) {{
    exit 1
}}

# Get software inventory
$software = Get-SoftwareInventory
if ($software.Count -eq 0) {{
    Write-Log "No software found, exiting" "ERROR"
    exit 1
}}

# Report to server
if (Report-Software -MachineId $machineId -Software $software) {{
    Write-Log "Inventory report completed successfully"
    Write-Log "View your machine at: $ServerUrl/machines"
}} else {{
    Write-Log "Inventory report failed" "ERROR"
    exit 1
}}
'''
    
    response = make_response(ps_script)
    response.headers['Content-Type'] = 'text/plain'
    response.headers['Content-Disposition'] = 'attachment; filename=sumcesa_agent.ps1'
    return response


@app.route('/download_agent_bat')
def download_agent_bat():
    """Download a Windows batch file agent that uses a separate PowerShell script"""
    server_url = _get_external_server_url(request)
    
    bat_content = f'''@echo off
setlocal enabledelayedexpansion

echo ================================================
echo SUMCESA Agent - Windows Batch File
echo ================================================
echo Start Time: %date% %time%
echo Server: {server_url}
echo ================================================
echo.

echo [INFO] Step 1: Downloading PowerShell agent script...
powershell -ExecutionPolicy Bypass -NoLogo -NoProfile -Command ^
    "try {{ Invoke-WebRequest -Uri '{server_url}/download_agent_ps1' -OutFile 'sumcesa_agent.ps1'; Write-Host '[SUCCESS] PowerShell script downloaded' }} catch {{ Write-Host '[ERROR] Failed to download script:' $_.Exception.Message; exit 1 }}"

echo.
echo [INFO] Step 2: Executing PowerShell agent script...
powershell -ExecutionPolicy Bypass -File "sumcesa_agent.ps1" -ServerUrl "{server_url}"

if errorlevel 1 (
    echo.
    echo [ERROR] ================================================
    echo [ERROR] POWERSHELL SCRIPT EXECUTION FAILED!
    echo [ERROR] ================================================
    echo [ERROR] Check the error messages above for details.
    echo [ERROR] ================================================
    echo.
    set "ERROR_OCCURRED=1"
    pause
    exit /b 1
)

echo.
echo [INFO] Step 3: Cleaning up...
del sumcesa_agent.ps1 2>nul

echo.
echo [SUCCESS] ================================================
echo [SUCCESS] BATCH FILE COMPLETED SUCCESSFULLY!
echo [SUCCESS] ================================================
echo [SUCCESS] End Time: %date% %time%
echo [SUCCESS] All steps completed without errors.
echo [SUCCESS] Your machine should now be visible in the SUMCESA dashboard.
echo [SUCCESS] ================================================
echo.
echo [INFO] Press any key to close this window...
pause >nul
'''
    
    response = make_response(bat_content)
    response.headers['Content-Type'] = 'text/plain'
    response.headers['Content-Disposition'] = 'attachment; filename=sumcesa_agent.bat'
    return response
    

def _get_external_server_url(req) -> str:
    """Determine an external-facing base URL for this server.
    Preference order:
      1) X-Forwarded-Proto + X-Forwarded-Host (behind proxies)
      2) req.scheme + req.host (as seen by the client)
      3) Replace localhost/127.0.0.1 with LAN IP
    """
    # Proxy headers
    xf_proto = req.headers.get('X-Forwarded-Proto')
    xf_host = req.headers.get('X-Forwarded-Host')
    if xf_proto and xf_host:
        return f"{xf_proto}://{xf_host}"

    scheme = req.scheme or 'http'
    host = req.host

    # If localhost, substitute with LAN IP
    hostname_only = host.split(':')[0]
    port = host.split(':')[1] if ':' in host else None
    if hostname_only in ('127.0.0.1', 'localhost'):
        try:
            # Determine LAN IP by opening a UDP socket
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                lan_ip = s.getsockname()[0]
            if port:
                return f"{scheme}://{lan_ip}:{port}"
            return f"{scheme}://{lan_ip}"
        except Exception:
            # Fallback to request.host_url
            return req.host_url.rstrip('/')

    return f"{scheme}://{host}"

@app.route('/inventory')
def view_inventory():
    # Optional filter by machine_id to support multi-machine view
    machine_id = request.args.get('machine_id', type=int)
    query = Software.query
    selected_machine = None
    if machine_id:
        query = query.filter_by(machine_id=machine_id)
        selected_machine = Machine.query.get(machine_id)

    software_list = query.order_by(Software.name).all()

    # Render directly from database without live augmentation to avoid repeated scans
    enhanced_list = []
    for software in software_list:
        enhanced_list.append({
            'id': software.id,
            'name': software.name,
            'installed_version': software.installed_version,
            'latest_version': software.latest_version,
            'vulnerabilities': software.vulnerabilities,
            'last_updated': software.last_updated,
            'update_available': software.update_available
        })

    machines = Machine.query.order_by(Machine.hostname).all()
    return render_template(
        'inventory.html',
        software_list=enhanced_list,
        machines=machines,
        selected_machine=selected_machine
    )

def get_winget_output(command: str, timeout: int = 60) -> Optional[str]:
    """Improved winget command execution with better error handling"""
    try:
        result = subprocess.run(
            ["winget"] + command.split(),
            capture_output=True,
            text=True,
            shell=True,
            timeout=timeout,
            check=True,
            encoding='utf-8',
            errors='ignore'
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Winget command failed: {e.stderr}")
        return None
    except Exception as e:
        print(f"Error executing winget: {str(e)}")
        return None


def clean_software_name(name: str) -> str:
    """Advanced name normalization with edge case handling"""
    if not name or name.lower() in ('n/a', 'unknown'):
        return ''
    
    # Remove version strings and special characters
    name = re.sub(r'[\d.]+(?:-\w+)*$', '', name, flags=re.IGNORECASE)
    name = re.sub(r'[^a-zA-Z0-9\s]', '', name)
    
    # Standardize casing and spacing
    name = name.strip().title()
    name = re.sub(r'\s+', ' ', name)
    
    # Remove platform/edition markers
    markers = {'x64', 'x86', 'arm64', 'preview', 'beta', 'release'}
    name = ' '.join([word for word in name.split() 
                   if word.lower() not in markers])
    
    return name

    return re.sub(r'\s+', ' ', name).strip()

def clean_version(version: str) -> str:
    """Extract clean version numbers from strings"""
    match = re.search(r'(\d+\.\d+\.?\d*[a-z0-9]*)', version)
    return match.group(0) if match else 'Unknown'

@app.route('/refresh_versions')
def refresh_versions():
    """Force reload all version data"""
    update_inventory()
    check_updates(refresh=True)
    flash("Software versions refreshed successfully", "success")
    return redirect(url_for('check_updates'))

@app.route('/check_updates')
def check_updates():
    refresh = request.args.get('refresh', 'false').lower() == 'true'
    
    if refresh:
        try:
            Software.query.update({'update_available': False})
            db.session.commit()
            
            output = get_winget_output("upgrade")
            updates = parse_winget_upgrade(output) if output else []
            
            update_count = 0
            for update in updates:
                software = Software.query.filter(
                    (Software.package_id == update['id']) |
                    (func.lower(Software.name) == func.lower(update['name']))
                ).first()
                
                if software:
                    software.update_available = True
                    software.latest_version = update['available_version']
                    software.installed_version = update['current_version']
                    
                    # Force vulnerability check for updated software
                    cves = asyncio.run(check_software_cves(software))
                    software.vulnerabilities = json.dumps(cves)
                    software.risk_score = calculate_risk_score(cves)
                    software.last_checked = datetime.now(timezone.utc)
                    
                    update_count += 1
            
            db.session.commit()
            flash(f"Found {update_count} available updates", "success")
            
        except Exception as e:
            flash(f"Error checking updates: {str(e)}", "danger")
    
    updates = Software.query.filter_by(update_available=True).all()
    return render_template('check_updates.html',
                         updates=updates,
                         update_count=len(updates))



def should_check_vulnerabilities(software: Software) -> bool:
    """Determine if we should check for vulnerabilities"""
    if not software.vulnerabilities:
        return True
    if not software.last_checked:
        return True
        
    # Convert both datetimes to aware datetimes in UTC
    now = datetime.now(timezone.utc)
    last_checked = software.last_checked.replace(tzinfo=timezone.utc)
    
    return (now - last_checked).days > 0


@app.cli.command('clean-inventory')
def clean_inventory():
    """CLI command to fix duplicate entries"""
    with app.app_context():
        # Remove entries with empty names
        Software.query.filter(
            (Software.name == '') | 
            (Software.name.is_(None))
        ).delete()
        
        # Merge duplicates
        duplicates = db.session.query(
            Software.name,
            func.count(Software.name).label('count')
        ).group_by(Software.name).having(func.count(Software.name) > 1)
        
        for dup in duplicates:
            # Keep most recent entry
            keep = Software.query.filter_by(name=dup.name)\
                       .order_by(Software.last_updated.desc())\
                       .first()
                       
            # Delete older duplicates
            Software.query.filter(
                (Software.name == dup.name) &
                (Software.id != keep.id)
            ).delete()
        
        db.session.commit()
    print("Inventory cleanup completed")


@app.route('/cpe_debug/<int:software_id>')
async def cpe_debug(software_id):
    """Enhanced debug view with detailed CVE info"""
    software = Software.query.get_or_404(software_id)
    cves = []
    official_cpe = generated_cpe = None
    
    try:
        if not software.installed_version or software.installed_version.lower() == 'unknown':
            flash("Cannot check CVEs for software with unknown version", "warning")
            return redirect_back()

        # Get all possible CPEs
        official_cpe = await get_official_cpe(software.name, software.installed_version)
        generated_cpe = generate_cpe(software.name, software.installed_version)

        # Check using all methods
        cves_cpe = await get_cves_by_cpe(official_cpe) if official_cpe else []
        cves_generated = await get_cves_by_cpe(generated_cpe)
        cves_keyword = await search_cves_by_keyword(software.name, software.installed_version)
        
        # Combine unique CVEs
        seen = set()
        all_cves = []
        for cve in cves_cpe + cves_generated + cves_keyword:
            if cve['cve_id'] not in seen:
                seen.add(cve['cve_id'])
                all_cves.append(cve)
                
        # Sort by severity
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        all_cves.sort(key=lambda x: severity_order.get(x['severity'], 4))

        # Update the software record
        software.vulnerabilities = json.dumps(all_cves)
        software.last_checked = datetime.now(timezone.utc)
        software.risk_score = calculate_risk_score(all_cves)
        db.session.commit()

    except Exception as e:
        print(f"Error in cpe_debug: {e}")
        db.session.rollback()
        flash(f"Error checking CVEs: {str(e)}", "danger")

    return render_template(
        'cpe_debug.html',
        software=software,
        official_cpe=official_cpe,
        generated_cpe=generated_cpe,
        cves=all_cves,
        cve_sources={
            'official_cpe': len(cves_cpe) if official_cpe else 0,
            'generated_cpe': len(cves_generated),
            'keyword': len(cves_keyword)
        }
    )

async def check_software_vulnerabilities(software_name: str, version: str) -> List[Dict]:
    """Comprehensive CVE check using multiple methods"""
    # Method 1: Try official CPE first
    official_cpe = await get_official_cpe(software_name, version)
    if official_cpe:
        cves = await get_cves_by_cpe(official_cpe)
        if cves:
            return cves
    
    # Method 2: Try generated CPE
    generated_cpe = generate_cpe(software_name, version)
    cves = await get_cves_by_cpe(generated_cpe)
    if cves:
        return cves
    
    # Method 3: Fallback to keyword search with version filter
    return await search_cves_by_keyword(software_name, version)


async def search_cves_by_keyword(name: str, version: str) -> List[Dict]:
    """Fallback CVE search using keywords and version filtering"""
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={quote(name)}"
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    return [
                        {
                            'cve_id': vuln['cve']['id'],
                            'description': next(
                                desc['value'] for desc in vuln['cve']['descriptions']
                                if desc['lang'] == 'en'
                            ),
                            'severity': vuln['cve']['metrics'].get('cvssMetricV31', [{}])[0]
                                        .get('cvssData', {}).get('baseSeverity', 'UNKNOWN')
                        }
                        for vuln in data.get('vulnerabilities', [])
                        if is_version_affected(vuln, version)
                    ]
    except Exception as e:
        print(f"Error in keyword search: {e}")
    return []


def is_version_affected(vuln: Dict, version: str) -> bool:
    """Check if the vulnerability affects our specific version"""
    # Check version ranges in configurations
    for node in vuln['cve'].get('configurations', []):
        for match in node.get('nodes', []):
            for cpe_match in match.get('cpeMatch', []):
                if not cpe_match.get('vulnerable', True):
                    continue
                
                # Check version start/end ranges
                version_start = cpe_match.get('versionStartIncluding') or cpe_match.get('versionStartExcluding')
                version_end = cpe_match.get('versionEndIncluding') or cpe_match.get('versionEndExcluding')
                
                if version_start and compare_versions(version, version_start) < 0:
                    continue
                if version_end and compare_versions(version, version_end) > 0:
                    continue
                
                return True
    return False


@app.route('/check_cves/<int:software_id>')
def check_cves(software_id):
    software = Software.query.get_or_404(software_id)
    
    try:
        cves = asyncio.run(fetch_cve_for_software(
            software.name,
            software.installed_version
        ))
        software.vulnerabilities = json.dumps(cves)
        db.session.commit()
        
        flash(f"Found {len(cves)} vulnerabilities for {software.name}", 'success')
    except Exception as e:
        flash(f"Error checking CVEs: {str(e)}", 'danger')
    
    return redirect(url_for('view_inventory'))


@app.route('/export_report')
def export_report():
    filename = export_report_to_csv()
    if filename:
        return send_from_directory(
            app.config['UPLOAD_FOLDER'],
            filename,
            as_attachment=True
        )
    else:
        flash('Failed to generate report', 'danger')
        return redirect(url_for('cve_report'))

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected', 'danger')
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            flash('No file selected', 'danger')
            return redirect(request.url)
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            
            # Process the uploaded file
            try:
                if filename.endswith('.csv'):
                    # Process CSV file
                    pass
                elif filename.endswith('.json'):
                    # Process JSON file
                    pass
                
                flash('File uploaded and processed successfully', 'success')
                return redirect(url_for('index'))
            except Exception as e:
                flash(f'Error processing file: {str(e)}', 'danger')
        
        else:
            flash('Invalid file type', 'danger')
    
    return render_template('upload.html')

@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if request.method == 'POST':
        new_interval = request.form.get('inventory_interval')
        try:
            global INVENTORY_UPDATE_INTERVAL
            INVENTORY_UPDATE_INTERVAL = int(new_interval)
            try:
                scheduler.reschedule_job('inventory_update', trigger='interval', minutes=INVENTORY_UPDATE_INTERVAL)
                flash('Settings updated successfully', 'success')
            except Exception as e:
                print(f"Error rescheduling job: {e}")
                flash('Settings updated but scheduler error occurred', 'warning')
        except ValueError:
            flash('Invalid interval value', 'danger')
    
    return render_template('settings.html', current_interval=INVENTORY_UPDATE_INTERVAL)


@app.route('/cpe_details')
def cpe_details():
    """Show CPE details for vulnerable software"""
    vulnerable_software = Software.query.filter(
        Software.risk_score > 0.0,
        Software.vulnerabilities.isnot(None),
        Software.vulnerabilities != '[]'
    ).all()
    
    cpe_data = []
    for software in vulnerable_software:
        vulns = json.loads(software.vulnerabilities) if software.vulnerabilities else []
        cpe_data.append({
            'software': software,
            'generated_cpe': generate_cpe(software.name, software.installed_version),
            'vulnerability_count': len(vulns),
            'has_vulnerabilities': bool(vulns)
        })
    
    return render_template('cpe_details.html', cpe_data=cpe_data)


@app.route('/refresh_cpe/<int:software_id>')
async def refresh_cpe(software_id):
    """Refresh CPE data for a specific software"""
    software = Software.query.get_or_404(software_id)
    
    # Get fresh CPE and CVE data
    official_cpe = await get_cpe_from_nvd(software.name)
    cves = await check_software_cves(software)
    
    # Update the software record
    software.vulnerabilities = json.dumps(cves)
    db.session.commit()
    
    flash(f"Refreshed CPE data for {software.name}", "success")
    return redirect(url_for('cpe_details'))


# --------------------- Template Filters ---------------------
@app.template_filter('severity_badge')
def severity_badge(severity):
    color = get_severity_color(severity)
    return f'<span class="badge bg-{color}">{severity}</span>'


@app.template_filter('datetimeformat')
def datetimeformat(value, format='%Y-%m-%d %H:%M'):
    if value is None:
        return ""
    return value.strftime(format)


# --------------------- Risk Scoring System ---------------------
def calculate_risk_score(vulnerabilities: List[Dict]) -> float:
    """Strict scoring with validation"""
    if not vulnerabilities or not isinstance(vulnerabilities, list):
        return 0.0
        
    severity_weights = {
        'CRITICAL': 1.0,
        'HIGH': 0.7,
        'MEDIUM': 0.4,
        'LOW': 0.1
    }
    
    total = sum(
        severity_weights.get(v.get('severity', '').upper(), 0.0)
        for v in vulnerabilities
        if isinstance(v, dict) and 'severity' in v
    )
    
    return min(total * 10, 10.0)

def generate_recommendation(software: Software) -> str:
    """Generate human-readable recommendation"""
    if not software.update_available:
        return "No action needed - software is up to date"
    
    vulns = json.loads(software.vulnerabilities) if software.vulnerabilities else []
    crit_count = sum(1 for v in vulns if v.get('severity') == 'CRITICAL')
    
    if crit_count > 0:
        return f"❗ Urgent: Update immediately ({crit_count} critical vulnerabilities)"
    elif software.risk_score > 5:
        return "⚠️ Recommended: Update as soon as possible"
    else:
        return "ℹ️ Suggested: Update when convenient"
    

def get_winget_output(command: str, timeout: int = 30) -> Optional[str]:
    """Safely execute winget command with timeout"""
    try:
        result = subprocess.run(
            ["winget"] + command.split(),
            capture_output=True,
            text=True,
            shell=True,
            timeout=timeout
        )
        if result.returncode == 0:
            return result.stdout
        return None
    except subprocess.TimeoutExpired:
        print(f"Winget command timed out: {command}")
        return None
    except Exception as e:
        print(f"Error executing winget: {e}")
        return None

def refresh_software_list():
    """Refresh the complete software list"""
    try:
        output = get_winget_output("list")
        if not output:
            raise Exception("Failed to get software list from winget")
            
        software_items = parse_winget_list(output)
        
        with app.app_context():
            # Clear existing data
            db.session.query(Software).delete()
            
            for sw in software_items:
                new_sw = Software(
                    name=clean_software_name(sw['name']),
                    package_id=sw.get('id'),
                    installed_version=sw.get('version'),
                    source=sw.get('source', 'winget'),
                    last_updated=datetime.now(timezone.utc)
                )
                db.session.add(new_sw)
            
            db.session.commit()
            return True
    except Exception as e:
        print(f"Error refreshing software list: {e}")
        return False
    


def redirect_back(default='index'):
    """Redirect to previous page or default"""
    return redirect(request.referrer or url_for(default))

def refresh_software_data(software: Software):
    """Refresh a single software's data from winget"""
    output = get_winget_output(f"list --id {software.package_id}" if software.package_id else f"list --name {software.name}")
    if output:
        items = parse_winget_list(output)
        if items and len(items) > 0:
            software.installed_version = items[0].get('version', software.installed_version)
            
# --------------------- Agent Registration API ---------------------
@app.route('/api/register', methods=['POST'])
def register_machine():
    data = request.json
    machine_id = data.get('machine_id')
    hostname = data.get('hostname')
    ip_address = request.remote_addr
    os = data.get('os')
    
    machine = Machine.query.filter_by(machine_id=machine_id).first()
    if not machine:
        machine = Machine(
            machine_id=machine_id,
            hostname=hostname,
            ip_address=ip_address,
            os=os
        )
        db.session.add(machine)
    else:
        machine.last_seen = datetime.now(timezone.utc)
    
    db.session.commit()
    return jsonify({'status': 'success', 'machine_id': machine.id})
    

# --------------------- Data Reporting API ---------------------
def clean_version(version_str):
    if not version_str:
        return ''
    # Remove "winget" or any non-version trailing text
    return version_str.replace("winget", "").strip()

@app.route('/api/report', methods=['POST'])
def receive_report():
    try:
        data = request.json
        print("[DEBUG] Incoming payload:", data)

        machine_id = data.get('machine_id')
        software_list = data.get('software', [])
        updates_list = data.get('updates', [])

        machine = Machine.query.filter_by(machine_id=machine_id).first()
        if not machine:
            return jsonify({'error': 'Machine not registered'}), 400

        # Process reported software
        for sw in software_list:
            print("[DEBUG] Processing software:", sw)

            available_clean = clean_version(sw.get('available', ''))
            version_clean = clean_version(sw.get('version', ''))

            software = Software.query.filter_by(
                name=sw['name'],
                machine_id=machine.id
            ).first()

            if software:
                software.installed_version = version_clean
                if available_clean:
                    software.latest_version = available_clean
                    software.update_available = (software.latest_version != software.installed_version)
                else:
                    software.update_available = False
                software.last_updated = datetime.now(timezone.utc)
            else:
                software = Software(
                    name=sw['name'],
                    installed_version=version_clean,
                    latest_version=available_clean or '',
                    update_available=bool(available_clean and available_clean != version_clean),
                    machine_id=machine.id,
                    source=sw.get('source', 'unknown')
                )
                db.session.add(software)

        # Process available updates (legacy support)
        for upd in updates_list:
            print("[DEBUG] Processing update:", upd)
            name = upd.get('name')
            current_v = upd.get('current_version') or upd.get('current')
            available_v = upd.get('available_version') or upd.get('available')

            if not name:
                print("[WARN] Skipping update entry without name:", upd)
                continue

            software = Software.query.filter_by(
                name=name,
                machine_id=machine.id
            ).first()

            if not software:
                software = Software(
                    name=name,
                    installed_version=current_v or 'Unknown',
                    machine_id=machine.id,
                    source='winget'
                )
                db.session.add(software)

            software.update_available = bool(available_v and (available_v != software.installed_version))
            if current_v:
                software.installed_version = current_v
            if available_v:
                software.latest_version = available_v

        print("[DEBUG] Preparing to commit software records for machine:", machine_id)
        for s in Software.query.filter_by(machine_id=machine.id).all():
            print(f"[DEBUG] {s.name} | Installed: {s.installed_version} | Latest: {s.latest_version} | "
                  f"Update Available: {s.update_available} | Source: {s.source}")

        # ✅ Commit once, after processing everything
        try:
            db.session.commit()
            print("[DEBUG] Commit successful.")
            return jsonify({
                'status': 'success',
                'processed': len(software_list),
                'updates': len(updates_list)
            })
        except Exception as e:
            import traceback
            db.session.rollback()
            print("[ERROR] DB Commit failed:", str(e))
            traceback.print_exc()
            return jsonify({'error': 'DB Commit Failed', 'details': str(e)}), 500

    except Exception as e:
        import traceback
        print("[ERROR] Unexpected failure in /api/report:", str(e))
        traceback.print_exc()
        return jsonify({'error': 'Unexpected failure', 'details': str(e)}), 500


# --------------------- Scheduler Setup ---------------------
def init_scheduler():
    if not scheduler.running:
        # Add the inventory update job if it doesn't exist
        try:
            scheduler.add_job(
                func=lambda: _update_all_machines_inventory(),
                trigger='interval',
                minutes=INVENTORY_UPDATE_INTERVAL,
                id='inventory_update',
                replace_existing=True
            )
        except Exception as e:
            print(f"Error adding inventory update job: {e}")
        
        scheduler.start()


def _update_all_machines_inventory():
    """Iterate over all registered machines and refresh their inventory.
    Note: This function triggers local inventory refresh logic. Remote machines
    should post data via /api/report from their agent; here we keep data fresh
    for the server host if applicable.
    """
    with app.app_context():
        machines = Machine.query.all()
        for m in machines:
            try:
                # Only perform local refresh for the server host (marker)
                if m.machine_id == 'local':
                    update_inventory(m.id)
            except Exception as e:
                print(f"Inventory update failed for machine {m.id}: {e}")


# --------------------- Initialization ---------------------
with app.app_context():
    try:
        db.create_all()
        print("Database tables created successfully")
        # Ensure a local machine record exists to represent the server host
        local_machine = Machine.query.filter_by(machine_id='local').first()
        if not local_machine:
            local_machine = Machine(
                machine_id='local',
                hostname=platform.node(),
                ip_address='127.0.0.1',
                os=f"{platform.system()} {platform.release()}"
            )
            db.session.add(local_machine)
            db.session.commit()
    except Exception as e:
        # Log the error; absolute DB path is in app.instance_path
        print(f"Error creating database tables: {e}")

# --------------------- Main Entry Point ---------------------
if __name__ == '__main__':
    # Initialize scheduler only when running the app directly
    init_scheduler()
    try:
        app.run(debug=True, host='0.0.0.0', port=5000)
    finally:
        try:
            if scheduler.running:
                scheduler.shutdown()
        except Exception as e:
            print(f"Error shutting down scheduler: {e}")