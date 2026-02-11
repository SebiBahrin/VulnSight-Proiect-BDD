import random
import hashlib
from faker import Faker
from datetime import datetime, timedelta

# CONFIGURARE GENERALĂ
fake = Faker()
NUM_ASSETS = 50
NUM_VULNS = 100
NUM_SCANS = 20
NUM_DETECTED = 1200 
NUM_AUDIT_LOGS = 50 
OUTPUT_FILE = "02_populare_date_vulnsight.sql"

# Liste statice de date
DEPARTMENTS = [
    ('IT Operations', 50000, 1.5),
    ('HR', 10000, 0.8),
    ('Finance', 30000, 1.2),
    ('Marketing', 15000, 0.9),
    ('Development', 45000, 1.4)
]

TEAMS = [
    ('Infra Defenders', 'Ion Popescu', 'Infrastructure'),
    ('AppSec Guardians', 'Maria Ionescu', 'AppSec'),
    ('Compliance Watch', 'Andrei Radu', 'Compliance'),
    ('NetPatrol', 'Elena Dumitrescu', 'Network') 
]

APP_USERS_DATA = [
    ('admin_sys', 'Admin'),
    ('ciso_manager', 'CISO'),
    ('auditor_ext', 'Auditor'),
    ('dev_lead', 'Viewer'),
    ('sec_analyst', 'Viewer')
]

# FUNCȚII HELPER
def oracle_date(date_obj):
    """Formatează data pentru Oracle TO_DATE."""
    return f"TO_DATE('{date_obj.strftime('%Y-%m-%d %H:%M:%S')}', 'YYYY-MM-DD HH24:MI:SS')"

def escape_sql(text):
    """Escapează caracterele speciale pentru SQL (ex. apostrof)."""
    if text:
        return text.replace("'", "''")
    return ""

def generate_hash(text):
    """Generează un hash dummy (SHA256) pentru parole."""
    return hashlib.sha256(text.encode()).hexdigest()

# GENERARE SCRIPT
print("Generare script SQL complet...")

with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    f.write("/* SCRIPT GENERAT AUTOMAT PENTRU POPULARE DATE VULNSIGHT */\n")
    f.write("/* Ordine: Nomenclatoare -> Active -> Tranzactii -> Loguri */\n\n")

    # 1. DEPARTMENTS
    f.write("-- 1. Inserare Departamente\n")
    for name, budget, risk in DEPARTMENTS:
        f.write(f"INSERT INTO DEPARTMENTS (Dept_Name, Budget, Risk_Weight) VALUES ('{name}', {budget}, {risk});\n")
    f.write("\n")

    # 2. SECURITY_TEAMS
    f.write("-- 2. Inserare Echipe de Securitate\n")
    # Salvăm ID-urile echipelor pentru referință (presupunem 1..N)
    team_ids_list = list(range(1, len(TEAMS) + 1))

    for name, lead, spec in TEAMS:
        f.write(f"INSERT INTO SECURITY_TEAMS (Team_Name, Team_Lead, Specialization) VALUES ('{name}', '{lead}', '{spec}');\n")
    f.write("\n")

    # 3. VULNERABILITY_DB
    f.write("-- 3. Inserare Catalog Vulnerabilități (CVE)\n")
    cve_ids = []
    for i in range(NUM_VULNS):
        cve_id = f"CVE-{random.randint(2020, 2025)}-{random.randint(1000, 9999)}"
        cve_ids.append(cve_id)

        desc = escape_sql(fake.sentence(nb_words=12))
        base_score = round(random.uniform(1.0, 10.0), 1)

        if base_score >= 9.0: severity = 'Critical'
        elif base_score >= 7.0: severity = 'High'
        elif base_score >= 4.0: severity = 'Medium'
        else: severity = 'Low'

        f.write(f"INSERT INTO VULNERABILITY_DB (CVE_ID, Description, Base_Score, Severity, Published_Date) "
                f"VALUES ('{cve_id}', '{desc}', {base_score}, '{severity}', SYSDATE - {random.randint(10, 300)});\n")
    f.write("\n")

    # 4. SCAN_SESSIONS
    f.write("-- 4. Inserare Sesiuni de Scanare\n")
    session_ids = []
    for i in range(1, NUM_SCANS + 1):
        session_ids.append(i)
        scan_date = fake.date_time_between(start_date='-1y', end_date='now')
        tool = random.choice(['Nessus', 'Qualys', 'OpenVAS', 'Rapid7'])
        operator = fake.name()
        f.write(f"INSERT INTO SCAN_SESSIONS (Scan_Date, Tool_Used, Scanner_Operator) "
                f"VALUES ({oracle_date(scan_date)}, '{tool}', '{operator}');\n")
    f.write("\n")

    # 5. APP_USERS
    f.write("-- 5. Inserare Utilizatori Aplicație\n")
    for username, role in APP_USERS_DATA:
        pass_hash = generate_hash(username + "123") 
        f.write(f"INSERT INTO APP_USERS (Username, Password_Hash, Role) "
                f"VALUES ('{username}', '{pass_hash}', '{role}');\n")
    f.write("\n")

    # 6. ASSETS
    f.write("-- 6. Inserare Active (Assets)\n")
    asset_ids = []
    asset_team_map = {}

    for i in range(1, NUM_ASSETS + 1):
        asset_ids.append(i)
        hostname = f"SRV-{fake.word().upper()}-{i}"
        ip = fake.ipv4()
        os_type = random.choice(['Windows Server 2019', 'Ubuntu 20.04', 'RedHat 8', 'Windows 10 Enterprise'])
        is_crit = 1 if random.random() > 0.7 else 0
        dept_id = random.randint(1, len(DEPARTMENTS))
        team_id = random.randint(1, len(TEAMS))

        asset_team_map[i] = team_id

        f.write(f"INSERT INTO ASSETS (Hostname, IP_Address, OS_Type, Is_Critical, Dept_ID, Team_ID) "
                f"VALUES ('{hostname}', '{ip}', '{os_type}', {is_crit}, {dept_id}, {team_id});\n")
    f.write("\n")

    # 7. DETECTED_VULNS
    f.write("-- 7. Inserare Vulnerabilități Detectate\n")

    tickets_candidates = []

    used_combos = set()
    det_id_counter = 0 
    count = 0
    while count < NUM_DETECTED:
        asset = random.choice(asset_ids)
        cve = random.choice(cve_ids)
        session = random.choice(session_ids)

        if (asset, cve, session) in used_combos:
            continue

        used_combos.add((asset, cve, session))
        count += 1
        det_id_counter += 1

        status = random.choice(['Open', 'Fixed', 'False Positive', 'Risk Accepted'])
        date_det = fake.date_time_between(start_date='-1y', end_date='now')
        risk_acc = 1 if status == 'Risk Accepted' else 0

        f.write(f"INSERT INTO DETECTED_VULNS (Asset_ID, CVE_ID, Session_ID, Status, Date_Detected, Risk_Accepted) "
                f"VALUES ({asset}, '{cve}', {session}, '{status}', {oracle_date(date_det)}, {risk_acc});\n")

        if status == 'Fixed':
            tickets_candidates.append({
                'det_id': det_id_counter,
                'asset_id': asset,
                'created_date': date_det
            })
    f.write("\n")

    # 8. REMEDIATION_TICKETS
    f.write("-- 8. Inserare Tichete de Remediere (Doar pentru status Fixed)\n")

    # Generăm tichete pentru o parte din vulnerabilitățile fixed
    num_tickets = min(len(tickets_candidates), 300) # Limităm la 300 tichete
    selected_tickets = random.sample(tickets_candidates, num_tickets)

    for t in selected_tickets:
        det_id = t['det_id']
        asset_id = t['asset_id']
        created_date = t['created_date']

        # Echipa care deține asset-ul primește tichetul
        assigned_team = asset_team_map.get(asset_id, 1)
        priority = random.choice(['P1', 'P2', 'P3', 'P4'])

        days_to_fix = random.randint(1, 14)
        resolved_date = created_date + timedelta(days=days_to_fix)
        due_date = created_date + timedelta(days=7) # SLA 7 zile

        notes = escape_sql(fake.sentence(nb_words=8)) + " - Patch applied successfully."

        f.write(f"INSERT INTO REMEDIATION_TICKETS (Det_ID, Assigned_Team_ID, Priority, Created_Date, Due_Date, Resolved_Date, Resolution_Notes) "
                f"VALUES ({det_id}, {assigned_team}, '{priority}', {oracle_date(created_date)}, {oracle_date(due_date)}, {oracle_date(resolved_date)}, '{notes}');\n")
    f.write("\n")

    # ---------------------------------------------------------
    f.write("-- 9. Inserare Loguri de Audit (Simulare)\n")
    audit_tables = ['ASSETS', 'DETECTED_VULNS', 'SECURITY_TEAMS']

    for _ in range(NUM_AUDIT_LOGS):
        action_date = fake.date_time_between(start_date='-6m', end_date='now')
        user = random.choice([u[0] for u in APP_USERS_DATA]) # Un user random
        table = random.choice(audit_tables)
        target_id = random.randint(1, 100)
        old_val = "OldConfig"
        new_val = "NewConfig"
        msg = escape_sql(fake.sentence(nb_words=6))

        f.write(f"INSERT INTO AUDIT_LOGS (Action_Date, User_App, Target_Table, Target_ID, Old_Value, New_Value, Message) "
                f"VALUES ({oracle_date(action_date)}, '{user}', '{table}', {target_id}, '{old_val}', '{new_val}', '{msg}');\n")

    f.write("\nCOMMIT;\n")

print(f"Gata! Fișierul {OUTPUT_FILE} a fost generat cu noile structuri.")
