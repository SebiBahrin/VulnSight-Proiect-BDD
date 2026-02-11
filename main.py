import streamlit as st
import oracledb
import pandas as pd
import plotly.express as px
import time

# 1. CONFIGURARE CONEXIUNE ORACLE
DB_USER = "STUDENT_BD"
DB_PASS = "admin"
DB_DSN = "localhost:1521/XE"

st.set_page_config(page_title="VulnSight Dashboard", layout="wide", page_icon="🛡️")

@st.cache_resource
def get_db_connection():
    try:
        conn = oracledb.connect(user=DB_USER, password=DB_PASS, dsn=DB_DSN)
        return conn
    except Exception as e:
        st.error(f"Eroare conectare DB: {e}")
        return None

# 2. FUNCTII APEL PROCEDURI STOCATE

def get_critical_assets(min_score):
    conn = get_db_connection()
    if not conn: return pd.DataFrame()
    cursor = conn.cursor()
    ref_cursor = conn.cursor()
    try:
        cursor.callproc("PKG_VULNSIGHT.GET_CRITICAL_ASSETS", [min_score, ref_cursor])
        columns = [col[0] for col in ref_cursor.description]
        data = ref_cursor.fetchall()
        return pd.DataFrame(data, columns=columns)
    except Exception as e:
        st.error(f"Eroare assets: {e}")
        return pd.DataFrame()
    finally:
        ref_cursor.close()
        cursor.close()

def get_team_performance():
    conn = get_db_connection()
    if not conn: return pd.DataFrame()
    cursor = conn.cursor()
    ref_cursor = conn.cursor()
    try:
        cursor.callproc("PKG_VULNSIGHT.GET_TEAM_PERFORMANCE", [ref_cursor])
        columns = [col[0] for col in ref_cursor.description]
        data = ref_cursor.fetchall()
        return pd.DataFrame(data, columns=columns)
    except Exception as e:
        st.error(f"Eroare performance: {e}")
        return pd.DataFrame()
    finally:
        ref_cursor.close()
        cursor.close()

def get_risk_report():
    conn = get_db_connection()
    if not conn: return pd.DataFrame()
    cursor = conn.cursor()
    ref_cursor = conn.cursor()
    try:
        cursor.callproc("PKG_VULNSIGHT.CALCULATE_DEPT_RISK", [ref_cursor])
        columns = [col[0] for col in ref_cursor.description]
        data = ref_cursor.fetchall()
        return pd.DataFrame(data, columns=columns)
    except Exception as e:
        st.error(f"Eroare risk report: {e}")
        return pd.DataFrame()
    finally:
        ref_cursor.close()
        cursor.close()

# --- OPERATIUNI ---

def get_all_teams():
    conn = get_db_connection()
    if not conn: return pd.DataFrame()
    cursor = conn.cursor()
    ref_cursor = conn.cursor()
    try:
        cursor.callproc("SP_GET_ALL_TEAMS", [ref_cursor])
        columns = [col[0] for col in ref_cursor.description]
        data = ref_cursor.fetchall()
        return pd.DataFrame(data, columns=columns)
    except Exception as e:
        st.error(f"Eroare fetch echipe: {e}")
        return pd.DataFrame()
    finally:
        ref_cursor.close()
        cursor.close()

def get_open_tickets_proc():
    conn = get_db_connection()
    if not conn: return pd.DataFrame()
    cursor = conn.cursor()
    ref_cursor = conn.cursor()
    try:
        cursor.callproc("SP_GET_OPEN_TICKETS", [ref_cursor])
        columns = [col[0] for col in ref_cursor.description]
        data = ref_cursor.fetchall()
        return pd.DataFrame(data, columns=columns)
    except Exception as e:
        st.error(f"Eroare fetch tichete: {e}")
        return pd.DataFrame()
    finally:
        ref_cursor.close()
        cursor.close()

def get_vulns_for_creation():
    conn = get_db_connection()
    if not conn: return pd.DataFrame()
    cursor = conn.cursor()
    ref_cursor = conn.cursor()
    try:
        cursor.callproc("SP_GET_VULNS_NO_TICKET", [ref_cursor])
        columns = [col[0] for col in ref_cursor.description]
        data = ref_cursor.fetchall()
        return pd.DataFrame(data, columns=columns)
    except Exception as e:
        st.error(f"Eroare fetch vulns: {e}")
        return pd.DataFrame()
    finally:
        ref_cursor.close()
        cursor.close()

def create_ticket_action(det_id, priority, team_id):
    conn = get_db_connection()
    if not conn: return "Eroare conexiune"
    cursor = conn.cursor()
    status_msg = cursor.var(oracledb.STRING)
    try:
        cursor.callproc("SP_CREATE_TICKET", [det_id, priority, team_id, status_msg])
        conn.commit()
        return status_msg.getvalue()
    except Exception as e:
        return f"Eroare: {e}"
    finally:
        cursor.close()

def resolve_ticket_action(ticket_id, note):
    conn = get_db_connection()
    if not conn: return "Eroare conexiune DB"
    cursor = conn.cursor()
    status_msg = cursor.var(oracledb.STRING)
    try:
        cursor.callproc("SP_RESOLVE_TICKET", [ticket_id, note, status_msg])
        conn.commit()
        return status_msg.getvalue()
    except Exception as e:
        return f"Eroare aplicatie: {e}"
    finally:
        cursor.close()

# 3. INTERFATA GRAFICA

st.title("Proiect BDD - Bahrin Sebastian Stefan")
st.markdown("---")

st.sidebar.header("Panou Control")
st.sidebar.info("Conectat la: Oracle XE")
st.sidebar.markdown("Proiect Baze de Date Distribuite 2025-2026")

tab1, tab2, tab3, tab4 = st.tabs([
    "Risc Strategic (C6)",
    "Performanță Echipe (C5)",
    "Active Critice (C8)",
    "Operațiuni cu Tichete"
])

# --- TAB 1: Risc Strategic ---
with tab1:
    st.header("Analiză de Risc pe Departamente (Complexitate 6)")
    st.info("Formulă: (Sum_CVSS * Weight) + (Criticals * 10) / Scalare Buget.")
    
    if st.button("Generează Raport Risc"):
        with st.spinner('Calculating Risk Metrics...'):
            df_risk = get_risk_report()
        
        if not df_risk.empty:
            col1, col2 = st.columns([2, 1])
            with col1:
                fig = px.bar(df_risk, x='DEPT_NAME', y='RISK_SCORE', color='RISK_CATEGORY',
                             color_discrete_map={'EXTREME': 'red', 'HIGH': 'orange', 'MODERATE': 'yellow'},
                             title="Scor de Risc Ponderat")
                st.plotly_chart(fig, use_container_width=True)
            with col2:
                st.dataframe(df_risk[['DEPT_NAME', 'VULN_COUNT', 'RISK_SCORE', 'RISK_CATEGORY']], use_container_width=True)
        else:
            st.warning("Nu există date calculate.")

# --- TAB 2: Performanta Echipe ---
with tab2:
    st.header("Eficiență Operațională (Complexitate 5)")
    st.write("Metrică combinată: SLA Breach vs Volume vs Severity Bonus.")
    
    df_perf = get_team_performance()
    if not df_perf.empty:
        col1, col2 = st.columns(2)
        with col1:
            fig2 = px.bar(df_perf, x='EFFICIENCY_SCORE', y='TEAM_NAME', orientation='h', color='PERFORMANCE_LABEL',
                          title="Scor Eficiență (Mai mare e mai bine)")
            st.plotly_chart(fig2, use_container_width=True)
        with col2:
            best_team = df_perf.iloc[0]
            st.metric("Cea mai eficientă echipă", best_team['TEAM_NAME'], f"Score: {best_team['EFFICIENCY_SCORE']}")
            st.dataframe(df_perf[['TEAM_NAME', 'TOTAL_TICKETS', 'SLA_BREACHES', 'MTTR', 'PERFORMANCE_LABEL']], use_container_width=True)
    else:
        st.info("Nu există date de performanță (tichete închise).")

# --- TAB 3: Active Critice ---
with tab3:
    st.header("Top Active Vulnerabile (Complexitate 8)")
    min_score = st.slider("Filtrează după Scor CVSS Minim", 0.0, 10.0, 9.0)
    
    df_assets = get_critical_assets(min_score)
    if not df_assets.empty:
        st.error(f"S-au găsit {len(df_assets)} active critice expuse de mult timp!")
        st.dataframe(df_assets, use_container_width=True)
    else:
        st.success("Niciun activ critic găsit cu acest filtru.")

# --- TAB 4: Operatiuni ---
with tab4:
    st.header("Centrul de Operațiuni Securitate (SOC)")
    col_create, col_resolve = st.columns(2, gap="large")

    # --- PARTEA STANGA: CREARE TICHET ---
    with col_create:
        st.subheader("1. Deschide Tichet Nou")
        st.info("Selectează vulnerabilitatea și echipa responsabilă.")

        df_vulns = get_vulns_for_creation()
        df_teams = get_all_teams()

        if not df_vulns.empty and not df_teams.empty:
            vuln_options = dict(zip(df_vulns['DET_ID'], df_vulns['DISPLAY_LABEL']))
            selected_det_id = st.selectbox("Selectează Vulnerabilitate", options=list(vuln_options.keys()), format_func=lambda x: vuln_options[x])

            team_options = dict(zip(df_teams['TEAM_ID'], df_teams['TEAM_NAME'] + " (" + df_teams['SPECIALIZATION'] + ")"))
            selected_team_id = st.selectbox("Alocă Echipa", options=list(team_options.keys()), format_func=lambda x: team_options[x])

            new_priority = st.select_slider("Prioritate", options=['P4', 'P3', 'P2', 'P1'], value='P3')

            if st.button("Creează Tichet"):
                res = create_ticket_action(int(selected_det_id), new_priority, int(selected_team_id))
                if "Succes" in res:
                    st.success(res)
                    time.sleep(1)
                    st.rerun()
                else:
                    st.error(res)
        else:
            if df_vulns.empty: st.success("Toate vulnerabilitățile au deja tichete alocate!")
            if df_teams.empty: st.error("Nu s-au putut încărca echipele.")

    # --- PARTEA DREAPTA: REZOLVARE TICHET ---
    with col_resolve:
        st.subheader("2. Rezolvă Tichet Existent")
        st.info("Închide tichetele după aplicarea patch-urilor.")

        df_tickets = get_open_tickets_proc()

        if not df_tickets.empty:
            st.dataframe(df_tickets[['TICKET_ID', 'PRIORITY', 'HOSTNAME', 'SEVERITY']], height=150, use_container_width=True)
            
            ticket_to_solve = st.selectbox("Alege ID Tichet de închis", df_tickets['TICKET_ID'])
            resolution_note = st.text_area("Notă Tehnică (Min 10 caractere pt P1)", height=100)

            if st.button(" Marchează REZOLVAT"):
                if not resolution_note:
                    st.error("Nota este obligatorie.")
                else:
                    result = resolve_ticket_action(int(ticket_to_solve), resolution_note)
                    if "Success" in result:
                        st.balloons()
                        st.success(result)
                        time.sleep(1)
                        st.rerun()
                    else:
                        st.error(result)
        else:
            st.info("Nu există tichete deschise.")

st.markdown("---")
st.caption("Proiect BDD 2025-2026 | Bahrin Sebastian Stefan")