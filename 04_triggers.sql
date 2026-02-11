CREATE OR REPLACE TRIGGER TRG_COMPLEX_TICKET_PROCESS
BEFORE UPDATE ON REMEDIATION_TICKETS
FOR EACH ROW
DECLARE
    v_vuln_status VARCHAR2(20);
BEGIN
    -- 1. VALIDARE DE BUSINESS
    -- Nu permitem inchiderea tichetelor P1 (Critice) fara note explicative serioase
    IF :NEW.Resolved_Date IS NOT NULL AND :OLD.Resolved_Date IS NULL THEN
        IF :NEW.Priority = 'P1' AND (:NEW.Resolution_Notes IS NULL OR LENGTH(:NEW.Resolution_Notes) < 10) THEN
            RAISE_APPLICATION_ERROR(-20001, 'Eroare Business: Tichetele P1 necesită note de rezoluție detaliate (min 10 caractere)!');
        END IF;
    END IF;

    -- 2. SINCRONIZARE AUTOMATA (Update pe alta tabela)
    -- Daca tichetul se inchide, marcam vulnerabilitatea ca Fixed
    IF :NEW.Resolved_Date IS NOT NULL AND :OLD.Resolved_Date IS NULL THEN
        UPDATE DETECTED_VULNS
        SET Status = 'Fixed'
        WHERE Det_ID = :NEW.Det_ID;
        
        v_vuln_status := 'Fixed';
    ELSE
        v_vuln_status := 'Unchanged';
    END IF;

    -- 3. AUDIT TRAIL (Insert in a 3-a tabela)
    -- Orice schimbare de status sau data se logheaza
    IF :NEW.Resolved_Date <> :OLD.Resolved_Date OR (:OLD.Resolved_Date IS NULL AND :NEW.Resolved_Date IS NOT NULL) THEN
        INSERT INTO AUDIT_LOGS (User_App, Target_Table, Target_ID, Old_Value, New_Value, Message)
        VALUES (
            USER,
            'REMEDIATION_TICKETS', 
            :NEW.Ticket_ID, 
            'Open/In Progress', 
            'Resolved', 
            'Tichet inchis. Vuln ID ' || :NEW.Det_ID ||' actualizata la ' || v_vuln_status
        );
    END IF;
END;
/