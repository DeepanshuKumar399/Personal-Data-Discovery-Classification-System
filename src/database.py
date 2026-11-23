import mysql.connector
import json
from datetime import datetime

DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "Nxnuuuu@77",
    "database": "pii_scanner",
}


def _connect():
    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor()
    cursor.execute("CREATE DATABASE IF NOT EXISTS pii_scanner")
    cursor.execute("USE pii_scanner")
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INT AUTO_INCREMENT PRIMARY KEY,
            scanned_at DATETIME,
            target VARCHAR(500),
            total_findings INT,
            summary JSON
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INT AUTO_INCREMENT PRIMARY KEY,
            scan_id INT,
            pii_type VARCHAR(50),
            value TEXT,
            masked_value TEXT,
            sensitivity VARCHAR(20),
            source VARCHAR(500),
            line_number INT,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        )
    """)
    conn.commit()
    return conn, cursor


def save_scan(target, findings, summary):
    conn, cursor = _connect()
    cursor.execute(
        "INSERT INTO scans (scanned_at, target, total_findings, summary) VALUES (%s, %s, %s, %s)",
        (datetime.now(), target, len(findings), json.dumps(summary)),
    )
    scan_id = cursor.lastrowid
    for f in findings:
        cursor.execute(
            "INSERT INTO findings (scan_id, pii_type, value, masked_value, sensitivity, source, line_number) VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (scan_id, f["type"], f["value"], f.get("masked_value", ""), f["sensitivity"], f["source"], f["line"]),
        )
    conn.commit()
    conn.close()
    return scan_id


def get_history():
    conn, cursor = _connect()
    cursor.execute("SELECT id, scanned_at, target, total_findings, summary FROM scans ORDER BY scanned_at DESC")
    rows = cursor.fetchall()
    conn.close()
    return [
        {"id": r[0], "scanned_at": str(r[1]), "target": r[2], "total_findings": r[3], "summary": json.loads(r[4])}
        for r in rows
    ]


def get_findings_by_scan(scan_id):
    conn, cursor = _connect()
    cursor.execute("SELECT pii_type, value, masked_value, sensitivity, source, line_number FROM findings WHERE scan_id = %s", (scan_id,))
    rows = cursor.fetchall()
    conn.close()
    return [
        {"type": r[0], "value": r[1], "masked_value": r[2], "sensitivity": r[3], "source": r[4], "line": r[5]}
        for r in rows
    ]
