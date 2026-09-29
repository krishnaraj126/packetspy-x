import sqlite3
from datetime import datetime

DB_NAME = "packetspy.db"


def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            time TEXT,
            src TEXT,
            dst TEXT,
            protocol TEXT,
            size INTEGER,
            status TEXT,
            reason TEXT
        )
    """)

    conn.commit()
    conn.close()


def insert_packet(data):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO packets (time, src, dst, protocol, size, status, reason)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        data["time"],
        data["src"],
        data["dst"],
        data["protocol"],
        data["size"],
        data["status"],
        data["reason"]
    ))

    conn.commit()
    conn.close()


def get_recent_packets(limit=100):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT time, src, dst, protocol, size, status, reason
        FROM packets
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))

    rows = cursor.fetchall()
    conn.close()

    return [
        {
            "time": row[0],
            "src": row[1],
            "dst": row[2],
            "protocol": row[3],
            "size": row[4],
            "status": row[5],
            "reason": row[6]
        }
        for row in rows
    ]