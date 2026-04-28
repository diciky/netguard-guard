// Persistence module
// Handles SQLite database operations

use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;
use rusqlite::{Connection, params};

use crate::types::{HistoryKey, HistoryValue};

/// Persistence struct for SQLite operations
pub struct Persistence {
    conn: Connection,
}

impl Persistence {
    /// Create new persistence instance
    pub fn new(db_path: &str) -> Result<Self, rusqlite::Error> {
        let conn = Connection::open(db_path)?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS flow_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                src_ip TEXT NOT NULL,
                app_id TEXT NOT NULL,
                date TEXT NOT NULL,
                duration INTEGER DEFAULT 0,
                bytes_up INTEGER DEFAULT 0,
                bytes_down INTEGER DEFAULT 0,
                UNIQUE(src_ip, app_id, date)
            )",
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_date ON flow_history(date)",
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_app ON flow_history(app_id)",
            [],
        )?;

        Ok(Self { conn })
    }

    /// Batch write history data
    pub fn batch_write(&self, data: &HashMap<HistoryKey, HistoryValue>) {
        for (key, value) in data {
            let src_ip_str = format!("{}", key.src_ip);
            self.conn.execute(
                "INSERT OR REPLACE INTO flow_history (src_ip, app_id, date, duration, bytes_up, bytes_down)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    src_ip_str,
                    key.app_id,
                    key.date,
                    value.total_duration as i64,
                    value.total_bytes as i64,
                    0i64
                ],
            ).ok();
        }
    }

    /// Query by date
    pub fn query_by_date(&self, date: &str) -> Vec<(String, String, i64, i64)> {
        let mut stmt = self.conn.prepare(
            "SELECT src_ip, app_id, duration, bytes_up FROM flow_history WHERE date = ?1"
        ).unwrap();

        stmt.query_map(params![date], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
            ))
        }).unwrap().map(|r| r.unwrap()).collect()
    }
}