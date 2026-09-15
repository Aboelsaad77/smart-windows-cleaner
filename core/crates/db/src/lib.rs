//! `sc-db` — local SQLite persistence (spec §21).
//!
//! All data stays on the user's machine. Nothing in this database is ever
//! transmitted anywhere.

use rusqlite::{params, Connection};
use sc_file_models::FileRecord;
use std::path::Path;

const SCHEMA: &str = include_str!("../schema.sql");

#[derive(Debug)]
pub struct Db {
    conn: Connection,
}

#[derive(Debug, Clone)]
pub struct AuditEntry {
    pub action: String,
    pub path: Option<String>,
    pub size: Option<u64>,
    pub risk: Option<String>,
    pub reason: Option<String>,
    pub engine: String,
    pub result: String,
    pub detail: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AuditRow {
    pub created_at: i64,
    pub action: String,
    pub path: Option<String>,
    pub size: Option<u64>,
    pub risk: Option<String>,
    pub reason: Option<String>,
    pub engine: String,
    pub result: String,
    pub detail: Option<String>,
}

impl Db {
    /// Open (or create) the database and apply the schema idempotently.
    pub fn open(path: &Path) -> rusqlite::Result<Db> {
        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA journal_mode = WAL;")?;
        conn.execute_batch(SCHEMA)?;
        conn.execute_batch(
            "INSERT OR IGNORE INTO meta(key, value) VALUES ('schema_version', '1');",
        )?;
        Ok(Db { conn })
    }

    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    fn now(&self) -> i64 {
        sc_file_models::now_secs()
    }

    // ---- scans ----

    pub fn start_scan_session(&self, mode: &str) -> rusqlite::Result<i64> {
        self.conn.execute(
            "INSERT INTO scan_sessions (started_at, mode) VALUES (?1, ?2)",
            params![self.now(), mode],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn finish_scan_session(
        &self,
        id: i64,
        files: u64,
        total_size: u64,
    ) -> rusqlite::Result<()> {
        self.conn.execute(
            "UPDATE scan_sessions SET finished_at = ?1, files_scanned = ?2, total_size = ?3 WHERE id = ?4",
            params![self.now(), files, total_size, id],
        )?;
        Ok(())
    }

    pub fn upsert_file(&self, session_id: i64, r: &FileRecord) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT INTO files (session_id, path, size, modified, file_class, content_kind, extension, sha256, owner_app, is_windows_component, in_use, last_scanned)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
             ON CONFLICT(session_id, path) DO UPDATE SET
                size = excluded.size,
                modified = excluded.modified,
                content_kind = excluded.content_kind,
                extension = excluded.extension,
                sha256 = excluded.sha256,
                owner_app = excluded.owner_app,
                is_windows_component = excluded.is_windows_component,
                in_use = excluded.in_use,
                last_scanned = excluded.last_scanned",
            params![
                session_id,
                r.path.to_string_lossy(),
                r.size,
                r.modified,
                enum_str(&r.file_class),
                enum_str(&r.content_kind),
                r.extension,
                r.sha256,
                r.owner_app,
                r.is_windows_component as i64,
                r.in_use as i64,
                self.now()
            ],
        )?;
        Ok(())
    }

    // ---- audit (spec §19) ----

    pub fn log_audit(&self, e: &AuditEntry) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT INTO audit_logs (created_at, action, path, size, risk, reason, engine, result, detail)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                self.now(),
                e.action,
                e.path,
                e.size,
                e.risk,
                e.reason,
                e.engine,
                e.result,
                e.detail
            ],
        )?;
        Ok(())
    }

    pub fn audit_since(&self, since: i64) -> rusqlite::Result<Vec<AuditRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT created_at, action, path, size, risk, reason, engine, result, detail
             FROM audit_logs WHERE created_at >= ?1 ORDER BY id DESC LIMIT 500",
        )?;
        let rows = stmt.query_map(params![since], |r| {
            Ok(AuditRow {
                created_at: r.get(0)?,
                action: r.get(1)?,
                path: r.get(2)?,
                size: r.get(3)?,
                risk: r.get(4)?,
                reason: r.get(5)?,
                engine: r.get(6)?,
                result: r.get(7)?,
                detail: r.get(8)?,
            })
        })?;
        rows.collect()
    }

    // ---- user exclusions (spec §18) ----

    pub fn add_exclusion(
        &self,
        path: &str,
        scope: &str,
        note: Option<&str>,
    ) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO user_exclusions (path, scope, created_at, note) VALUES (?1, ?2, ?3, ?4)",
            params![path, scope, self.now(), note],
        )?;
        Ok(())
    }

    pub fn list_exclusions(&self) -> rusqlite::Result<Vec<(String, String)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT path, scope FROM user_exclusions ORDER BY path")?;
        let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
        rows.collect()
    }

    pub fn remove_exclusion(&self, path: &str) -> rusqlite::Result<usize> {
        self.conn
            .execute("DELETE FROM user_exclusions WHERE path = ?1", params![path])
    }

    // ---- software registry (spec §4) ----

    pub fn upsert_software(
        &self,
        name: &str,
        publisher: Option<&str>,
        install_location: Option<&str>,
        version: Option<&str>,
    ) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT INTO software (name, publisher, install_location, version, installed_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(name) DO UPDATE SET
                publisher = excluded.publisher,
                install_location = excluded.install_location,
                version = excluded.version",
            params![name, publisher, install_location, version, self.now()],
        )?;
        Ok(())
    }

    pub fn list_software(&self) -> rusqlite::Result<Vec<(String, Option<String>)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT name, publisher FROM software ORDER BY name")?;
        let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
        rows.collect()
    }

    // ---- quarantine mirror (kept in sync with the vault manifest) ----

    #[allow(clippy::too_many_arguments)] // mirrors the QuarantineItem fields 1:1
    pub fn record_quarantine(
        &self,
        id: &str,
        original_path: &str,
        vault_path: &str,
        sha256: &str,
        size: u64,
        at: i64,
        reason: &str,
        risk: u16,
        status: &str,
    ) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT INTO quarantine_items (id, original_path, vault_path, sha256, size, quarantined_at, reason, risk_score, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(id) DO UPDATE SET status = excluded.status",
            params![id, original_path, vault_path, sha256, size, at, reason, risk, status],
        )?;
        Ok(())
    }

    // ---- settings ----

    pub fn set_setting(&self, key: &str, value: &str) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES (?1, ?2)",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn get_setting(&self, key: &str) -> rusqlite::Result<Option<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT value FROM settings WHERE key = ?1")?;
        let mut rows = stmt.query_map(params![key], |r| r.get::<_, String>(0))?;
        rows.next().transpose()
    }
}

/// Serialize an enum as its serde snake_case string.
fn enum_str<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_string(v)
        .unwrap_or_default()
        .trim_matches('"')
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_db(tag: &str) -> (std::path::PathBuf, Db) {
        let dir = std::env::temp_dir().join(format!("sc-db-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("test.db");
        let _ = std::fs::remove_file(&p);
        let _ = std::fs::remove_file(p.with_extension("db-wal"));
        let _ = std::fs::remove_file(p.with_extension("db-shm"));
        (dir, Db::open(&p).unwrap())
    }

    #[test]
    fn schema_applies_and_session_lifecycle() {
        let (_dir, db) = tmp_db("session");
        let id = db.start_scan_session("smart").unwrap();
        assert!(id > 0);
        db.finish_scan_session(id, 42, 1024).unwrap();

        let n: i64 = db
            .conn()
            .query_row(
                "SELECT files_scanned FROM scan_sessions WHERE id = ?1",
                params![id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 42);
    }

    #[test]
    fn file_upsert_is_idempotent_per_session() {
        let (_dir, db) = tmp_db("files");
        let id = db.start_scan_session("smart").unwrap();
        let r = FileRecord::new("C:\\x\\a.tmp", 100, 123);
        db.upsert_file(id, &r).unwrap();
        let mut r2 = FileRecord::new("C:\\x\\a.tmp", 200, 456);
        r2.owner_app = Some("SomeApp".into());
        db.upsert_file(id, &r2).unwrap();
        let other = FileRecord::new("C:\\x\\b.log", 10, 1);
        db.upsert_file(id, &other).unwrap();

        let count: i64 = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM files WHERE session_id = ?1",
                params![id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 2);

        let size: i64 = db
            .conn()
            .query_row(
                "SELECT size FROM files WHERE path = ?1",
                params!["C:\\x\\a.tmp"],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(size, 200);
    }

    #[test]
    fn audit_log_roundtrip() {
        let (_dir, db) = tmp_db("audit");
        db.log_audit(&AuditEntry {
            action: "quarantine".into(),
            path: Some("C:\\x\\a.tmp".into()),
            size: Some(123),
            risk: Some("low".into()),
            reason: Some("application cache".into()),
            engine: "local-rules".into(),
            result: "success".into(),
            detail: None,
        })
        .unwrap();
        let rows = db.audit_since(0).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].action, "quarantine");
        assert_eq!(rows[0].result, "success");
        assert_eq!(rows[0].size, Some(123));
    }

    #[test]
    fn exclusions_and_settings() {
        let (_dir, db) = tmp_db("excl");
        db.add_exclusion("D:\\MyProjects", "folder", Some("never touch"))
            .unwrap();
        db.add_exclusion("C:\\x\\b.log", "file", None).unwrap();
        let list = db.list_exclusions().unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(db.remove_exclusion("C:\\x\\b.log").unwrap(), 1);
        assert_eq!(db.list_exclusions().unwrap().len(), 1);

        db.set_setting("retention_days", "7").unwrap();
        assert_eq!(
            db.get_setting("retention_days").unwrap().as_deref(),
            Some("7")
        );
    }

    #[test]
    fn software_registry() {
        let (_dir, db) = tmp_db("software");
        db.upsert_software(
            "Google Chrome",
            Some("Google LLC"),
            Some("C:\\Program Files\\Google\\Chrome"),
            Some("126.0"),
        )
        .unwrap();
        db.upsert_software(
            "Google Chrome",
            Some("Google LLC"),
            Some("C:\\Program Files\\Google\\Chrome"),
            Some("127.0"),
        )
        .unwrap();
        let list = db.list_software().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].0, "Google Chrome");
    }
}
