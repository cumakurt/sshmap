use crate::db::migrations::apply_read_only_pragmas;
use anyhow::{Context, Result, bail};
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{Connection, OpenFlags};
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Clone)]
pub struct ReadOnlyPool {
    pool: Arc<r2d2::Pool<SqliteConnectionManager>>,
}

pub trait ReadOnlyDbAccess {
    fn with_read_connection<T, F>(&self, callback: F) -> Result<T>
    where
        F: FnOnce(&Connection) -> Result<T>;
}

impl ReadOnlyDbAccess for Path {
    fn with_read_connection<T, F>(&self, callback: F) -> Result<T>
    where
        F: FnOnce(&Connection) -> Result<T>,
    {
        with_read_only_connection(self, callback)
    }
}

impl ReadOnlyDbAccess for PathBuf {
    fn with_read_connection<T, F>(&self, callback: F) -> Result<T>
    where
        F: FnOnce(&Connection) -> Result<T>,
    {
        with_read_only_connection(self, callback)
    }
}

impl ReadOnlyDbAccess for ReadOnlyPool {
    fn with_read_connection<T, F>(&self, callback: F) -> Result<T>
    where
        F: FnOnce(&Connection) -> Result<T>,
    {
        let connection = self
            .pool
            .get()
            .context("failed to acquire read-only database connection from pool")?;
        apply_read_only_pragmas(&connection)?;
        callback(&connection)
    }
}

impl ReadOnlyPool {
    pub fn open(path: &Path) -> Result<Self> {
        if !path.exists() {
            bail!("database not found: {}", path.display());
        }

        let manager =
            SqliteConnectionManager::file(path).with_flags(OpenFlags::SQLITE_OPEN_READ_ONLY);
        let pool = r2d2::Pool::builder()
            .max_size(8)
            .connection_timeout(std::time::Duration::from_secs(5))
            .build(manager)
            .with_context(|| format!("failed to create read-only pool for {}", path.display()))?;

        Ok(Self {
            pool: Arc::new(pool),
        })
    }
}

pub fn with_read_only_connection<T, F>(path: &Path, callback: F) -> Result<T>
where
    F: FnOnce(&Connection) -> Result<T>,
{
    if !path.exists() {
        bail!("database not found: {}", path.display());
    }

    let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .with_context(|| format!("failed to open database read-only at {}", path.display()))?;
    apply_read_only_pragmas(&connection)?;
    callback(&connection)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::migrations::initialize_database;

    #[test]
    fn read_only_pool_matches_path_reads() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let db_path = temp_dir.path().join("pool.db");
        initialize_database(&db_path).expect("initialize");
        let pool = ReadOnlyPool::open(&db_path).expect("pool");

        let from_path =
            crate::db::load_database_stats_read_only(db_path.as_path()).expect("path stats");
        let from_pool = crate::db::load_database_stats_read_only(&pool).expect("pool stats");
        assert_eq!(from_path.hosts, from_pool.hosts);
        assert_eq!(from_path.risks, from_pool.risks);
    }
}
