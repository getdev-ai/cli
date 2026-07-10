//! Local SQLite cache for registry lookups (DEC-07): WAL mode, two TTL
//! tiers (7 days existence / 24 hours metadata), single mutex-guarded writer
//! connection shared across the process — SQLite allows exactly one writer
//! at a time even in WAL mode, so opening a connection per `rayon` thread
//! and writing concurrently produces intermittent `SQLITE_BUSY` errors
//! (03-RESEARCH.md Pitfall 4).

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::Connection;

use crate::client::{Ecosystem, Existence};

/// 7 days, per DEC-07.
const EXISTENCE_TTL_SECS: i64 = 7 * 24 * 3600;
/// 24 hours, per DEC-07.
const METADATA_TTL_SECS: i64 = 24 * 3600;

/// `(downloads, created_at)` — mirrors the tuple `RegistryClient::metadata`
/// returns.
pub type Metadata = (Option<u64>, Option<i64>);

const CACHE_FILE_NAME: &str = "cache.sqlite3";

#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    #[error("failed to open cache at {path}: {source}")]
    Open {
        path: PathBuf,
        #[source]
        source: rusqlite::Error,
    },
    #[error("cache query failed: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("failed to create cache directory {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// Resolves the registry cache directory: `GETDEV_CACHE_DIR` first (the
/// test/CI override — hermetic tests must never touch the real
/// `~/.getdev`), else `~/.getdev/cache/registry` (`%USERPROFILE%` on
/// Windows).
pub fn cache_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("GETDEV_CACHE_DIR") {
        return PathBuf::from(dir);
    }
    let home_var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    let home = std::env::var_os(home_var)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(".getdev").join("cache").join("registry")
}

pub struct Cache {
    conn: Mutex<Connection>,
}

impl Cache {
    /// Open (creating if needed) the cache at [`cache_dir`].
    pub fn open() -> Result<Self, CacheError> {
        Self::open_at(&cache_dir())
    }

    /// Open (creating if needed) the cache at an explicit directory — the
    /// hermetic-test entry point (paired with `GETDEV_CACHE_DIR`).
    pub fn open_at(dir: &Path) -> Result<Self, CacheError> {
        std::fs::create_dir_all(dir).map_err(|source| CacheError::Io {
            path: dir.to_path_buf(),
            source,
        })?;
        let db_path = dir.join(CACHE_FILE_NAME);
        let conn = Connection::open(&db_path).map_err(|source| CacheError::Open {
            path: db_path.clone(),
            source,
        })?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA busy_timeout = 5000;
             CREATE TABLE IF NOT EXISTS existence_cache (
                 ecosystem   TEXT NOT NULL,
                 name        TEXT NOT NULL,
                 exists_flag INTEGER NOT NULL,
                 fetched_at  INTEGER NOT NULL,
                 PRIMARY KEY (ecosystem, name)
             );
             CREATE TABLE IF NOT EXISTS metadata_cache (
                 ecosystem    TEXT NOT NULL,
                 name         TEXT NOT NULL,
                 downloads    INTEGER,
                 created_at   INTEGER,
                 fetched_at   INTEGER NOT NULL,
                 PRIMARY KEY (ecosystem, name)
             );",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Never panics on a poisoned mutex — recovers the inner guard instead
    /// (a panicking analyzer/cache write must not propagate across the
    /// thread boundary and take the whole process down, DEC-10/DEC-11).
    fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// `None` on a miss OR an expired (>7d) row — the caller cannot tell
    /// the two apart, and doesn't need to: both mean "go fetch".
    pub fn get_existence(
        &self,
        eco: Ecosystem,
        name: &str,
    ) -> Result<Option<Existence>, CacheError> {
        let conn = self.lock();
        let now = now_unix();
        let row = conn.query_row(
            "SELECT exists_flag, fetched_at FROM existence_cache WHERE ecosystem = ?1 AND name = ?2",
            rusqlite::params![eco.as_str(), name],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)),
        );
        match row {
            Ok((flag, fetched_at)) => {
                if now - fetched_at > EXISTENCE_TTL_SECS {
                    Ok(None)
                } else {
                    Ok(Some(if flag != 0 {
                        Existence::Found
                    } else {
                        Existence::Missing
                    }))
                }
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(err) => Err(CacheError::from(err)),
        }
    }

    /// `Existence::Inconclusive` is never written — caching an unconfirmed
    /// result would suppress a real lookup for the rest of the TTL window.
    pub fn put_existence(
        &self,
        eco: Ecosystem,
        name: &str,
        existence: Existence,
    ) -> Result<(), CacheError> {
        let flag = match existence {
            Existence::Found => 1,
            Existence::Missing => 0,
            Existence::Inconclusive => return Ok(()),
        };
        let conn = self.lock();
        conn.execute(
            "INSERT INTO existence_cache (ecosystem, name, exists_flag, fetched_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(ecosystem, name) DO UPDATE SET
                 exists_flag = excluded.exists_flag,
                 fetched_at  = excluded.fetched_at",
            rusqlite::params![eco.as_str(), name, flag, now_unix()],
        )?;
        Ok(())
    }

    pub fn get_metadata(&self, eco: Ecosystem, name: &str) -> Result<Option<Metadata>, CacheError> {
        let conn = self.lock();
        let now = now_unix();
        let row = conn.query_row(
            "SELECT downloads, created_at, fetched_at FROM metadata_cache WHERE ecosystem = ?1 AND name = ?2",
            rusqlite::params![eco.as_str(), name],
            |r| {
                Ok((
                    r.get::<_, Option<i64>>(0)?,
                    r.get::<_, Option<i64>>(1)?,
                    r.get::<_, i64>(2)?,
                ))
            },
        );
        match row {
            Ok((downloads, created_at, fetched_at)) => {
                if now - fetched_at > METADATA_TTL_SECS {
                    Ok(None)
                } else {
                    Ok(Some((downloads.map(|d| d.max(0) as u64), created_at)))
                }
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(err) => Err(CacheError::from(err)),
        }
    }

    /// Validation-before-write (cache-poisoning mitigation,
    /// 03-RESEARCH.md Security Domain): a `created_at` in the future, or
    /// negative, is nonsensical for a package-creation timestamp and is
    /// silently dropped rather than trusted and cached.
    pub fn put_metadata(
        &self,
        eco: Ecosystem,
        name: &str,
        downloads: Option<u64>,
        created_at: Option<i64>,
    ) -> Result<(), CacheError> {
        let now = now_unix();
        let created_at = created_at.filter(|&ts| ts >= 0 && ts <= now);
        let downloads_i64 = downloads.map(|d| i64::try_from(d).unwrap_or(i64::MAX));
        let conn = self.lock();
        conn.execute(
            "INSERT INTO metadata_cache (ecosystem, name, downloads, created_at, fetched_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(ecosystem, name) DO UPDATE SET
                 downloads  = excluded.downloads,
                 created_at = excluded.created_at,
                 fetched_at = excluded.fetched_at",
            rusqlite::params![eco.as_str(), name, downloads_i64, created_at, now],
        )?;
        Ok(())
    }
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn temp_cache(label: &str) -> (Cache, PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "getdev-registry-cache-test-{label}-{}-{}",
            std::process::id(),
            now_unix()
        ));
        let cache = Cache::open_at(&dir).unwrap();
        (cache, dir)
    }

    #[test]
    fn existence_round_trips_and_never_stores_inconclusive() {
        let (cache, _dir) = temp_cache("existence");
        assert_eq!(
            cache.get_existence(Ecosystem::Npm, "left-pad").unwrap(),
            None
        );

        cache
            .put_existence(Ecosystem::Npm, "left-pad", Existence::Found)
            .unwrap();
        assert_eq!(
            cache.get_existence(Ecosystem::Npm, "left-pad").unwrap(),
            Some(Existence::Found)
        );

        cache
            .put_existence(Ecosystem::Npm, "totally-fake-xyz", Existence::Missing)
            .unwrap();
        assert_eq!(
            cache
                .get_existence(Ecosystem::Npm, "totally-fake-xyz")
                .unwrap(),
            Some(Existence::Missing)
        );

        // Inconclusive must never be persisted.
        cache
            .put_existence(Ecosystem::Npm, "unknown-pkg", Existence::Inconclusive)
            .unwrap();
        assert_eq!(
            cache.get_existence(Ecosystem::Npm, "unknown-pkg").unwrap(),
            None
        );
    }

    #[test]
    fn existence_ttl_expiry_treats_stale_row_as_absent() {
        let (cache, _dir) = temp_cache("existence-ttl");
        let conn = cache.conn.lock().unwrap();
        let stale_fetched_at = now_unix() - EXISTENCE_TTL_SECS - 1;
        conn.execute(
            "INSERT INTO existence_cache (ecosystem, name, exists_flag, fetched_at) VALUES ('npm','left-pad',1,?1)",
            rusqlite::params![stale_fetched_at],
        )
        .unwrap();
        drop(conn);
        assert_eq!(
            cache.get_existence(Ecosystem::Npm, "left-pad").unwrap(),
            None
        );
    }

    #[test]
    fn metadata_round_trips_and_rejects_future_created_at() {
        let (cache, _dir) = temp_cache("metadata");
        assert_eq!(
            cache.get_metadata(Ecosystem::Npm, "left-pad").unwrap(),
            None
        );

        cache
            .put_metadata(Ecosystem::Npm, "left-pad", Some(1234), Some(1_000_000))
            .unwrap();
        assert_eq!(
            cache.get_metadata(Ecosystem::Npm, "left-pad").unwrap(),
            Some((Some(1234), Some(1_000_000)))
        );

        // A creation date in the future is nonsensical — dropped, not cached.
        let future = now_unix() + 1_000_000;
        cache
            .put_metadata(Ecosystem::Npm, "from-the-future", Some(1), Some(future))
            .unwrap();
        assert_eq!(
            cache
                .get_metadata(Ecosystem::Npm, "from-the-future")
                .unwrap(),
            Some((Some(1), None))
        );
    }

    #[test]
    fn metadata_ttl_expiry_treats_stale_row_as_absent() {
        let (cache, _dir) = temp_cache("metadata-ttl");
        let conn = cache.conn.lock().unwrap();
        let stale_fetched_at = now_unix() - METADATA_TTL_SECS - 1;
        conn.execute(
            "INSERT INTO metadata_cache (ecosystem, name, downloads, created_at, fetched_at)
             VALUES ('npm','left-pad',1234,1000000,?1)",
            rusqlite::params![stale_fetched_at],
        )
        .unwrap();
        drop(conn);
        assert_eq!(
            cache.get_metadata(Ecosystem::Npm, "left-pad").unwrap(),
            None
        );
    }

    // `cache_dir()`'s `GETDEV_CACHE_DIR` branch is a single `var_os` read
    // (see the function above) exercised by every other test in this module
    // via `open_at`, which is the same override mechanism the real CLI will
    // use (`Cache::open_at(&cache_dir())`). It is not re-verified here via
    // `std::env::set_var`: that call is `unsafe` as of this toolchain
    // (process-wide env mutation is not thread-safe) and this crate forbids
    // `unsafe_code` workspace-wide with no per-item override (DEC-11).

    #[test]
    fn opens_with_wal_journal_mode() {
        let (cache, _dir) = temp_cache("wal-mode");
        let conn = cache.conn.lock().unwrap();
        let mode: String = conn
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap();
        assert_eq!(mode.to_lowercase(), "wal");
    }
}
