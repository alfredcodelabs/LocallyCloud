use std::ffi::{c_char, c_int, c_void};
use std::sync::OnceLock;

use libsqlite3_sys as sqlite;
use zeroize::Zeroizing;

static KEY: OnceLock<Zeroizing<[u8; 32]>> = OnceLock::new();

extern "C" {
    fn sqlite3_key(database: *mut sqlite::sqlite3, key: *const c_void, size: c_int) -> c_int;
}

/// Configure every upstream SQLx connection before its first schema access.
/// SQLite invokes this initializer inside sqlite3_open, including for pools
/// opened by ExtendDB bootstrap, catalog and background workers.
unsafe extern "C" fn key_connection(
    database: *mut sqlite::sqlite3,
    _error: *mut *mut c_char,
    _api: *const sqlite::sqlite3_api_routines,
) -> c_int {
    let Some(key) = KEY.get() else {
        return sqlite::SQLITE_ERROR;
    };
    // SAFETY: SQLite supplies its live connection; the immutable key outlives
    // every connection and SQLCipher copies the key during this call.
    let result = unsafe { sqlite3_key(database, key.as_ptr().cast(), 32) };
    if result != sqlite::SQLITE_OK {
        return result;
    }
    // Keep temporary SQL values in RAM as well as encrypting database/WAL pages.
    // SAFETY: constant terminated SQL, live connection, no callback or output.
    unsafe {
        sqlite::sqlite3_exec(
            database,
            c"PRAGMA temp_store=MEMORY; PRAGMA cipher_memory_security=ON;".as_ptr(),
            None,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    }
}

pub fn install(key: Zeroizing<[u8; 32]>) -> Result<(), &'static str> {
    KEY.set(key).map_err(|_| "cipher already initialized")?;
    // SAFETY: the callback has SQLite's documented extension signature and
    // uses only the immutable process key. Register before starting any pools.
    let result = unsafe { sqlite::sqlite3_auto_extension(Some(key_connection)) };
    if result != sqlite::SQLITE_OK {
        return Err("cannot initialize encrypted storage");
    }
    Ok(())
}
