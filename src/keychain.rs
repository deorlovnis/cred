//! Keychain items: every value is its own generic password, service "cred:<resource>/<field>",
//! account = the macOS user.

use std::env;
#[cfg(debug_assertions)]
use std::{fs, path::PathBuf};

use anyhow::{Context, Result};
use security_framework::item::{ItemClass, ItemSearchOptions, Limit};
use security_framework::os::macos::keychain::SecKeychain;
use security_framework::passwords::{
    delete_generic_password, get_generic_password, set_generic_password,
};

const PREFIX: &str = "cred:";

fn account() -> String {
    env::var("USER").unwrap_or_default()
}

fn service(res: &str, field: &str) -> String {
    format!("{PREFIX}{res}/{field}")
}

/// Debug builds keep items in files under $CRED_TEST_KEYCHAIN when it is set, so end-to-end
/// tests never touch the real Keychain. Release builds don't contain this.
#[cfg(debug_assertions)]
fn fake(res: &str, field: &str) -> Option<PathBuf> {
    Some(PathBuf::from(env::var_os("CRED_TEST_KEYCHAIN")?).join(format!("{res}.{field}")))
}

pub fn get(res: &str, field: &str) -> Option<String> {
    #[cfg(debug_assertions)]
    if let Some(file) = fake(res, field) {
        return fs::read_to_string(file).ok();
    }
    get_generic_password(&service(res, field), &account())
        .ok()
        .map(|v| String::from_utf8_lossy(&v).into_owned())
}

/// Read an item only if macOS lets cred do so without asking. Approval records are read this
/// way: one planted by another program would need a prompt, so it reads as missing.
pub fn get_silently(res: &str, field: &str) -> Option<String> {
    #[cfg(debug_assertions)]
    if fake(res, field).is_some() {
        return get(res, field);
    }
    let _no_ui = SecKeychain::disable_user_interaction().ok()?;
    get(res, field)
}

/// A password another app keeps, e.g. Chrome's "Chrome Safe Storage". macOS asks the user
/// before cred may read it.
pub fn get_app_password(service: &str, account: &str) -> Result<Vec<u8>> {
    Ok(get_generic_password(service, account)?)
}

/// Whether the item exists, without reading its value: only reading a value can make
/// macOS ask for Keychain access, so status checks never prompt.
pub fn exists(res: &str, field: &str) -> bool {
    #[cfg(debug_assertions)]
    if let Some(file) = fake(res, field) {
        return file.exists();
    }
    ItemSearchOptions::new()
        .class(ItemClass::generic_password())
        .service(&service(res, field))
        .account(&account())
        .load_attributes(true)
        .limit(Limit::Max(1))
        .search()
        .is_ok_and(|r| !r.is_empty())
}

pub fn set(res: &str, field: &str, value: &str) -> Result<()> {
    #[cfg(debug_assertions)]
    if let Some(file) = fake(res, field) {
        return fs::write(file, value).with_context(|| format!("storing {res}/{field}"));
    }
    // Updates in place if the item exists, so rotation keeps the same Keychain item.
    set_generic_password(&service(res, field), &account(), value.as_bytes())
        .with_context(|| format!("storing {res}/{field} in Keychain"))
}

/// Store the value in a new item, so its access list names only the cred running now.
pub fn replace(res: &str, field: &str, value: &str) -> Result<()> {
    delete(res, field);
    set(res, field, value)
}

pub fn delete(res: &str, field: &str) -> bool {
    #[cfg(debug_assertions)]
    if let Some(file) = fake(res, field) {
        return fs::remove_file(file).is_ok();
    }
    delete_generic_password(&service(res, field), &account()).is_ok()
}
