//! Keychain items: every value is its own generic password, service "cred:<resource>/<field>",
//! account = the macOS user.

use std::env;

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

pub fn get(res: &str, field: &str) -> Option<String> {
    get_generic_password(&service(res, field), &account())
        .ok()
        .map(|v| String::from_utf8_lossy(&v).into_owned())
}

/// Read an item only if macOS lets cred do so without asking. Approval records are read this
/// way: one planted by another program would need a prompt, so it reads as missing.
pub fn get_silently(res: &str, field: &str) -> Option<String> {
    let _no_ui = SecKeychain::disable_user_interaction().ok()?;
    get(res, field)
}

/// Whether the item exists, without reading its value: only reading a value can make
/// macOS ask for Keychain access, so status checks never prompt.
pub fn exists(res: &str, field: &str) -> bool {
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
    delete_generic_password(&service(res, field), &account()).is_ok()
}
