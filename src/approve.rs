//! Confirmation by the person at the Mac: Touch ID, or the login password as a fallback.
//! An agent can't answer this prompt, so it gates everything that loosens a policy or
//! releases a value outside cred.

use std::sync::mpsc;
use std::time::Duration;

use anyhow::{Result, bail};
use block2::RcBlock;
use objc2::runtime::Bool;
use objc2_foundation::{NSError, NSString};
use objc2_local_authentication::{LAContext, LAPolicy};

/// How long the prompt waits for an answer before it is withdrawn.
const TIMEOUT: Duration = Duration::from_secs(120);

/// Ask for confirmation; macOS shows it as "cred is trying to <reason>."
pub fn confirm(reason: &str) -> Result<()> {
    // Automated tests answer for the user. Release builds don't contain this.
    #[cfg(debug_assertions)]
    if let Ok(answer) = std::env::var("CRED_TEST_APPROVE") {
        eprintln!("cred: [test] {reason}: {answer}");
        return if answer == "yes" { Ok(()) } else { bail!("not approved: {reason}") };
    }

    let context = unsafe { LAContext::new() };
    let (tx, rx) = mpsc::channel();
    let reply = RcBlock::new(move |ok: Bool, error: *mut NSError| {
        let failure = (!ok.as_bool()).then(|| {
            unsafe { error.as_ref() }
                .map_or("cancelled".to_string(), |e| e.localizedDescription().to_string())
        });
        let _ = tx.send(failure);
    });
    unsafe {
        context.evaluatePolicy_localizedReason_reply(
            LAPolicy::DeviceOwnerAuthentication,
            &NSString::from_str(reason),
            &reply,
        );
    }
    match rx.recv_timeout(TIMEOUT) {
        Ok(None) => Ok(()),
        Ok(Some(why)) => bail!("not approved ({why}): {reason}"),
        Err(_) => {
            unsafe { context.invalidate() };
            bail!("no answer to the approval prompt: {reason}")
        }
    }
}
