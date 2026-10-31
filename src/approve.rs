//! Confirmation by the person at the Mac: Touch ID, or the login password as a fallback.
//! An agent can't answer this prompt, so it gates everything that loosens a policy or
//! releases a value outside cred.

use std::sync::Mutex;

use anyhow::{Result, bail};

/// How each prompt was answered since the last `take_answers` (true: approved).
static ANSWERS: Mutex<Vec<bool>> = Mutex::new(Vec::new());

/// The answers to the prompts so far, and forget them. The audit log reads what a call asked.
pub fn take_answers() -> Vec<bool> {
    std::mem::take(&mut *ANSWERS.lock().unwrap_or_else(|e| e.into_inner()))
}

/// Ask for confirmation; macOS shows it as "cred is trying to <reason>."
pub fn confirm(reason: &str) -> Result<()> {
    let result = prompt(reason);
    ANSWERS.lock().unwrap_or_else(|e| e.into_inner()).push(result.is_ok());
    result
}

fn prompt(reason: &str) -> Result<()> {
    // Automated tests answer for the user. Release builds don't contain this.
    #[cfg(debug_assertions)]
    if let Ok(answer) = std::env::var("CRED_TEST_APPROVE") {
        eprintln!("cred: [test] {reason}: {answer}");
        return if answer == "yes" { Ok(()) } else { bail!("not approved: {reason}") };
    }

    ask_person(reason)
}

#[cfg(target_os = "macos")]
fn ask_person(reason: &str) -> Result<()> {
    use std::sync::mpsc;
    use std::time::Duration;

    use block2::RcBlock;
    use objc2::runtime::Bool;
    use objc2_foundation::{NSError, NSString};
    use objc2_local_authentication::{LAContext, LAPolicy};

    /// How long the prompt waits for an answer before it is withdrawn.
    const TIMEOUT: Duration = Duration::from_secs(120);

    let context = unsafe { LAContext::new() };
    let (tx, rx) = mpsc::channel();
    let reply = RcBlock::new(move |ok: Bool, error: *mut NSError| {
        let failure = (!ok.as_bool()).then(|| unsafe { error.as_ref() }.map_or("cancelled".to_string(), |e| e.localizedDescription().to_string()));
        let _ = tx.send(failure);
    });
    unsafe {
        context.evaluatePolicy_localizedReason_reply(LAPolicy::DeviceOwnerAuthentication, &NSString::from_str(reason), &reply);
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

/// Nobody can answer here, so everything that needs a person is refused.
#[cfg(not(target_os = "macos"))]
fn ask_person(reason: &str) -> Result<()> {
    bail!("not approved (Touch ID needs macOS): {reason}")
}
