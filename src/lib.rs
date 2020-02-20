pub mod account;
use crate::account::Account;
use colored::*;
use rand::prelude::*;
use rand::rngs::StdRng;
use rand::thread_rng;
use regex::Regex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

pub fn try_generate_wallet(
    regex: &Regex,
    trying: &AtomicBool,
    verbosity: u64,
    tries: &AtomicU64,
) -> Option<Account> {
    let mut result = None;
    let mut generator = StdRng::from_rng(thread_rng()).unwrap();
    let mut pk_src: [u8; 32] = [0; 32];
    loop {
        generator.fill_bytes(&mut pk_src);
        if trying.load(Ordering::SeqCst) {
            tries.fetch_add(1, Ordering::SeqCst);
            let account = Account::new(&pk_src);
            let address = account.address_as_hex();

            if verbosity >= 2 {
                eprint!("{}\r", account.address_as_hex());
            }

            if regex.is_match(&address) {
                result = Some(account);
                println!("found an address {}", address);
                trying.fetch_and(false, Ordering::SeqCst);
                break;
            }
        } else {
            break;
        }
    }

    result
}

pub fn run(search: &str, cpus: usize, verbosity: u64) -> Result<Account, String> {
    let now = Instant::now();
    let regex = Arc::new(Regex::new(search).unwrap());
    let trying = Arc::new(AtomicBool::new(true));
    let account = Arc::new(Mutex::new(None));
    let tries = Arc::new(AtomicU64::new(0));

    if verbosity >= 2 {
        println!("searching for address containing: {}.", search);
        println!("using {} logical processors.", cpus);
        println!("using level {} verbosity.", verbosity);
        println!("\n");
        println!("searching...")
    }

    let mut workers = Vec::with_capacity(cpus);
    for _ in 0..cpus {
        let regex = Arc::clone(&regex);
        let account = Arc::clone(&account);
        let tries = Arc::clone(&tries);
        let trying = Arc::clone(&trying);

        let worker = thread::spawn(move || {
            if let Some(result) = try_generate_wallet(&regex, &trying, verbosity, &tries) {
                *account.lock().unwrap() = Some(result);
            }
        });
        workers.push(worker);
    }

    for worker in workers {
        worker.join().unwrap();
    }

    let account = account.lock().unwrap().take().unwrap();
    let tries = tries.load(Ordering::SeqCst);

    if verbosity >= 1 {
        let task_duration = now.elapsed().as_secs();
        println!("\n\n");
        println!("tries: {}", tries);
        println!(
            "{}",
            format!("found matching account in {} seconds.", task_duration).magenta()
        );
        if task_duration > 0 {
            println!("tries per second: {}", tries / task_duration);
        }
        println!(
            "{}{}",
            "private key: ".yellow(),
            String::from(account.priv_key_as_hex()).cyan()
        );
        println!(
            "{}{}",
            "public key: ".yellow(),
            String::from(account.pub_key_as_hex()).cyan()
        );
        println!(
            "{}{}",
            "address: ".yellow(),
            String::from(account.address_as_hex()).cyan()
        );
    }

    Ok(account)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_run() {
        run("0000", 8, 1).unwrap();
    }
}
