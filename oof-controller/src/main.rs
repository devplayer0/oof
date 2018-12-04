#![feature(wait_until)]

use std::error::Error as StdError;
use std::sync::{Arc, Mutex, Condvar};
use std::process;

use log::{info, error};
use simplelog::{LevelFilter, TermLogger};

use oof_common::constants;
use oof_controller::Controller;

fn run() -> Result <(), Box<dyn StdError>> {
    info!("starting controller");

    let stop = Arc::new((Mutex::new(false), Condvar::new()));
    {
        let stop = Arc::clone(&stop);
        ctrlc::set_handler(move || {
            let &(ref stop_lock, ref stop_cond) = &*stop;

            let mut stop = stop_lock.lock().unwrap();
            if *stop {
                return;
            }

            info!("shutting down...");
            *stop = true;
            stop_cond.notify_one();
        })?;
    }

    let controller = Controller::bind(format!("127.0.0.1:{}", constants::DEFAULT_PORT))?;
    {
        let &(ref lock, ref cvar) = &*stop;
        let _guard = cvar.wait_until(lock.lock().unwrap(), |stop| *stop).unwrap();
    }

    controller.stop();

    Ok(())
}
fn main() {
    TermLogger::init(LevelFilter::Debug, simplelog::Config::default()).expect("failed to initialize logger");

    if let Err(e) = run() {
        error!("{}", e);
        process::exit(1);
    }
}
