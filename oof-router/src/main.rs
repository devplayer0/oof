#![feature(wait_until)]

use std::sync::{Arc, Mutex, Condvar};
use std::error::Error as StdError;
use std::process;

use log::{debug, info, error};
use simplelog::{LevelFilter, TermLogger};

use oof_common::constants;
use oof_router::Router;

fn run() -> Result<(), Box<dyn StdError>> {
    info!("starting router");

    let stop = Arc::new((Mutex::new(false), Condvar::new()));
    {
        let stop = Arc::clone(&stop);
        ctrlc::set_handler(move || {
            let &(ref lock, ref cvar) = &*stop;

            let mut stop = lock.lock().unwrap();
            if *stop {
                return;
            }

            info!("shutting down...");
            *stop = true;
            cvar.notify_one();
        })?;
    }

    let err = Arc::new(Mutex::new(None));
    let router = Router::connect(format!("127.0.0.1:{}", constants::DEFAULT_PORT), {
        let err = Arc::clone(&err);
        let stop = Arc::clone(&stop);
        move |e| {
            let mut err = err.lock().unwrap();
            if let Some(ref e) = *err {
                error!("{}", e);
            }
            *err = Some(e);

            let &(ref lock, ref cvar) = &*stop;

            let mut stop = lock.lock().unwrap();
            if *stop {
                return;
            }

            *stop = true;
            cvar.notify_one();
        }
    })?;
    use oof_common::net::*;
    router.update_links(vec![Link::new("10.0.0.1/24".parse().unwrap(), LinkSpeed::Gigabit)])?;
    debug!("links updated");
    {
        let &(ref lock, ref cvar) = &*stop;
        let _guard = cvar.wait_until(lock.lock().unwrap(), |stop| *stop).unwrap();
    }

    router.stop();

    match Arc::try_unwrap(err).ok().unwrap().into_inner().unwrap() {
        None => Ok(()),
        Some(e) => Err(Box::new(e)),
    }
}
fn main() {
    TermLogger::init(LevelFilter::Debug, simplelog::Config::default()).expect("failed to initialize logger");

    if let Err(e) = run() {
        error!("{}", e);
        process::exit(1);
    }
}
