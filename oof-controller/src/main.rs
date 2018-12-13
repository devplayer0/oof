#![feature(wait_until)]

use std::error::Error as StdError;
use std::sync::{Arc, Mutex, Condvar};
use std::process;

use log::{info, error};
use simplelog::{LevelFilter, TermLogger};

use oof_common::util;
use oof_controller::Controller;

struct Config {
    log_level: LevelFilter,

    bind_addr: String,
}
impl<'a> From<clap::ArgMatches<'a>> for Config {
    fn from(args: clap::ArgMatches) -> Config {
        Config {
            log_level: util::verbosity_to_log_level(args.occurrences_of("verbose") as usize),

            bind_addr: args.value_of("bind_addr").unwrap().to_owned(),
        }
    }
}

fn args<'a>() -> clap::ArgMatches<'a> {
    clap::App::new("Oof controller")
        .version("0.1")
        .author("Jack O'Sullivan <jackos1998@gmail.com>")
        .arg(clap::Arg::with_name("verbose")
             .short("v")
             .long("verbose")
             .multiple(true)
             .help("Print extra log messages"))
        .arg(clap::Arg::with_name("bind_addr")
             .short("b")
             .long("bind-address")
             .value_name("address[:port]")
             .help("set bind address")
             .default_value("192.168.123.1:27999")
             .takes_value(true)
             .validator(|val| util::parse_addr(&val).map(|_| ()).map_err(|e| format!("{}", e))))
        .get_matches()
}
fn run(config: Config) -> Result <(), Box<dyn StdError>> {
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

    let controller = Controller::bind(config.bind_addr)?;
    {
        let &(ref lock, ref cvar) = &*stop;
        let _guard = cvar.wait_until(lock.lock().unwrap(), |stop| *stop).unwrap();
    }

    controller.stop();

    Ok(())
}
fn main() {
    let config: Config = args().into();
    TermLogger::init(config.log_level, simplelog::Config::default()).expect("failed to initialize logger");

    if let Err(e) = run(config) {
        error!("{}", e);
        process::exit(1);
    }
}
