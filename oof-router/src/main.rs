#![feature(wait_until)]

use std::error::Error as StdError;
use std::sync::{Arc, Mutex, Condvar};
use std::process;

use log::{info, error};
use simplelog::{LevelFilter, TermLogger};

use oof_common::util;
use oof_router::raw::RawRouter;

struct Config {
    log_level: LevelFilter,

    address: String,
    ignored_interfaces: Vec<String>,
}
impl<'a> From<clap::ArgMatches<'a>> for Config {
    fn from(args: clap::ArgMatches) -> Config {
        Config {
            log_level: util::verbosity_to_log_level(args.occurrences_of("verbose") as usize),

            address: args.value_of("address").unwrap().to_owned(),
            ignored_interfaces: match args.values_of("ignored_interfaces") {
                Some(ifaces) => ifaces.map(|i| i.to_owned()).collect(),
                None => Vec::new(),
            },
        }
    }
}

fn args<'a>() -> clap::ArgMatches<'a> {
    clap::App::new("Oof router")
        .version("0.1")
        .author("Jack O'Sullivan <jackos1998@gmail.com>")
        .arg(clap::Arg::with_name("verbose")
             .short("v")
             .long("verbose")
             .multiple(true)
             .help("Print extra log messages"))
        .arg(clap::Arg::with_name("address")
             .short("a")
             .long("address")
             .value_name("address[:port]")
             .help("set controller address")
             .default_value("192.168.123.1:27999")
             .takes_value(true)
             .validator(|val| util::parse_addr(&val).map(|_| ()).map_err(|e| format!("{}", e))))
        .arg(clap::Arg::with_name("ignored_interfaces")
             .short("I")
             .long("ignore-interfaces")
             .value_name("interface,...")
             .help("set interfaces to ignore")
             .use_delimiter(true)
             .takes_value(true))
        .get_matches()
}
fn run(config: Config) -> Result<(), Box<dyn StdError>> {
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
    let router = RawRouter::start(config.address, config.ignored_interfaces.iter().map(|i| &i[..]), {
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
    let config: Config = args().into();
    TermLogger::init(config.log_level, simplelog::Config::default()).expect("failed to initialize logger");

    if let Err(e) = run(config) {
        error!("{}", e);
        process::exit(1);
    }
}
