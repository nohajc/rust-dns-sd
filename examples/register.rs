extern crate dns_sd;

use dns_sd::DNSService;
use std::time::Duration;
use std::thread;

fn main() {
    let _svc = DNSService::register(Some("WebServer"),
                                    "_http._tcp",
                                    None,
                                    None,
                                    80,
                                    None,
                                    &["path=/"])
                    .unwrap();

    println!("Service registered. Waiting 10 seconds...");
    // The event loop runs automatically in the background.
    // Just keep the DNSService value alive and sleep.
    thread::sleep(Duration::from_secs(10));
}
