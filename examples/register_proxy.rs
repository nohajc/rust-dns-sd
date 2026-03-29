extern crate dns_sd;
use dns_sd::DNSService;
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;
use std::thread;

/// Plain IPv4 proxy — equivalent of:
///   dns-sd -P "My Web Server" _http._tcp local 80 myproxy.local 127.0.0.1
fn register_ipv4_proxy() {
    let conn = DNSService::create_connection().unwrap();

    // Port is ignored for the A record; use 0.
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let mut rec = conn.register_record("myproxy.local", addr, Some("lo0")).unwrap();
    println!("DNS record requested");

    // Wait for the registration callback to confirm the record is registered
    // This ensures the record is actively responding to DNS queries before proceeding
    rec.wait_for_registration().unwrap();
    println!("DNS record registered successfully");

    // let _svc = DNSService::register(
    //     Some("My Web Server"),
    //     "_nfs._tcp",
    //     Some("local"),
    //     Some("myproxy.local"),
    //     2049,
    //     &[],
    // )
    // .unwrap();

    println!("IPv4 proxy advertisement active for 10 seconds...");
    // The event loop runs automatically in the background.
    // Just keep the DNSService values alive and sleep.
    thread::sleep(Duration::from_secs(10));
}

/// Link-local IPv6 proxy — equivalent of:
///   dns-sd -P "My Web Server" _http._tcp local 80 myproxy6.local fe80::1%en0
fn register_ipv6_proxy() {
    let conn = DNSService::create_connection().unwrap();

    // Use standard Rust parsing: "[fe80::1%lo0]:0" parses to a SocketAddrV6 with correct scope_id.
    let addr6: SocketAddr = ("fe80::1%lo0", 0)
        .to_socket_addrs()
        .unwrap()
        .next()
        .unwrap();
    println!(
        "Registering on interface index {}.",
        match addr6 {
            std::net::SocketAddr::V6(ref a) => a.scope_id(),
            _ => 0,
        }
    );

    let mut rec = conn.register_record("myproxy6.local", addr6, Some("lo0")).unwrap();

    // Wait for the record registration callback before registering the service
    rec.wait_for_registration().unwrap();
    println!("IPv6 DNS record registered successfully");

    let _svc = DNSService::register(
        Some("My Web Server v6"),
        "_http._tcp",
        Some("local"),
        Some("myproxy6.local."),
        80,
        Some("lo0"),
        &["path=/"],
    )
    .unwrap();

    println!("IPv6 proxy advertisement active for 10 seconds...");
    // The event loop runs automatically in the background.
    // Just keep the DNSService values alive and sleep.
    thread::sleep(Duration::from_secs(10));
}

fn main() {
    register_ipv4_proxy();
    register_ipv6_proxy();
}
