use std::ffi::CString;
use std::ffi::c_void;
use std::net::SocketAddr;
use std::ptr::null;
use std::ptr::null_mut;
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::sync::mpsc;

use objc2_core_foundation::kCFRunLoopDefaultMode;
use objc2_core_foundation::{CFRunLoop, CFSocket, CFSocketContext, kCFAllocatorDefault};

// Callback for DNSServiceRegisterRecord - just logs, doesn't stop runloop
extern "C" fn register_record_callback(
    _sdref: ffi::DNSServiceRef,
    _rec: ffi::DNSRecordRef,
    _flags: ffi::DNSServiceFlags,
    error: ffi::DNSServiceErrorType,
    _context: *mut c_void,
) {
    if error != ffi::DNSServiceErrorType::NoError {
        eprintln!("DNSServiceRegisterRecord callback error: {:?}", error);
    } else {
        println!("DNSServiceRegisterRecord callback: record registered successfully.");
    }
    
    // NOTE: Do NOT call CFRunLoop::stop() here!
    // The runloop must keep running to service the registered DNS records.
}

// Callback for processing DNS-SD socket events
unsafe extern "C-unwind" fn socket_callback(
    _s: *mut CFSocket,
    _type: objc2_core_foundation::CFSocketCallBackType,
    _address: *const objc2_core_foundation::CFData,
    _data: *const std::ffi::c_void,
    info: *mut std::ffi::c_void,
) {
    let sd_ref = info as ffi::DNSServiceRef;
    let err = unsafe { ffi::DNSServiceProcessResult(sd_ref) };
    if err != ffi::DNSServiceErrorType::NoError {
        eprintln!("DNSServiceProcessResult error: {:?}", err);
    }
}

/// Request to add a socket source to the background runloop
struct AddSourceRequest {
    fd: i32,
    sd_ref: ffi::DNSServiceRef,
    response_tx: mpsc::Sender<Result<(), DNSError>>,
}

// AddSourceRequest contains raw pointers which are safe to send across threads
// since they're opaque library-managed pointers that don't have affinity to any thread
unsafe impl Send for AddSourceRequest {}

/// Manages the background event loop thread for DNS-SD operations.
/// Uses reference counting - the thread runs as long as at least one DNSService exists.
struct EventLoopManager {
    _thread_handle: Mutex<Option<thread::JoinHandle<()>>>,
    stop_tx: Mutex<Option<mpsc::Sender<()>>>,
    add_source_tx: Mutex<mpsc::Sender<AddSourceRequest>>,
}

impl std::fmt::Debug for EventLoopManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventLoopManager").finish()
    }
}

impl EventLoopManager {
    /// Create and start the event loop thread.
    fn new() -> Arc<Self> {
        let (stop_tx, stop_rx) = mpsc::channel::<()>();
        let (add_source_tx, add_source_rx) = mpsc::channel::<AddSourceRequest>();
        
        let handle = thread::spawn(move || {
            event_loop_thread_run(stop_rx, add_source_rx);
        });
        
        Arc::new(EventLoopManager {
            _thread_handle: Mutex::new(Some(handle)),
            stop_tx: Mutex::new(Some(stop_tx)),
            add_source_tx: Mutex::new(add_source_tx),
        })
    }
    
    /// Request to add a socket source to the background runloop
    fn add_source(&self, fd: i32, sd_ref: ffi::DNSServiceRef) -> Result<(), DNSError> {
        let (response_tx, response_rx) = mpsc::channel();
        
        let request = AddSourceRequest {
            fd,
            sd_ref,
            response_tx,
        };
        
        if let Ok(tx) = self.add_source_tx.lock() {
            tx.send(request).map_err(|_| DNSError(ffi::DNSServiceErrorType::Unknown))?;
        } else {
            return Err(DNSError(ffi::DNSServiceErrorType::Unknown));
        }
        
        // Wait for the background thread to process the request
        response_rx.recv().map_err(|_| DNSError(ffi::DNSServiceErrorType::Unknown))?
    }
}

impl Drop for EventLoopManager {
    fn drop(&mut self) {
        // Signal the thread to stop by dropping the sender
        if let Ok(mut tx_opt) = self.stop_tx.lock() {
            tx_opt.take(); // Drop sender, causing recv to fail
        }
        
        // Wait for thread to finish
        if let Ok(mut handle_opt) = self._thread_handle.lock() {
            if let Some(handle) = handle_opt.take() {
                let _ = handle.join();
            }
        }
    }
}

/// Background thread that runs the CFRunLoop to service DNS-SD events.
fn event_loop_thread_run(stop_rx: mpsc::Receiver<()>, add_source_rx: mpsc::Receiver<AddSourceRequest>) {
    // Use the background thread's own CFRunLoop
    let runloop = CFRunLoop::current().unwrap();
    
    loop {
        // Process pending source requests
        loop {
            match add_source_rx.try_recv() {
                Ok(request) => {
                    let result = add_source_to_runloop(&runloop, request.fd, request.sd_ref);
                    let _ = request.response_tx.send(result);
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => return,
            }
        }
        
        // Check if we've been signaled to stop
        match stop_rx.try_recv() {
            Ok(_) | Err(mpsc::TryRecvError::Disconnected) => break,
            Err(mpsc::TryRecvError::Empty) => {
                // Continue running - but actually run the event loop to process callbacks
                unsafe {
                    // Run ONE iteration of the runloop with a timeout.
                    // This allows pending DNS-SD callbacks to fire.
                    CFRunLoop::run_in_mode(kCFRunLoopDefaultMode, 0.01, true);
                }
            }
        }
    }
}

/// Add a socket source for the given fd to the runloop (called from background thread)
fn add_source_to_runloop(runloop: &CFRunLoop, fd: i32, sd_ref: ffi::DNSServiceRef) -> Result<(), DNSError> {
    if fd < 0 {
        return Err(DNSError(ffi::DNSServiceErrorType::Unknown));
    }
    
    unsafe {
        let mut context = CFSocketContext {
            version: 0,
            info: sd_ref as *mut _,
            retain: None,
            release: None,
            copyDescription: None,
        };

        let cf_sock = match CFSocket::with_native(
            kCFAllocatorDefault,
            fd,
            1, // kCFSocketReadCallBack = 1
            Some(socket_callback),
            &mut context,
        ) {
            Some(sock) => sock,
            None => return Err(DNSError(ffi::DNSServiceErrorType::Unknown)),
        };

        let sock_ref: &objc2_core_foundation::CFSocket = cf_sock.as_ref();
        let rl_source = match CFSocket::new_run_loop_source(kCFAllocatorDefault, Some(sock_ref), 0) {
            Some(src) => src,
            None => return Err(DNSError(ffi::DNSServiceErrorType::Unknown)),
        };

        runloop.add_source(Some(&rl_source), kCFRunLoopDefaultMode);

        // IMPORTANT: Leak the CFSocket to keep it alive.
        // The runloop source holds a reference to the socket but doesn't keep it alive
        // on its own. By leaking it, we ensure the socket remains valid for the
        // entire lifetime of the background thread.
        std::mem::forget(cf_sock);
    }
    
    Ok(())
}

/// Get or create the global event loop manager.
fn get_event_loop_manager() -> Arc<EventLoopManager> {
    static MANAGER: OnceLock<Arc<EventLoopManager>> = OnceLock::new();
    
    MANAGER
        .get_or_init(|| EventLoopManager::new())
        .clone()
}

#[allow(non_upper_case_globals)]
mod ffi {
    use libc::c_char;
    use libc::c_void;

    pub enum DNSService {}
    pub type DNSServiceRef = *mut DNSService;

    pub enum DNSRecord {}
    pub type DNSRecordRef = *mut DNSRecord;

    #[repr(i32)]
    #[allow(dead_code)]
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    pub enum DNSServiceErrorType {
        NoError = 0,
        Unknown = -65537,
        NoSuchName = -65538,
        NoMemory = -65539,
        BadParam = -65540,
        BadReference = -65541,
        BadState = -65542,
        BadFlags = -65543,
        Unsupported = -65544,
        NotInitialized = -65545,
        AlreadyRegistered = -65547,
        NameConflict = -65548,
        Invalid = -65549,
        Firewall = -65550,
        Incompatible = -65551,
        BadInterfaceIndex = -65552,
        Refused = -65553,
        NoSuchRecord = -65554,
        NoAuth = -65555,
        NoSuchKey = -65556,
        NATTraversal = -65557,
        DoubleNAT = -65558,
        BadTime = -65559,
        BadSig = -65560,
        BadKey = -65561,
        Transient = -65562,
        ServiceNotRunning = -65563,
        NATPortMappingUnsupported = -65564,
        NATPortMappingDisabled = -65565,
        NoRouter = -65566,
        PollingMode = -65567,
        Timeout = -65568,
    }

    pub type DNSServiceFlags = u32;

    pub const kDNSServiceFlagsUnique: DNSServiceFlags = 0x20;

    pub const kDNSServiceType_A: u16 = 1;
    pub const kDNSServiceType_AAAA: u16 = 28;
    pub const kDNSServiceClass_IN: u16 = 1;

    pub type DNSServiceRegisterReply = Option<
        extern "C" fn(
            DNSServiceRef,
            DNSServiceFlags,
            DNSServiceErrorType,
            *const c_char,
            *const c_char,
            *const c_char,
            *mut c_void,
        ),
    >;

    pub type DNSServiceRegisterRecordReply = Option<
        extern "C" fn(
            DNSServiceRef,
            DNSRecordRef,
            DNSServiceFlags,
            DNSServiceErrorType,
            *mut c_void,
        ),
    >;

    unsafe extern "C" {
        pub fn DNSServiceRegister(
            sdRef: *mut DNSServiceRef,
            flags: DNSServiceFlags,
            interfaceIndex: u32,
            name: *const c_char,
            regtype: *const c_char,
            domain: *const c_char,
            host: *const c_char,
            port: u16,
            txtLen: u16,
            txtRecord: *const u8,
            callBack: DNSServiceRegisterReply,
            context: *mut c_void,
        ) -> DNSServiceErrorType;

        pub fn DNSServiceCreateConnection(sdRef: *mut DNSServiceRef) -> DNSServiceErrorType;

        pub fn DNSServiceRegisterRecord(
            sdRef: DNSServiceRef,
            RecordRef: *mut DNSRecordRef,
            flags: DNSServiceFlags,
            interfaceIndex: u32,
            fullname: *const c_char,
            rrtype: u16,
            rrclass: u16,
            rdlen: u16,
            rdata: *const u8,
            ttl: u32,
            callBack: DNSServiceRegisterRecordReply,
            context: *mut c_void,
        ) -> DNSServiceErrorType;

        pub fn DNSServiceRemoveRecord(
            sdRef: DNSServiceRef,
            RecordRef: DNSRecordRef,
            flags: DNSServiceFlags,
        ) -> DNSServiceErrorType;

        pub fn DNSServiceRefDeallocate(sdRef: DNSServiceRef);

        pub fn DNSServiceRefSockFD(sdRef: DNSServiceRef) -> i32;
        pub fn DNSServiceProcessResult(sdRef: DNSServiceRef) -> DNSServiceErrorType;

        // No need for direct FFI for CFSocket/CFRunLoop; use Rust wrappers
    }
}

#[derive(Debug)]
pub struct DNSService {
    sd_ref: ffi::DNSServiceRef,
    _event_loop: Arc<EventLoopManager>,
}

// No longer needed: DispatchContext

/// A registered DNS record (A or AAAA) on a connection-based [`DNSService`].
///
/// Dropping this value deregisters the record via `DNSServiceRemoveRecord`.
/// The parent [`DNSService`] must outlive this value.
#[derive(Debug)]
pub struct DNSRecord {
    sd_ref: ffi::DNSServiceRef,
    rec_ref: ffi::DNSRecordRef,
    _event_loop: Arc<EventLoopManager>,
}

#[derive(Debug)]
pub struct DNSError(ffi::DNSServiceErrorType);

impl std::fmt::Display for DNSError {
    fn fmt(&self, format: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        write!(format, "DNS-SD Error: {:?}", self.0)
    }
}

impl std::error::Error for DNSError {
    fn description(&self) -> &str {
        "DNS-SD Error"
    }
}

impl Drop for DNSRecord {
    fn drop(&mut self) {
        unsafe {
            ffi::DNSServiceRemoveRecord(self.sd_ref, self.rec_ref, 0);
        }
    }
}

impl DNSService {
    /// Register a service advertisement (equivalent to `dns-sd -R`).
    pub fn register(
        name: Option<&str>,
        regtype: &str,
        domain: Option<&str>,
        host: Option<&str>,
        port: u16,
        txt: &[&str],
    ) -> std::result::Result<DNSService, DNSError> {
        let mut sd_ref: ffi::DNSServiceRef = null_mut();

        let txt_data: Vec<u8> = txt
            .into_iter()
            .flat_map(|value| std::iter::once(value.len() as u8).chain(value.bytes()))
            .collect();

        let name = name.map(|s| CString::new(s).unwrap());
        let regtype = CString::new(regtype).unwrap();
        let domain = domain.map(|s| CString::new(s).unwrap());
        let host = host.map(|s| CString::new(s).unwrap());

        let err = unsafe {
            ffi::DNSServiceRegister(
                &mut sd_ref as *mut _,
                0,
                0,
                name.as_ref().map_or(null(), |s| s.as_ptr()),
                regtype.as_ptr(),
                domain.as_ref().map_or(null(), |s| s.as_ptr()),
                host.as_ref().map_or(null(), |s| s.as_ptr()),
                port.to_be(),
                txt_data.len() as u16,
                if txt_data.is_empty() {
                    null()
                } else {
                    txt_data.as_ptr()
                },
                None,
                null_mut(),
            )
        };

        // We must be sure these stay are still alive during the DNSServiceRegister call
        // Because we pass them as raw pointers, rust's borrow checker is useless there
        // If they are still valid at this point, then we're good
        drop(name);
        drop(regtype);
        drop(domain);
        drop(host);
        drop(txt_data);

        if err == ffi::DNSServiceErrorType::NoError {
            Ok(DNSService {
                sd_ref: sd_ref,
                _event_loop: get_event_loop_manager(),
            })
        } else {
            Err(DNSError(err))
        }
    }

    /// Create a connection-based service reference.
    ///
    /// The returned [`DNSService`] can be passed to [`DNSService::register_record`]
    /// to register individual DNS resource records (needed for proxy advertisement).
    pub fn create_connection() -> std::result::Result<DNSService, DNSError> {
        let mut sd_ref: ffi::DNSServiceRef = null_mut();
        let err = unsafe { ffi::DNSServiceCreateConnection(&mut sd_ref as *mut _) };
        if err != ffi::DNSServiceErrorType::NoError {
            return Err(DNSError(err));
        }
        Ok(DNSService {
            sd_ref,
            _event_loop: get_event_loop_manager(),
        })
    }

    /// Register an address record (A for IPv4, AAAA for IPv6) on this connection.
    ///
    /// `fullname` must be a fully-qualified domain name (e.g. `"myhost.local."`).
    /// The address and, for IPv6, the interface scope are taken from `addr`.
    /// The port in `addr` is not used for the DNS record and may be set to `0`.
    ///
    /// For link-local IPv6 addresses the `scope_id` of the [`std::net::SocketAddrV6`]
    /// is used as the interface index passed to `DNSServiceRegisterRecord`.
    /// Use a correctly-scoped value from a string like `"fe80::1%en0"`.
    ///
    /// This is used together with [`DNSService::register`] (specifying the same `host`)
    /// to implement proxy service advertisement (equivalent to `dns-sd -P`):
    ///
    /// ```no_run
    /// use dns_sd::{DNSService, parse_scoped_ipv6};
    /// use std::net::SocketAddr;
    ///
    /// // Plain IPv4 proxy
    /// let conn = DNSService::create_connection().unwrap();
    /// let addr: SocketAddr = "192.0.2.1:0".parse().unwrap();
    /// let _rec = conn.register_record("myhost.local.", addr).unwrap();
    /// let _svc = DNSService::register(Some("My Service"), "_http._tcp", None,
    ///                                 Some("myhost.local."), 80, &[]).unwrap();
    ///
    /// // Link-local IPv6 proxy — scope_id carries the interface index
    /// let conn2 = DNSService::create_connection().unwrap();
    /// let addr6 = parse_scoped_ipv6("fe80::1%en0").unwrap();
    /// let _rec2 = conn2.register_record("myhost6.local.", SocketAddr::V6(addr6)).unwrap();
    /// ```
    ///
    /// The [`DNSRecord`] must be kept alive (alongside `self`) for the registration
    /// to remain active.
    pub fn register_record(
        &self,
        fullname: &str,
        addr: SocketAddr,
    ) -> std::result::Result<DNSRecord, DNSError> {
        let mut rec_ref: ffi::DNSRecordRef = null_mut();
        let fullname = CString::new(fullname).unwrap();

        println!("DEBUG addr: {:?}", addr);

        // Add the socket source to the runloop BEFORE registering the record
        // The DNS-SD library needs the socket to be monitored from the start
        unsafe {
            let fd = ffi::DNSServiceRefSockFD(self.sd_ref);
            let event_loop = get_event_loop_manager();
            event_loop.add_source(fd, self.sd_ref)?;
        }

        let err = match addr {
            SocketAddr::V4(a) => {
                let raw_ip = a.ip().octets();
                unsafe {
                    ffi::DNSServiceRegisterRecord(
                        self.sd_ref,
                        &mut rec_ref as *mut _,
                        ffi::kDNSServiceFlagsUnique,
                        0,
                        fullname.as_ptr(),
                        ffi::kDNSServiceType_A,
                        ffi::kDNSServiceClass_IN,
                        4,
                        raw_ip.as_ptr(),
                        240,
                        Some(register_record_callback),
                        null_mut(),
                    )
                }
            }
            SocketAddr::V6(a) => {
                let raw_ip = a.ip().octets();
                unsafe {
                    ffi::DNSServiceRegisterRecord(
                        self.sd_ref,
                        &mut rec_ref as *mut _,
                        ffi::kDNSServiceFlagsUnique,
                        a.scope_id(),
                        fullname.as_ptr(),
                        ffi::kDNSServiceType_AAAA,
                        ffi::kDNSServiceClass_IN,
                        16,
                        raw_ip.as_ptr(),
                        240,
                        Some(register_record_callback),
                        null_mut(),
                    )
                }
            }
        };

        drop(fullname);

        if err == ffi::DNSServiceErrorType::NoError {
            Ok(DNSRecord {
                sd_ref: self.sd_ref,
                rec_ref,
                _event_loop: get_event_loop_manager(),
            })
        } else {
            Err(DNSError(err))
        }
    }
}

impl Drop for DNSService {
    fn drop(&mut self) {
        unsafe {
            ffi::DNSServiceRefDeallocate(self.sd_ref);
        }
    }
}
