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

// Callback for DNSServiceRegisterRecord
// The context is a Box<mpsc::Sender<ffi::DNSServiceErrorType>> that will be consumed here
extern "C" fn register_record_callback(
    _sdref: ffi::DNSServiceRef,
    _rec: ffi::DNSRecordRef,
    _flags: ffi::DNSServiceFlags,
    error: ffi::DNSServiceErrorType,
    context: *mut c_void,
) {
    if error != ffi::DNSServiceErrorType::NoError {
        eprintln!("DNSServiceRegisterRecord callback error: {:?}", error);
    } else {
        println!("DNSServiceRegisterRecord callback: record registered successfully.");
    }
    
    // Send the error code (or success) on the channel, consuming the sender
    if !context.is_null() {
        unsafe {
            let boxed_tx = Box::from_raw(context as *mut mpsc::Sender<ffi::DNSServiceErrorType>);
            let _ = boxed_tx.send(error);
            // boxed_tx is dropped here, closing the sender side of the channel
        }
    }
}

// Callback for processing DNS-SD socket events
unsafe extern "C-unwind" fn socket_callback(
    _s: *mut CFSocket,
    _type: objc2_core_foundation::CFSocketCallBackType,
    _address: *const objc2_core_foundation::CFData,
    _data: *const std::ffi::c_void,
    info: *mut std::ffi::c_void,
) {
    eprintln!("[CALLBACK] socket_callback invoked!");
    let sd_ref = info as ffi::DNSServiceRef;
    let err = unsafe { ffi::DNSServiceProcessResult(sd_ref) };
    eprintln!("[CALLBACK] DNSServiceProcessResult returned: {:?}", err);
    if err != ffi::DNSServiceErrorType::NoError {
        eprintln!("DNSServiceProcessResult error: {:?}", err);
    }
}

enum BackgroundThreadRequest {
    Register {
        name: Option<String>,
        regtype: String,
        domain: Option<String>,
        host: Option<String>,
        port: u16,
        txt: Vec<String>,
        response_tx: mpsc::Sender<Result<ffi::DNSServiceRef, DNSError>>,
    },
    CreateConnection {
        response_tx: mpsc::Sender<Result<ffi::DNSServiceRef, DNSError>>,
    },
    RegisterRecord {
        sd_ref: ffi::DNSServiceRef,
        fullname: String,
        addr: SocketAddr,
        response_tx: mpsc::Sender<Result<ffi::DNSRecordRef, DNSError>>,
        callback_tx: mpsc::Sender<ffi::DNSServiceErrorType>,
    },
}

unsafe impl Send for BackgroundThreadRequest {}

struct EventLoopManager {
    request_tx: mpsc::Sender<BackgroundThreadRequest>,
    _thread_handle: Mutex<Option<thread::JoinHandle<()>>>,
}

impl std::fmt::Debug for EventLoopManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventLoopManager").finish()
    }
}

impl EventLoopManager {
    fn new() -> Arc<Self> {
        eprintln!("[INIT] EventLoopManager::new() started");
        let (request_tx, request_rx) = mpsc::channel();
        eprintln!("[INIT] Channels created");
        
        let handle = thread::spawn(move || {
            background_thread_main(request_rx);
        });
        eprintln!("[INIT] Background thread spawned");
        
        Arc::new(EventLoopManager {
            request_tx,
            _thread_handle: Mutex::new(Some(handle)),
        })
    }
}

impl Drop for EventLoopManager {
    fn drop(&mut self) {
        if let Ok(mut handle_opt) = self._thread_handle.lock() {
            if let Some(handle) = handle_opt.take() {
                let _ = handle.join();
            }
        }
    }
}

fn background_thread_main(request_rx: mpsc::Receiver<BackgroundThreadRequest>) {
    eprintln!("[BG] Background thread started");
    let runloop = CFRunLoop::current().unwrap();
    eprintln!("[BG] Got CFRunLoop: {:?}", runloop);
    
    loop {
        // Process all pending requests
        loop {
            match request_rx.try_recv() {
                Ok(request) => {
                    match request {
                        BackgroundThreadRequest::Register { name, regtype, domain, host, port, txt, response_tx } => {
                            eprintln!("[BG] Processing Register request: {} type={}", name.as_deref().unwrap_or("(auto)"), regtype);
                            let result = unsafe { dns_service_register(&name, &regtype, &domain, &host, port, &txt) };
                            let _ = response_tx.send(result);
                        }
                        BackgroundThreadRequest::CreateConnection { response_tx } => {
                            eprintln!("[BG] Processing CreateConnection request");
                            let result = unsafe { dns_service_create_connection() };
                            let _ = response_tx.send(result);
                        }
                        BackgroundThreadRequest::RegisterRecord { sd_ref, fullname, addr, response_tx, callback_tx } => {
                            eprintln!("[BG] Processing RegisterRecord request: fullname={}, addr={}", fullname, addr);
                            let result = unsafe { dns_service_register_record(sd_ref, &fullname, addr, &runloop, callback_tx) };
                            eprintln!("[BG] RegisterRecord completed: {:?}", result.is_ok());
                            let _ = response_tx.send(result);
                        }
                    }
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    eprintln!("[BG] Request channel disconnected, exiting background thread");
                    return;
                }
            }
        }
        
        // Run the runloop briefly to process callbacks
        // eprintln!("[BG] Running CFRunLoop::run_in_mode for 10ms");
        unsafe {
            CFRunLoop::run_in_mode(kCFRunLoopDefaultMode, 0.01, true);
        }
        // eprintln!("[BG] CFRunLoop::run_in_mode returned");
    }
}

unsafe fn dns_service_register(
    name: &Option<String>,
    regtype: &str,
    domain: &Option<String>,
    host: &Option<String>,
    port: u16,
    txt: &[String],
) -> Result<ffi::DNSServiceRef, DNSError> {
    let mut sd_ref: ffi::DNSServiceRef = null_mut();

    let txt_data: Vec<u8> = txt
        .iter()
        .flat_map(|value| std::iter::once(value.len() as u8).chain(value.bytes()))
        .collect();

    let name_c = name.as_ref().map(|s| CString::new(s.clone()).unwrap());
    let regtype_c = CString::new(regtype.to_string()).unwrap();
    let domain_c = domain.as_ref().map(|s| CString::new(s.clone()).unwrap());
    let host_c = host.as_ref().map(|s| CString::new(s.clone()).unwrap());

    let err = unsafe {
        ffi::DNSServiceRegister(
            &mut sd_ref,
            0,
            0,
            name_c.as_ref().map_or(null(), |s| s.as_ptr()),
            regtype_c.as_ptr(),
            domain_c.as_ref().map_or(null(), |s| s.as_ptr()),
            host_c.as_ref().map_or(null(), |s| s.as_ptr()),
            port.to_be(),
            txt_data.len() as u16,
            if txt_data.is_empty() { null() } else { txt_data.as_ptr() },
            None,
            null_mut(),
        )
    };

    if err == ffi::DNSServiceErrorType::NoError {
        Ok(sd_ref)
    } else {
        Err(DNSError(err))
    }
}

unsafe fn dns_service_create_connection() -> Result<ffi::DNSServiceRef, DNSError> {
    let mut sd_ref: ffi::DNSServiceRef = null_mut();
    let err = unsafe { ffi::DNSServiceCreateConnection(&mut sd_ref) };
    if err != ffi::DNSServiceErrorType::NoError {
        return Err(DNSError(err));
    }
    Ok(sd_ref)
}

unsafe fn dns_service_register_record(
    sd_ref: ffi::DNSServiceRef,
    fullname: &str,
    addr: SocketAddr,
    runloop: &CFRunLoop,
    callback_tx: mpsc::Sender<ffi::DNSServiceErrorType>,
) -> Result<ffi::DNSRecordRef, DNSError> {
    let mut rec_ref: ffi::DNSRecordRef = null_mut();
    let fullname_c = CString::new(fullname).unwrap();

    eprintln!("[DNS] register_record: fullname={}, addr={}", fullname, addr);

    // Register the socket source BEFORE calling DNSServiceRegisterRecord
    let fd = unsafe { ffi::DNSServiceRefSockFD(sd_ref) };
    eprintln!("[DNS] Socket FD: {}", fd);
    if fd < 0 {
        eprintln!("[DNS] Invalid FD!");
        return Err(DNSError(ffi::DNSServiceErrorType::Unknown));
    }

    let mut context = CFSocketContext {
        version: 0,
        info: sd_ref as *mut _,
        retain: None,
        release: None,
        copyDescription: None,
    };

    eprintln!("[DNS] Creating CFSocket...");
    let cf_sock = match unsafe {
        CFSocket::with_native(
            kCFAllocatorDefault,
            fd,
            1,
            Some(socket_callback),
            &mut context,
        )
    } {
        Some(sock) => {
            eprintln!("[DNS] CFSocket created successfully");
            sock
        }
        None => {
            eprintln!("[DNS] Failed to create CFSocket");
            return Err(DNSError(ffi::DNSServiceErrorType::Unknown));
        }
    };

    let sock_ref: &objc2_core_foundation::CFSocket = cf_sock.as_ref();
    eprintln!("[DNS] Creating runloop source...");
    let rl_source = match unsafe {
        CFSocket::new_run_loop_source(kCFAllocatorDefault, Some(sock_ref), 0)
    } {
        Some(src) => {
            eprintln!("[DNS] Runloop source created successfully");
            src
        }
        None => {
            eprintln!("[DNS] Failed to create runloop source");
            return Err(DNSError(ffi::DNSServiceErrorType::Unknown));
        }
    };

    eprintln!("[DNS] Adding source to runloop...");
    unsafe {
        runloop.add_source(Some(&rl_source), kCFRunLoopDefaultMode);
    }
    eprintln!("[DNS] Source added to runloop");
    std::mem::forget(cf_sock);
    eprintln!("[DNS] CFSocket leaked (intentional)");

    // Now register the record
    eprintln!("[DNS] Calling DNSServiceRegisterRecord...");
    
    // Box the callback sender to pass as context
    let context_ptr = Box::into_raw(Box::new(callback_tx)) as *mut c_void;
    
    let err = match addr {
        SocketAddr::V4(a) => {
            let raw_ip = a.ip().octets();
            unsafe {
                ffi::DNSServiceRegisterRecord(
                    sd_ref,
                    &mut rec_ref,
                    ffi::kDNSServiceFlagsUnique,
                    0,
                    fullname_c.as_ptr(),
                    ffi::kDNSServiceType_A,
                    ffi::kDNSServiceClass_IN,
                    4,
                    raw_ip.as_ptr(),
                    240,
                    Some(register_record_callback),
                    context_ptr,
                )
            }
        }
        SocketAddr::V6(a) => {
            let raw_ip = a.ip().octets();
            unsafe {
                ffi::DNSServiceRegisterRecord(
                    sd_ref,
                    &mut rec_ref,
                    ffi::kDNSServiceFlagsUnique,
                    a.scope_id(),
                    fullname_c.as_ptr(),
                    ffi::kDNSServiceType_AAAA,
                    ffi::kDNSServiceClass_IN,
                    16,
                    raw_ip.as_ptr(),
                    240,
                    Some(register_record_callback),
                    context_ptr,
                )
            }
        }
    };

    eprintln!("[DNS] DNSServiceRegisterRecord returned: {:?}", err);
    
    if err != ffi::DNSServiceErrorType::NoError {
        eprintln!("[DNS] Record registration failed!");
        // Clean up context if registration failed
        unsafe {
            let _ = Box::from_raw(context_ptr as *mut mpsc::Sender<ffi::DNSServiceErrorType>);
        }
        return Err(DNSError(err));
    }
    
    // Return immediately - the main thread will wait for callback completion
    // The context (callback_tx) is now owned by the DNS-SD library and will be consumed
    // by the callback when it fires
    eprintln!("[DNS] Record registered, waiting for callback on main thread");
    Ok(rec_ref)
}

fn get_event_loop_manager() -> Arc<EventLoopManager> {
    static MANAGER: OnceLock<Arc<EventLoopManager>> = OnceLock::new();
    eprintln!("[INIT] Getting or initializing EventLoopManager");
    let result = MANAGER.get_or_init(|| {
        eprintln!("[INIT] Creating new EventLoopManager");
        EventLoopManager::new()
    }).clone();
    eprintln!("[INIT] EventLoopManager ready");
    result
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
    }
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

/// A DNS service reference for registering services and records.
///
/// This struct represents a connection to the DNS service for registration of services
/// or individual DNS records. It maintains the underlying service reference and manages
/// the automatic event loop lifecycle via reference counting.
///
/// Typically used in two ways:
/// - Call [`DNSService::register`] for simple service advertisement
/// - Call [`DNSService::create_connection`] then [`register_record`](Self::register_record)
///   for proxy service advertisement (advertising services for other hosts)
///
/// # Lifetime
///
/// Keep this struct alive for the duration that you want the service to remain
/// registered. When dropped, the service is unregistered. The event loop runs
/// automatically in the background as long as at least one `DNSService` or `DNSRecord`
/// referencing it remains alive.
#[derive(Debug)]
pub struct DNSService {
    sd_ref: ffi::DNSServiceRef,
    _event_loop: Arc<EventLoopManager>,
}

/// A registered DNS resource record (A, AAAA, SRV, etc.).
///
/// This struct represents a registered DNS record. **The record remains registered only
/// as long as this struct is kept alive (in scope).** When the `DNSRecord` is dropped,
/// the underlying DNS record is automatically unregistered via `DNSServiceRemoveRecord`.
///
/// # Lifetime Requirements
///
/// You **must keep the `DNSRecord` alive** for the entire duration that you want the
/// record to remain registered. If you accidentally let it go out of scope or drop it,
/// the record will be immediately unregistered and no longer available for DNS queries.
///
/// # Example
///
/// ```ignore
/// let conn = DNSService::create_connection()?;
/// let addr: SocketAddr = "192.0.2.100:0".parse()?;
/// let _record = conn.register_record("myhost.local.", addr)?;
///
/// // The record is registered and will respond to DNS queries
/// thread::sleep(Duration::from_secs(60));
///
/// // When _record is dropped here, the record is unregistered
/// ```
#[derive(Debug)]
pub struct DNSRecord {
    sd_ref: ffi::DNSServiceRef,
    rec_ref: ffi::DNSRecordRef,
    _event_loop: Arc<EventLoopManager>,
}

impl Drop for DNSRecord {
    fn drop(&mut self) {
        unsafe {
            ffi::DNSServiceRemoveRecord(self.sd_ref, self.rec_ref, 0);
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

impl DNSService {
    /// Register a service advertisement (equivalent to `dns-sd -R`).
    ///
    /// This method advertises a service with the given name, type, and port. The service
    /// will be discoverable by other applications on the local network.
    ///
    /// # Arguments
    ///
    /// * `name` - Optional service instance name. If `None`, the system default (usually
    ///   the hostname) is used.
    /// * `regtype` - The service registration type (e.g., `"_http._tcp"`, `"_ssh._tcp"`)
    /// * `domain` - Optional domain name. Typically `Some("local")` for Bonjour on the
    ///   local network.
    /// * `host` - Optional fully-qualified hostname. If provided with `create_connection`
    ///   and `register_record`, this enables proxy advertisement for other hosts.
    /// * `port` - The port number on which the service is accessible.
    /// * `txt` - Text records (key-value pairs) providing additional service metadata.
    ///
    /// # Lifetime Requirements
    ///
    /// **Keep the returned [`DNSService`] alive** for the duration that you want the
    /// service to remain advertised. When it is dropped, the service is unregistered.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use dns_sd::DNSService;
    ///
    /// let _service = DNSService::register(
    ///     Some("My App"),
    ///     "_http._tcp",
    ///     Some("local"),
    ///     None,
    ///     8080,
    ///     &["path=/api", "version=1.0"],
    /// )?;
    ///
    /// // Service is registered and discoverable
    /// std::thread::sleep(std::time::Duration::from_secs(60));
    /// // Service is unregistered when _ scope ends
    /// ```
    ///
    /// # Returns
    ///
    /// Returns a [`DNSService`] on success, or a [`DNSError`] if registration fails.
    pub fn register(
        name: Option<&str>,
        regtype: &str,
        domain: Option<&str>,
        host: Option<&str>,
        port: u16,
        txt: &[&str],
    ) -> Result<DNSService, DNSError> {
        eprintln!("[API] register() called: name={:?}, regtype={}", name, regtype);
        let event_loop = get_event_loop_manager();
        let (response_tx, response_rx) = mpsc::channel();

        let request = BackgroundThreadRequest::Register {
            name: name.map(|s| s.to_string()),
            regtype: regtype.to_string(),
            domain: domain.map(|s| s.to_string()),
            host: host.map(|s| s.to_string()),
            port,
            txt: txt.iter().map(|s| s.to_string()).collect(),
            response_tx,
        };

        eprintln!("[API] Sending register request to background thread");
        event_loop.request_tx.send(request).map_err(|_| DNSError(ffi::DNSServiceErrorType::Unknown))?;
        eprintln!("[API] Waiting for response...");
        let sd_ref = response_rx.recv().map_err(|_| DNSError(ffi::DNSServiceErrorType::Unknown))??;
        eprintln!("[API] register() succeeded");

        Ok(DNSService {
            sd_ref,
            _event_loop: event_loop,
        })
    }

    /// Create a connection-based service reference for registering individual DNS records.
    ///
    /// This is used to implement proxy service advertisement, where you advertise a
    /// service on behalf of another host. You can then use [`register_record`](Self::register_record)
    /// to register individual address records (A or AAAA) for that service.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use dns_sd::DNSService;
    /// use std::net::SocketAddr;
    ///
    /// // Create a connection for proxy records
    /// let conn = DNSService::create_connection()?;
    ///
    /// // Register an address record
    /// let addr: SocketAddr = "192.0.2.100:0".parse()?;
    /// let _record = conn.register_record("myhost.local.", addr)?;
    ///
    /// // Register the service
    /// let _service = DNSService::register(
    ///     Some("My Service"),
    ///     "_http._tcp",
    ///     None,
    ///     Some("myhost.local."),
    ///     80,
    ///     &[],
    /// )?;
    ///
    /// // Keep both alive as long as the registration should remain active
    /// std::thread::sleep(std::time::Duration::from_secs(60));
    /// ```
    ///
    /// # Returns
    ///
    /// Returns a [`DNSService`] that can be used to register DNS records, or a
    /// [`DNSError`] if the connection cannot be created.
    pub fn create_connection() -> Result<DNSService, DNSError> {
        eprintln!("[API] create_connection() called");
        let event_loop = get_event_loop_manager();
        let (response_tx, response_rx) = mpsc::channel();

        let request = BackgroundThreadRequest::CreateConnection { response_tx };

        eprintln!("[API] Sending create_connection request to background thread");
        event_loop.request_tx.send(request).map_err(|_| DNSError(ffi::DNSServiceErrorType::Unknown))?;
        eprintln!("[API] Waiting for response...");
        let sd_ref = response_rx.recv().map_err(|_| DNSError(ffi::DNSServiceErrorType::Unknown))??;
        eprintln!("[API] create_connection() succeeded");

        Ok(DNSService {
            sd_ref,
            _event_loop: event_loop,
        })
    }

    /// Register an address record (A for IPv4, AAAA for IPv6) on this connection.
    ///
    /// This method registers a DNS address record that will respond to queries for the
    /// specified fully-qualified domain name. **This call blocks the caller until the
    /// DNS-SD callback confirms the registration is complete.** This ensures safe ordering
    /// for subsequent operations like network mounting.
    ///
    /// # Arguments
    ///
    /// * `fullname` - A fully-qualified domain name (FQDN) including the trailing dot,
    ///   e.g. `"myhost.local."` or `"example.com."`
    /// * `addr` - A `SocketAddr` containing the IP address to register. The port in the
    ///   address is ignored and can be set to `0`. For IPv6 link-local addresses with
    ///   a scope ID (e.g., `"fe80::1%en0"`), the scope ID becomes the interface index
    ///   passed to the DNS-SD library.
    ///
    /// # Blocking Behavior
    ///
    /// This method blocks the calling thread (typically main) until the DNS-SD registration
    /// callback fires, confirming the record has been registered. This prevents race
    /// conditions where subsequent code might proceed before DNS queries are being answered.
    /// The background event loop thread continues processing normally during this wait.
    ///
    /// # Lifetime Requirements
    ///
    /// **Critical:** You must keep the returned [`DNSRecord`] alive (in scope) for as long
    /// as you want the record to remain registered. When the `DNSRecord` is dropped, the
    /// record is immediately unregistered and will no longer respond to DNS queries.
    ///
    /// This is a common source of bugs: if you call this method but don't store the
    /// returned `DNSRecord` in a variable that outlives the registration period, the
    /// record will be unregistered immediately.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use dns_sd::DNSService;
    /// use std::net::SocketAddr;
    /// use std::thread;
    /// use std::time::Duration;
    ///
    /// // CORRECT: Keep the record alive
    /// let conn = DNSService::create_connection()?;
    /// let addr: SocketAddr = "192.0.2.1:0".parse()?;
    /// let _record = conn.register_record("myhost.local.", addr)?;  // Store in variable
    ///
    /// // The record is now registered and responding to DNS queries
    /// thread::sleep(Duration::from_secs(30));
    /// // Record is unregistered when _record is dropped
    ///
    /// // WRONG: Record is immediately unregistered
    /// let _addr: SocketAddr = "192.0.2.2:0".parse()?;
    /// conn.register_record("other.local.", _addr)?;  // Record unregistered immediately!
    /// ```
    ///
    /// # Returns
    ///
    /// Returns a [`DNSRecord`] on success, which must be kept alive to maintain the
    /// registration. Returns a [`DNSError`] if the registration fails.
    pub fn register_record(
        &self,
        fullname: &str,
        addr: SocketAddr,
    ) -> Result<DNSRecord, DNSError> {
        eprintln!("[API] register_record() called: fullname={}, addr={}", fullname, addr);
        let (response_tx, response_rx) = mpsc::channel();
        let (callback_tx, callback_rx) = mpsc::channel();

        let request = BackgroundThreadRequest::RegisterRecord {
            sd_ref: self.sd_ref,
            fullname: fullname.to_string(),
            addr,
            response_tx,
            callback_tx,
        };

        eprintln!("[API] Sending register_record request to background thread");
        self._event_loop.request_tx.send(request).map_err(|_| DNSError(ffi::DNSServiceErrorType::Unknown))?;
        eprintln!("[API] Waiting for registration response...");
        let rec_ref = response_rx.recv().map_err(|_| DNSError(ffi::DNSServiceErrorType::Unknown))??;
        
        eprintln!("[API] Waiting for callback completion...");
        let callback_result = callback_rx.recv().map_err(|_| DNSError(ffi::DNSServiceErrorType::Unknown))?;
        
        if callback_result != ffi::DNSServiceErrorType::NoError {
            eprintln!("[API] Callback returned error: {:?}", callback_result);
            return Err(DNSError(callback_result));
        }
        
        eprintln!("[API] register_record() succeeded");

        Ok(DNSRecord {
            sd_ref: self.sd_ref,
            rec_ref,
            _event_loop: self._event_loop.clone(),
        })
    }
}
