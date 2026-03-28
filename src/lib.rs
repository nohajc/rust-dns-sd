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
        let (request_tx, request_rx) = mpsc::channel();
        
        let handle = thread::spawn(move || {
            background_thread_main(request_rx);
        });
        
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
    let runloop = CFRunLoop::current().unwrap();
    
    loop {
        // Process all pending requests
        loop {
            match request_rx.try_recv() {
                Ok(request) => {
                    match request {
                        BackgroundThreadRequest::Register { name, regtype, domain, host, port, txt, response_tx } => {
                            let result = unsafe { dns_service_register(&name, &regtype, &domain, &host, port, &txt) };
                            let _ = response_tx.send(result);
                        }
                        BackgroundThreadRequest::CreateConnection { response_tx } => {
                            let result = unsafe { dns_service_create_connection() };
                            let _ = response_tx.send(result);
                        }
                        BackgroundThreadRequest::RegisterRecord { sd_ref, fullname, addr, response_tx } => {
                            let result = unsafe { dns_service_register_record(sd_ref, &fullname, addr, &runloop) };
                            let _ = response_tx.send(result);
                        }
                    }
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => return,
            }
        }
        
        // Run the runloop briefly to process callbacks
        unsafe {
            CFRunLoop::run_in_mode(kCFRunLoopDefaultMode, 0.01, true);
        }
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
) -> Result<ffi::DNSRecordRef, DNSError> {
    let mut rec_ref: ffi::DNSRecordRef = null_mut();
    let fullname_c = CString::new(fullname).unwrap();

    println!("DEBUG addr: {:?}", addr);

    // Register the socket source BEFORE calling DNSServiceRegisterRecord
    let fd = unsafe { ffi::DNSServiceRefSockFD(sd_ref) };
    if fd < 0 {
        return Err(DNSError(ffi::DNSServiceErrorType::Unknown));
    }

    let mut context = CFSocketContext {
        version: 0,
        info: sd_ref as *mut _,
        retain: None,
        release: None,
        copyDescription: None,
    };

    let cf_sock = match unsafe {
        CFSocket::with_native(
            kCFAllocatorDefault,
            fd,
            1,
            Some(socket_callback),
            &mut context,
        )
    } {
        Some(sock) => sock,
        None => return Err(DNSError(ffi::DNSServiceErrorType::Unknown)),
    };

    let sock_ref: &objc2_core_foundation::CFSocket = cf_sock.as_ref();
    let rl_source = match unsafe {
        CFSocket::new_run_loop_source(kCFAllocatorDefault, Some(sock_ref), 0)
    } {
        Some(src) => src,
        None => return Err(DNSError(ffi::DNSServiceErrorType::Unknown)),
    };

    unsafe {
        runloop.add_source(Some(&rl_source), kCFRunLoopDefaultMode);
    }
    std::mem::forget(cf_sock);

    // Now register the record
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
                    null_mut(),
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
                    null_mut(),
                )
            }
        }
    };

    if err == ffi::DNSServiceErrorType::NoError {
        Ok(rec_ref)
    } else {
        Err(DNSError(err))
    }
}

fn get_event_loop_manager() -> Arc<EventLoopManager> {
    static MANAGER: OnceLock<Arc<EventLoopManager>> = OnceLock::new();
    MANAGER.get_or_init(|| EventLoopManager::new()).clone()
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

#[derive(Debug)]
pub struct DNSService {
    sd_ref: ffi::DNSServiceRef,
    _event_loop: Arc<EventLoopManager>,
}

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
    pub fn register(
        name: Option<&str>,
        regtype: &str,
        domain: Option<&str>,
        host: Option<&str>,
        port: u16,
        txt: &[&str],
    ) -> Result<DNSService, DNSError> {
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

        event_loop.request_tx.send(request).map_err(|_| DNSError(ffi::DNSServiceErrorType::Unknown))?;
        let sd_ref = response_rx.recv().map_err(|_| DNSError(ffi::DNSServiceErrorType::Unknown))??;

        Ok(DNSService {
            sd_ref,
            _event_loop: event_loop,
        })
    }

    pub fn create_connection() -> Result<DNSService, DNSError> {
        let event_loop = get_event_loop_manager();
        let (response_tx, response_rx) = mpsc::channel();

        let request = BackgroundThreadRequest::CreateConnection { response_tx };

        event_loop.request_tx.send(request).map_err(|_| DNSError(ffi::DNSServiceErrorType::Unknown))?;
        let sd_ref = response_rx.recv().map_err(|_| DNSError(ffi::DNSServiceErrorType::Unknown))??;

        Ok(DNSService {
            sd_ref,
            _event_loop: event_loop,
        })
    }

    pub fn register_record(
        &self,
        fullname: &str,
        addr: SocketAddr,
    ) -> Result<DNSRecord, DNSError> {
        let (response_tx, response_rx) = mpsc::channel();

        let request = BackgroundThreadRequest::RegisterRecord {
            sd_ref: self.sd_ref,
            fullname: fullname.to_string(),
            addr,
            response_tx,
        };

        self._event_loop.request_tx.send(request).map_err(|_| DNSError(ffi::DNSServiceErrorType::Unknown))?;
        let rec_ref = response_rx.recv().map_err(|_| DNSError(ffi::DNSServiceErrorType::Unknown))??;

        Ok(DNSRecord {
            sd_ref: self.sd_ref,
            rec_ref,
            _event_loop: self._event_loop.clone(),
        })
    }
}
