#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

pub mod sl_cpc;

#[derive(Debug, Copy, Clone)]
pub struct cpc_handle {
    pub cpc: sl_cpc::cpc_handle_t,
}
unsafe impl Send for cpc_handle {}

#[derive(Debug, Copy, Clone)]
pub struct cpc_endpoint {
    endpoint: sl_cpc::cpc_endpoint_t,
    pub fd: std::os::unix::io::RawFd,
}
unsafe impl Send for cpc_endpoint {}

#[derive(Debug, Copy, Clone)]
pub struct cpc_endpoint_event {
    event: sl_cpc::cpc_endpoint_event_handle_t,
    pub fd: std::os::unix::io::RawFd,
}
unsafe impl Send for cpc_endpoint_event {}

pub fn cpc_buffer() -> Vec<u8> {
    vec![0; sl_cpc::SL_CPC_READ_MINIMUM_SIZE as usize]
}

pub fn init(
    instance_name: &str,
    enable_tracing: bool,
    reset_callback: std::option::Option<unsafe extern "C" fn()>,
) -> Result<cpc_handle, std::os::raw::c_int> {
    let mut cpc = sl_cpc::cpc_handle_t {
        ptr: 0 as *mut std::os::raw::c_void,
    };

    let err = unsafe {
        sl_cpc::cpc_init(
            &mut cpc as *mut sl_cpc::cpc_handle_t,
            std::ffi::CString::new(instance_name)
                .unwrap()
                .as_bytes_with_nul()
                .as_ptr() as *const std::os::raw::c_char,
            enable_tracing,
            reset_callback,
        )
    };

    if err != 0 {
        Err(err)
    } else {
        Ok(cpc_handle { cpc })
    }
}

pub fn restart(cpc: &mut cpc_handle) -> Result<(), std::os::raw::c_int> {
    let err = unsafe { sl_cpc::cpc_restart(&mut cpc.cpc as *mut sl_cpc::cpc_handle_t) };

    if err < 0 {
        Err(err)
    } else {
        Ok(())
    }
}

pub fn open_endpoint(
    cpc: &cpc_handle,
    id: u8,
    tx_window_size: u8,
) -> Result<cpc_endpoint, std::os::raw::c_int> {
    let mut endpoint = sl_cpc::cpc_endpoint_t {
        ptr: 0 as *mut std::os::raw::c_void,
    };

    let fd = unsafe {
        sl_cpc::cpc_open_endpoint(
            cpc.cpc,
            &mut endpoint as *mut sl_cpc::cpc_endpoint_t,
            id,
            tx_window_size,
        )
    };

    if fd < 0 {
        Err(fd)
    } else {
        Ok(cpc_endpoint { endpoint, fd })
    }
}

pub fn close_endpoint(endpoint: &mut cpc_endpoint) -> Result<(), std::os::raw::c_int> {
    let err = unsafe {
        sl_cpc::cpc_close_endpoint(&mut endpoint.endpoint as *mut sl_cpc::cpc_endpoint_t)
    };

    if err < 0 {
        Err(err)
    } else {
        Ok(())
    }
}

pub fn write_endpoint(
    endpoint: &cpc_endpoint,
    data: &Vec<u8>,
    flags: sl_cpc::cpc_endpoint_write_flags_t,
) -> Result<isize, isize> {
    let bytes_written = unsafe {
        sl_cpc::cpc_write_endpoint(
            endpoint.endpoint,
            data.as_ptr() as *const std::ffi::c_void,
            data.len().try_into().unwrap(),
            flags,
        )
    };

    if bytes_written < 0 {
        Err(bytes_written)
    } else {
        Ok(bytes_written)
    }
}

pub fn read_endpoint(
    endpoint: &cpc_endpoint,
    flags: sl_cpc::cpc_endpoint_read_flags_t,
) -> Result<Vec<u8>, isize> {
    let mut buffer = cpc_buffer();

    let bytes_read = unsafe {
        sl_cpc::cpc_read_endpoint(
            endpoint.endpoint,
            buffer.as_mut_ptr() as *mut std::ffi::c_void,
            buffer.len().try_into().unwrap(),
            flags,
        )
    };

    if bytes_read < 0 {
        Err(bytes_read)
    } else {
        Ok((&buffer[..bytes_read as usize]).to_vec())
    }
}

pub fn get_endpoint_state(
    cpc: &cpc_handle,
    id: u8,
) -> Result<sl_cpc::cpc_endpoint_state_t_enum, std::os::raw::c_int> {
    let mut state: sl_cpc::cpc_endpoint_state_t = 0;

    let err = unsafe {
        sl_cpc::cpc_get_endpoint_state(cpc.cpc, id, &mut state as *mut sl_cpc::cpc_endpoint_state_t)
    };

    if err < 0 {
        Err(err)
    } else {
        Ok(sl_cpc::cpc_endpoint_state_t_enum::try_from(state as u32).unwrap())
    }
}

pub fn set_endpoint_option(
    endpoint: &cpc_endpoint,
    option: sl_cpc::cpc_option_t_enum,
    optval: *const std::os::raw::c_void,
    optlen: usize,
) -> Result<(), std::os::raw::c_int> {
    let err = unsafe {
        sl_cpc::cpc_set_endpoint_option(
            endpoint.endpoint,
            option as sl_cpc::cpc_option_t,
            optval,
            optlen,
        )
    };

    if err < 0 {
        Err(err)
    } else {
        Ok(())
    }
}

pub fn get_endpoint_option(
    endpoint: &cpc_endpoint,
    option: sl_cpc::cpc_option_t_enum,
    optval: *mut std::os::raw::c_void,
    optlen: *mut usize,
) -> Result<(), std::os::raw::c_int> {
    let err = unsafe {
        sl_cpc::cpc_get_endpoint_option(
            endpoint.endpoint,
            option as sl_cpc::cpc_option_t,
            optval,
            optlen,
        )
    };

    if err < 0 {
        Err(err)
    } else {
        Ok(())
    }
}

pub fn get_library_version() -> Option<String> {
    unsafe {
        let ptr = sl_cpc::cpc_get_library_version();
        if ptr == std::ptr::null() {
            None
        } else {
            match std::ffi::CStr::from_ptr(ptr).to_str() {
                Ok(str) => Some(str.to_string()),
                Err(_) => None,
            }
        }
    }
}

pub fn get_secondary_app_version(cpc: &cpc_handle) -> Option<String> {
    unsafe {
        let ptr = sl_cpc::cpc_get_secondary_app_version(cpc.cpc);
        if ptr == std::ptr::null() {
            None
        } else {
            match std::ffi::CStr::from_ptr(ptr).to_str() {
                Ok(str) => {
                    let copy = str.to_owned();
                    if sl_cpc::cpc_free_secondary_app_version(ptr as *mut std::os::raw::c_char) < 0
                    {
                        None
                    } else {
                        Some(copy)
                    }
                }
                Err(_) => None,
            }
        }
    }
}

pub fn set_endpoint_read_timeout(
    endpoint: &cpc_endpoint,
    timeval: sl_cpc::cpc_timeval_t,
) -> Result<(), std::os::raw::c_int> {
    let err = unsafe { sl_cpc::cpc_set_endpoint_read_timeout(endpoint.endpoint, timeval) };

    if err < 0 {
        Err(err)
    } else {
        Ok(())
    }
}

pub fn get_endpoint_read_timeout(
    endpoint: &cpc_endpoint,
) -> Result<sl_cpc::cpc_timeval_t, std::os::raw::c_int> {
    let mut timeval = sl_cpc::cpc_timeval_t {
        seconds: 0,
        microseconds: 0,
    };

    let err = unsafe {
        sl_cpc::cpc_get_endpoint_read_timeout(
            endpoint.endpoint,
            &mut timeval as *mut sl_cpc::cpc_timeval_t,
        )
    };

    if err < 0 {
        Err(err)
    } else {
        Ok(timeval)
    }
}

pub fn set_endpoint_write_timeout(
    endpoint: &cpc_endpoint,
    timeval: sl_cpc::cpc_timeval_t,
) -> Result<(), std::os::raw::c_int> {
    let err = unsafe { sl_cpc::cpc_set_endpoint_write_timeout(endpoint.endpoint, timeval) };

    if err < 0 {
        Err(err)
    } else {
        Ok(())
    }
}

pub fn get_endpoint_write_timeout(
    endpoint: &cpc_endpoint,
) -> Result<sl_cpc::cpc_timeval_t, std::os::raw::c_int> {
    let mut timeval = sl_cpc::cpc_timeval_t {
        seconds: 0,
        microseconds: 0,
    };

    let err = unsafe {
        sl_cpc::cpc_get_endpoint_write_timeout(
            endpoint.endpoint,
            &mut timeval as *mut sl_cpc::cpc_timeval_t,
        )
    };

    if err < 0 {
        Err(err)
    } else {
        Ok(timeval)
    }
}

pub fn set_endpoint_blocking(
    endpoint: &cpc_endpoint,
    blocking: bool,
) -> Result<(), std::os::raw::c_int> {
    let err = unsafe { sl_cpc::cpc_set_endpoint_blocking(endpoint.endpoint, blocking) };

    if err < 0 {
        Err(err)
    } else {
        Ok(())
    }
}

pub fn get_endpoint_blocking_mode(endpoint: &cpc_endpoint) -> Result<bool, std::os::raw::c_int> {
    let mut is_blocking = false;

    let err = unsafe {
        sl_cpc::cpc_get_endpoint_blocking_mode(endpoint.endpoint, &mut is_blocking as *mut bool)
    };

    if err < 0 {
        Err(err)
    } else {
        Ok(is_blocking)
    }
}

pub fn set_endpoint_socket_size(
    endpoint: &cpc_endpoint,
    socket_size: u32,
) -> Result<(), std::os::raw::c_int> {
    let err = unsafe { sl_cpc::cpc_set_endpoint_socket_size(endpoint.endpoint, socket_size) };

    if err < 0 {
        Err(err)
    } else {
        Ok(())
    }
}

pub fn get_endpoint_socket_size(endpoint: &cpc_endpoint) -> Result<u32, std::os::raw::c_int> {
    let mut socket_size = 0;

    let err = unsafe {
        sl_cpc::cpc_get_endpoint_socket_size(endpoint.endpoint, &mut socket_size as *mut u32)
    };

    if err < 0 {
        Err(err)
    } else {
        Ok(socket_size)
    }
}

pub fn get_endpoint_max_write_size(endpoint: &cpc_endpoint) -> Result<usize, std::os::raw::c_int> {
    let mut max_write_size: usize = 0;

    let err = unsafe {
        sl_cpc::cpc_get_endpoint_max_write_size(
            endpoint.endpoint,
            &mut max_write_size as *mut usize,
        )
    };

    if err < 0 {
        Err(err)
    } else {
        Ok(max_write_size)
    }
}

pub fn get_endpoint_encryption_state(endpoint: &cpc_endpoint) -> Result<bool, std::os::raw::c_int> {
    let mut encrypted = false;

    let err = unsafe {
        sl_cpc::cpc_get_endpoint_encryption_state(endpoint.endpoint, &mut encrypted as *mut bool)
    };

    if err < 0 {
        Err(err)
    } else {
        Ok(encrypted)
    }
}

pub fn init_endpoint_event(
    cpc: &cpc_handle,
    id: u8,
) -> Result<cpc_endpoint_event, std::os::raw::c_int> {
    let mut event = sl_cpc::cpc_endpoint_event_handle_t {
        ptr: 0 as *mut std::os::raw::c_void,
    };

    let fd = unsafe {
        sl_cpc::cpc_init_endpoint_event(
            cpc.cpc,
            &mut event as *mut sl_cpc::cpc_endpoint_event_handle_t,
            id,
        )
    };

    if fd < 0 {
        Err(fd)
    } else {
        Ok(cpc_endpoint_event { event, fd })
    }
}

pub fn deinit_endpoint_event(event: &mut cpc_endpoint_event) -> Result<(), std::os::raw::c_int> {
    let err = unsafe {
        sl_cpc::cpc_deinit_endpoint_event(
            &mut event.event as *mut sl_cpc::cpc_endpoint_event_handle_t,
        )
    };

    if err < 0 {
        Err(err)
    } else {
        Ok(())
    }
}

pub fn read_endpoint_event(
    event: &cpc_endpoint_event,
    flags: sl_cpc::cpc_events_flags_t,
) -> Result<sl_cpc::cpc_event_type_t_enum, std::os::raw::c_int> {
    let mut event_type: sl_cpc::cpc_event_type_t = 0;

    let err = unsafe {
        sl_cpc::cpc_read_endpoint_event(
            event.event,
            &mut event_type as *mut sl_cpc::cpc_event_type_t,
            flags,
        )
    };

    if err < 0 {
        Err(err)
    } else {
        Ok(sl_cpc::cpc_event_type_t_enum::try_from(event_type as u32).unwrap())
    }
}

pub fn get_endpoint_event_option(
    event: &cpc_endpoint_event,
    option: sl_cpc::cpc_endpoint_event_option_t_enum,
    optval: *mut std::os::raw::c_void,
    optlen: *mut usize,
) -> Result<(), std::os::raw::c_int> {
    let err = unsafe {
        sl_cpc::cpc_get_endpoint_event_option(
            event.event,
            option as sl_cpc::cpc_endpoint_event_option_t,
            optval,
            optlen,
        )
    };

    if err < 0 {
        Err(err)
    } else {
        Ok(())
    }
}

pub fn set_endpoint_event_option(
    event: &cpc_endpoint_event,
    option: sl_cpc::cpc_endpoint_event_option_t_enum,
    optval: *const std::os::raw::c_void,
    optlen: usize,
) -> Result<(), std::os::raw::c_int> {
    let err = unsafe {
        sl_cpc::cpc_set_endpoint_event_option(
            event.event,
            option as sl_cpc::cpc_endpoint_event_option_t,
            optval,
            optlen,
        )
    };

    if err < 0 {
        Err(err)
    } else {
        Ok(())
    }
}

pub fn set_endpoint_event_read_timeout(
    event: &cpc_endpoint_event,
    timeval: sl_cpc::cpc_timeval_t,
) -> Result<(), std::os::raw::c_int> {
    let err = unsafe { sl_cpc::cpc_set_endpoint_event_read_timeout(event.event, timeval) };

    if err < 0 {
        Err(err)
    } else {
        Ok(())
    }
}

pub fn get_endpoint_event_read_timeout(
    event: &cpc_endpoint_event,
) -> Result<sl_cpc::cpc_timeval_t, std::os::raw::c_int> {
    let mut timeval = sl_cpc::cpc_timeval_t {
        seconds: 0,
        microseconds: 0,
    };

    let err = unsafe {
        sl_cpc::cpc_get_endpoint_event_read_timeout(
            event.event,
            &mut timeval as *mut sl_cpc::cpc_timeval_t,
        )
    };

    if err < 0 {
        Err(err)
    } else {
        Ok(timeval)
    }
}

pub fn set_endpoint_event_blocking(
    event: &cpc_endpoint_event,
    blocking: bool,
) -> Result<(), std::os::raw::c_int> {
    let err = unsafe { sl_cpc::cpc_set_endpoint_event_blocking(event.event, blocking) };

    if err < 0 {
        Err(err)
    } else {
        Ok(())
    }
}

pub fn get_endpoint_event_blocking_mode(
    event: &cpc_endpoint_event,
) -> Result<bool, std::os::raw::c_int> {
    let mut is_blocking = false;

    let err = unsafe {
        sl_cpc::cpc_get_endpoint_event_blocking_mode(event.event, &mut is_blocking as *mut bool)
    };

    if err < 0 {
        Err(err)
    } else {
        Ok(is_blocking)
    }
}
