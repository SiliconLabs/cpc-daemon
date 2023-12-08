#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

use thiserror::Error;

pub use libcpc_sys::{
    cpc_endpoint_event_flags_t_enum, cpc_endpoint_event_option_t_enum,
    cpc_endpoint_read_flags_t_enum, cpc_endpoint_state_t_enum, cpc_endpoint_write_flags_t_enum,
    cpc_event_type_t_enum, cpc_handle_t, cpc_option_t_enum, cpc_timeval_t,
    sl_cpc_service_endpoint_id_t_enum, sl_cpc_user_endpoint_id_t_enum,
};

#[derive(Debug, Copy, Clone)]
pub enum cpc_endpoint_id {
    Service(libcpc_sys::sl_cpc_service_endpoint_id_t_enum),
    User(libcpc_sys::sl_cpc_user_endpoint_id_t_enum),
}
impl From<cpc_endpoint_id> for u8 {
    fn from(id: cpc_endpoint_id) -> u8 {
        match id {
            cpc_endpoint_id::Service(id) => id as u8,
            cpc_endpoint_id::User(id) => id as u8,
        }
    }
}

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Errno(std::io::Error),
    #[error(transparent)]
    NulError(#[from] std::ffi::NulError),
    #[error(transparent)]
    InvalidEndpointStateType(#[from] num_enum::TryFromPrimitiveError<cpc_endpoint_state_t_enum>),
    #[error(transparent)]
    InvalidEndpointEventType(#[from] num_enum::TryFromPrimitiveError<cpc_event_type_t_enum>),
}

#[derive(Debug, Copy, Clone)]
pub struct cpc_handle {
    pub cpc: libcpc_sys::cpc_handle_t,
}
unsafe impl Send for cpc_handle {}
unsafe impl Sync for cpc_handle {}
impl cpc_handle {
    pub fn open_endpoint(
        &self,
        id: cpc_endpoint_id,
        tx_window_size: u8,
    ) -> Result<cpc_endpoint, Error> {
        let mut endpoint = libcpc_sys::cpc_endpoint_t {
            ptr: 0 as *mut std::os::raw::c_void,
        };

        let fd = unsafe {
            libcpc_sys::cpc_open_endpoint(
                self.cpc,
                &mut endpoint as *mut libcpc_sys::cpc_endpoint_t,
                id.into(),
                tx_window_size,
            )
        };

        if fd < 0 {
            Err(Error::Errno(std::io::Error::from_raw_os_error(-fd)))
        } else {
            Ok(cpc_endpoint { endpoint, fd })
        }
    }

    pub fn get_endpoint_state(
        &self,
        id: cpc_endpoint_id,
    ) -> Result<cpc_endpoint_state_t_enum, Error> {
        let mut state: libcpc_sys::cpc_endpoint_state_t = 0;

        let err = unsafe {
            libcpc_sys::cpc_get_endpoint_state(
                self.cpc,
                id.into(),
                &mut state as *mut libcpc_sys::cpc_endpoint_state_t,
            )
        };

        if err < 0 {
            Err(Error::Errno(std::io::Error::from_raw_os_error(-err)))
        } else {
            Ok(cpc_endpoint_state_t_enum::try_from(state as u32)?)
        }
    }

    pub fn init_endpoint_event(&self, id: cpc_endpoint_id) -> Result<cpc_endpoint_event, Error> {
        let mut event = libcpc_sys::cpc_endpoint_event_handle_t {
            ptr: 0 as *mut std::os::raw::c_void,
        };

        let fd = unsafe {
            libcpc_sys::cpc_init_endpoint_event(
                self.cpc,
                &mut event as *mut libcpc_sys::cpc_endpoint_event_handle_t,
                id.into(),
            )
        };

        if fd < 0 {
            Err(Error::Errno(std::io::Error::from_raw_os_error(-fd)))
        } else {
            Ok(cpc_endpoint_event { event, fd })
        }
    }

    pub fn get_secondary_app_version(&self) -> Option<String> {
        unsafe {
            let ptr = libcpc_sys::cpc_get_secondary_app_version(self.cpc);
            if ptr == std::ptr::null() {
                None
            } else {
                match std::ffi::CStr::from_ptr(ptr).to_str() {
                    Ok(str) => {
                        let copy = str.to_owned();
                        if libcpc_sys::cpc_free_secondary_app_version(
                            ptr as *mut std::os::raw::c_char,
                        ) < 0
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

    pub fn restart(&mut self) -> Result<(), Error> {
        let err =
            unsafe { libcpc_sys::cpc_restart(&mut self.cpc as *mut libcpc_sys::cpc_handle_t) };

        if err < 0 {
            Err(Error::Errno(std::io::Error::from_raw_os_error(-err)))
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub struct cpc_endpoint {
    endpoint: libcpc_sys::cpc_endpoint_t,
    pub fd: std::os::unix::io::RawFd,
}
unsafe impl Send for cpc_endpoint {}
unsafe impl Sync for cpc_endpoint {}
impl cpc_endpoint {
    pub fn close(&mut self) -> Result<(), Error> {
        let err = unsafe {
            libcpc_sys::cpc_close_endpoint(&mut self.endpoint as *mut libcpc_sys::cpc_endpoint_t)
        };

        if err < 0 {
            Err(Error::Errno(std::io::Error::from_raw_os_error(-err)))
        } else {
            Ok(())
        }
    }

    pub fn write(
        &self,
        data: &[u8],
        flags: &[cpc_endpoint_write_flags_t_enum],
    ) -> Result<(), Error> {
        let mut write_flags = 0;
        for flag in flags {
            write_flags |= *flag as libcpc_sys::cpc_endpoint_write_flags_t;
        }

        let err = unsafe {
            libcpc_sys::cpc_write_endpoint(
                self.endpoint,
                data.as_ptr() as *const std::ffi::c_void,
                data.len(),
                write_flags,
            )
        };

        if err < 0 {
            Err(Error::Errno(std::io::Error::from_raw_os_error(
                -err as std::os::raw::c_int,
            )))
        } else {
            Ok(())
        }
    }

    pub fn read(&self, flags: &[cpc_endpoint_read_flags_t_enum]) -> Result<Vec<u8>, Error> {
        let mut read_flags = 0;
        for flag in flags {
            read_flags |= *flag as libcpc_sys::cpc_endpoint_read_flags_t;
        }

        let mut buffer = cpc_buffer();

        let bytes_read = unsafe {
            libcpc_sys::cpc_read_endpoint(
                self.endpoint,
                buffer.as_mut_ptr() as *mut std::ffi::c_void,
                buffer.len(),
                read_flags,
            )
        };

        if bytes_read < 0 {
            Err(Error::Errno(std::io::Error::from_raw_os_error(
                -bytes_read as std::os::raw::c_int,
            )))
        } else {
            Ok((&buffer[..bytes_read as usize]).to_vec())
        }
    }

    pub fn set_option(
        &self,
        option: libcpc_sys::cpc_option_t_enum,
        optval: *const std::os::raw::c_void,
        optlen: usize,
    ) -> Result<(), Error> {
        let err = unsafe {
            libcpc_sys::cpc_set_endpoint_option(
                self.endpoint,
                option as libcpc_sys::cpc_option_t,
                optval,
                optlen,
            )
        };

        if err < 0 {
            Err(Error::Errno(std::io::Error::from_raw_os_error(-err)))
        } else {
            Ok(())
        }
    }

    pub fn get_option(
        &self,
        option: libcpc_sys::cpc_option_t_enum,
        optval: *mut std::os::raw::c_void,
        optlen: *mut usize,
    ) -> Result<(), Error> {
        let err = unsafe {
            libcpc_sys::cpc_get_endpoint_option(
                self.endpoint,
                option as libcpc_sys::cpc_option_t,
                optval,
                optlen,
            )
        };

        if err < 0 {
            Err(Error::Errno(std::io::Error::from_raw_os_error(-err)))
        } else {
            Ok(())
        }
    }

    pub fn set_read_timeout(&self, timeval: libcpc_sys::cpc_timeval_t) -> Result<(), Error> {
        let err = unsafe { libcpc_sys::cpc_set_endpoint_read_timeout(self.endpoint, timeval) };

        if err < 0 {
            Err(Error::Errno(std::io::Error::from_raw_os_error(-err)))
        } else {
            Ok(())
        }
    }

    pub fn get_read_timeout(&self) -> Result<libcpc_sys::cpc_timeval_t, Error> {
        let mut timeval = libcpc_sys::cpc_timeval_t {
            seconds: 0,
            microseconds: 0,
        };

        let err = unsafe {
            libcpc_sys::cpc_get_endpoint_read_timeout(
                self.endpoint,
                &mut timeval as *mut libcpc_sys::cpc_timeval_t,
            )
        };

        if err < 0 {
            Err(Error::Errno(std::io::Error::from_raw_os_error(-err)))
        } else {
            Ok(timeval)
        }
    }

    pub fn set_write_timeout(&self, timeval: libcpc_sys::cpc_timeval_t) -> Result<(), Error> {
        let err = unsafe { libcpc_sys::cpc_set_endpoint_write_timeout(self.endpoint, timeval) };

        if err < 0 {
            Err(Error::Errno(std::io::Error::from_raw_os_error(-err)))
        } else {
            Ok(())
        }
    }

    pub fn get_write_timeout(&self) -> Result<libcpc_sys::cpc_timeval_t, Error> {
        let mut timeval = libcpc_sys::cpc_timeval_t {
            seconds: 0,
            microseconds: 0,
        };

        let err = unsafe {
            libcpc_sys::cpc_get_endpoint_write_timeout(
                self.endpoint,
                &mut timeval as *mut libcpc_sys::cpc_timeval_t,
            )
        };

        if err < 0 {
            Err(Error::Errno(std::io::Error::from_raw_os_error(-err)))
        } else {
            Ok(timeval)
        }
    }

    pub fn set_blocking(&self, blocking: bool) -> Result<(), Error> {
        let err = unsafe { libcpc_sys::cpc_set_endpoint_blocking(self.endpoint, blocking) };

        if err < 0 {
            Err(Error::Errno(std::io::Error::from_raw_os_error(-err)))
        } else {
            Ok(())
        }
    }

    pub fn get_blocking_mode(&self) -> Result<bool, Error> {
        let mut is_blocking = false;

        let err = unsafe {
            libcpc_sys::cpc_get_endpoint_blocking_mode(self.endpoint, &mut is_blocking as *mut bool)
        };

        if err < 0 {
            Err(Error::Errno(std::io::Error::from_raw_os_error(-err)))
        } else {
            Ok(is_blocking)
        }
    }

    pub fn set_socket_size(&self, socket_size: u32) -> Result<(), Error> {
        let err = unsafe { libcpc_sys::cpc_set_endpoint_socket_size(self.endpoint, socket_size) };

        if err < 0 {
            Err(Error::Errno(std::io::Error::from_raw_os_error(-err)))
        } else {
            Ok(())
        }
    }

    pub fn get_socket_size(&self) -> Result<u32, Error> {
        let mut socket_size = 0;

        let err = unsafe {
            libcpc_sys::cpc_get_endpoint_socket_size(self.endpoint, &mut socket_size as *mut u32)
        };

        if err < 0 {
            Err(Error::Errno(std::io::Error::from_raw_os_error(-err)))
        } else {
            Ok(socket_size)
        }
    }

    pub fn get_max_write_size(&self) -> Result<usize, Error> {
        let mut max_write_size: usize = 0;

        let err = unsafe {
            libcpc_sys::cpc_get_endpoint_max_write_size(
                self.endpoint,
                &mut max_write_size as *mut usize,
            )
        };

        if err < 0 {
            Err(Error::Errno(std::io::Error::from_raw_os_error(-err)))
        } else {
            Ok(max_write_size)
        }
    }

    pub fn get_encryption_state(&self) -> Result<bool, Error> {
        let mut encrypted = false;

        let err = unsafe {
            libcpc_sys::cpc_get_endpoint_encryption_state(
                self.endpoint,
                &mut encrypted as *mut bool,
            )
        };

        if err < 0 {
            Err(Error::Errno(std::io::Error::from_raw_os_error(-err)))
        } else {
            Ok(encrypted)
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub struct cpc_endpoint_event {
    event: libcpc_sys::cpc_endpoint_event_handle_t,
    pub fd: std::os::unix::io::RawFd,
}
unsafe impl Send for cpc_endpoint_event {}
impl cpc_endpoint_event {
    pub fn deinit_event(&mut self) -> Result<(), Error> {
        let err = unsafe {
            libcpc_sys::cpc_deinit_endpoint_event(
                &mut self.event as *mut libcpc_sys::cpc_endpoint_event_handle_t,
            )
        };

        if err < 0 {
            Err(Error::Errno(std::io::Error::from_raw_os_error(-err)))
        } else {
            Ok(())
        }
    }

    pub fn read_event(
        &self,
        flags: &[cpc_endpoint_event_flags_t_enum],
    ) -> Result<cpc_event_type_t_enum, Error> {
        let mut events_flags = 0;
        for flag in flags {
            events_flags |= *flag as libcpc_sys::cpc_endpoint_event_flags_t;
        }

        let mut event_type: libcpc_sys::cpc_event_type_t = 0;

        let err = unsafe {
            libcpc_sys::cpc_read_endpoint_event(
                self.event,
                &mut event_type as *mut libcpc_sys::cpc_event_type_t,
                events_flags,
            )
        };

        if err < 0 {
            Err(Error::Errno(std::io::Error::from_raw_os_error(-err)))
        } else {
            Ok(cpc_event_type_t_enum::try_from(event_type as u32)?)
        }
    }

    pub fn get_event_option(
        &self,
        option: libcpc_sys::cpc_endpoint_event_option_t_enum,
        optval: *mut std::os::raw::c_void,
        optlen: *mut usize,
    ) -> Result<(), Error> {
        let err = unsafe {
            libcpc_sys::cpc_get_endpoint_event_option(
                self.event,
                option as libcpc_sys::cpc_endpoint_event_option_t,
                optval,
                optlen,
            )
        };

        if err < 0 {
            Err(Error::Errno(std::io::Error::from_raw_os_error(-err)))
        } else {
            Ok(())
        }
    }

    pub fn set_event_option(
        &self,
        option: libcpc_sys::cpc_endpoint_event_option_t_enum,
        optval: *const std::os::raw::c_void,
        optlen: usize,
    ) -> Result<(), Error> {
        let err = unsafe {
            libcpc_sys::cpc_set_endpoint_event_option(
                self.event,
                option as libcpc_sys::cpc_endpoint_event_option_t,
                optval,
                optlen,
            )
        };

        if err < 0 {
            Err(Error::Errno(std::io::Error::from_raw_os_error(-err)))
        } else {
            Ok(())
        }
    }

    pub fn set_event_read_timeout(&self, timeval: libcpc_sys::cpc_timeval_t) -> Result<(), Error> {
        let err = unsafe { libcpc_sys::cpc_set_endpoint_event_read_timeout(self.event, timeval) };

        if err < 0 {
            Err(Error::Errno(std::io::Error::from_raw_os_error(-err)))
        } else {
            Ok(())
        }
    }

    pub fn get_event_read_timeout(&self) -> Result<libcpc_sys::cpc_timeval_t, Error> {
        let mut timeval = libcpc_sys::cpc_timeval_t {
            seconds: 0,
            microseconds: 0,
        };

        let err = unsafe {
            libcpc_sys::cpc_get_endpoint_event_read_timeout(
                self.event,
                &mut timeval as *mut libcpc_sys::cpc_timeval_t,
            )
        };

        if err < 0 {
            Err(Error::Errno(std::io::Error::from_raw_os_error(-err)))
        } else {
            Ok(timeval)
        }
    }

    pub fn set_event_blocking(&self, blocking: bool) -> Result<(), Error> {
        let err = unsafe { libcpc_sys::cpc_set_endpoint_event_blocking(self.event, blocking) };

        if err < 0 {
            Err(Error::Errno(std::io::Error::from_raw_os_error(-err)))
        } else {
            Ok(())
        }
    }

    pub fn get_event_blocking_mode(&self) -> Result<bool, Error> {
        let mut is_blocking = false;

        let err = unsafe {
            libcpc_sys::cpc_get_endpoint_event_blocking_mode(
                self.event,
                &mut is_blocking as *mut bool,
            )
        };

        if err < 0 {
            Err(Error::Errno(std::io::Error::from_raw_os_error(-err)))
        } else {
            Ok(is_blocking)
        }
    }
}

pub fn cpc_buffer() -> Vec<u8> {
    vec![0; libcpc_sys::SL_CPC_READ_MINIMUM_SIZE as usize]
}

pub fn init(
    instance_name: &str,
    enable_tracing: bool,
    reset_callback: std::option::Option<unsafe extern "C" fn()>,
) -> Result<cpc_handle, Error> {
    let mut cpc = libcpc_sys::cpc_handle_t {
        ptr: 0 as *mut std::os::raw::c_void,
    };

    let err = unsafe {
        libcpc_sys::cpc_init(
            &mut cpc as *mut libcpc_sys::cpc_handle_t,
            std::ffi::CString::new(instance_name)?
                .as_bytes_with_nul()
                .as_ptr() as *const std::os::raw::c_char,
            enable_tracing,
            reset_callback,
        )
    };

    if err != 0 {
        Err(Error::Errno(std::io::Error::from_raw_os_error(-err)))
    } else {
        Ok(cpc_handle { cpc })
    }
}

pub fn get_library_version() -> Option<String> {
    unsafe {
        let ptr = libcpc_sys::cpc_get_library_version();
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
