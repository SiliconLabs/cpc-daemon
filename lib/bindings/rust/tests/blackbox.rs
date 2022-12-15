pub mod common;

#[test]
#[serial_test::serial]
fn test_cpc_lib_version() {
    match libcpc::get_library_version() {
        Ok(version) => assert!(!version.is_empty()),
        Err(err) => assert!(false, "{err}"),
    }
}

#[test]
#[serial_test::serial]
fn test_cpc_secondary_version() {
    let mut cpc_handle = common::cpc_init();

    match libcpc::get_secondary_app_version(&cpc_handle) {
        Ok(version) => assert!(!version.is_empty()),
        Err(err) => assert!(false, "{err}"),
    }

    common::cpc_deinit_internal(&mut cpc_handle);
}

#[test]
#[serial_test::serial]
fn test_cpc_init_deinit() {
    let mut cpc_handle = common::cpc_init();
    common::cpc_deinit_internal(&mut cpc_handle);
}

#[test]
#[serial_test::serial]
fn test_cpc_restart() {
    let mut cpc_handle = common::cpc_init();

    match libcpc::restart(&mut cpc_handle) {
        Ok(_) => (),
        Err(err) => assert!(false, "{err}"),
    }

    common::cpc_deinit_internal(&mut cpc_handle);
}

#[test]
#[serial_test::serial]
fn test_cpc_cmd_endpoint_write_read() {
    let mut cpc_handle = common::cpc_init();
    let cmd_endpoint_id = libcpc::sl_cpc::sl_cpc_user_endpoint_id_t_enum::SL_CPC_ENDPOINT_USER_ID_0
        as libcpc::sl_cpc::sl_cpc_user_endpoint_id_t;
    let (mut cmd_endpoint, mut cmd_endpoint_ev) =
        common::cpc_open_endpoint(&cpc_handle, cmd_endpoint_id);

    let test_string = "TEST\0";
    match libcpc::write_endpoint(
        &cmd_endpoint,
        &test_string.as_bytes().to_vec(),
        libcpc::sl_cpc::cpc_endpoint_write_flags_t_enum::CPC_ENDPOINT_WRITE_FLAG_NONE
            as libcpc::sl_cpc::cpc_endpoint_write_flags_t,
    ) {
        Ok(bytes_written) => {
            assert_eq!(test_string.len() as isize, bytes_written)
        }
        Err(err) => assert!(false, "{err}"),
    }

    let ack_string = "ACK\0";
    match libcpc::read_endpoint(
        &cmd_endpoint,
        libcpc::sl_cpc::cpc_endpoint_read_flags_t_enum::CPC_ENDPOINT_READ_FLAG_NONE
            as libcpc::sl_cpc::cpc_endpoint_read_flags_t,
    ) {
        Ok(bytes) => {
            assert_eq!(std::str::from_utf8(&bytes).unwrap(), ack_string)
        }
        Err(err) => assert!(false, "{err}"),
    }

    common::cpc_close_endpoint(
        &cpc_handle,
        &mut cmd_endpoint,
        &mut cmd_endpoint_ev,
        cmd_endpoint_id,
    );
    common::cpc_deinit_internal(&mut cpc_handle);
}

#[test]
#[serial_test::serial]
fn test_cpc_cmd_endpoint_options() {
    let mut cpc_handle = common::cpc_init();
    let cmd_endpoint_id = libcpc::sl_cpc::sl_cpc_user_endpoint_id_t_enum::SL_CPC_ENDPOINT_USER_ID_0
        as libcpc::sl_cpc::sl_cpc_user_endpoint_id_t;
    let (mut cmd_endpoint, mut cmd_endpoint_ev) =
        common::cpc_open_endpoint(&cpc_handle, cmd_endpoint_id);

    let rx_timeout_seconds = 666;

    let option: libcpc::sl_cpc::cpc_option_t_enum =
        libcpc::sl_cpc::cpc_option_t_enum::CPC_OPTION_RX_TIMEOUT;

    let mut optval = libcpc::sl_cpc::cpc_timeval_t {
        seconds: rx_timeout_seconds,
        microseconds: 0,
    };
    let optval_ptr = &mut optval as *mut libcpc::sl_cpc::cpc_timeval_t as *mut std::os::raw::c_void;

    let optlen = std::mem::size_of::<libcpc::sl_cpc::cpc_timeval_t>() as usize;

    match libcpc::set_endpoint_option(&cmd_endpoint, option, optval_ptr, optlen) {
        Ok(_) => (),
        Err(err) => assert!(false, "{err}"),
    }

    let option: libcpc::sl_cpc::cpc_option_t_enum =
        libcpc::sl_cpc::cpc_option_t_enum::CPC_OPTION_RX_TIMEOUT;

    let mut optval = libcpc::sl_cpc::cpc_timeval_t {
        seconds: 0,
        microseconds: 0,
    };
    let optval_ptr = &mut optval as *mut libcpc::sl_cpc::cpc_timeval_t as *mut std::os::raw::c_void;

    let mut optlen = std::mem::size_of::<libcpc::sl_cpc::cpc_timeval_t>() as usize;
    let optlen_ptr = &mut optlen as *mut usize;

    match libcpc::get_endpoint_option(&cmd_endpoint, option, optval_ptr, optlen_ptr) {
        Ok(_) => assert_eq!(rx_timeout_seconds, optval.seconds),
        Err(err) => assert!(false, "{err}"),
    }

    common::cpc_close_endpoint(
        &cpc_handle,
        &mut cmd_endpoint,
        &mut cmd_endpoint_ev,
        cmd_endpoint_id,
    );
    common::cpc_deinit_internal(&mut cpc_handle);
}

#[test]
#[serial_test::serial]
fn test_cpc_cmd_endpoint_read_timeout() {
    let mut cpc_handle = common::cpc_init();
    let cmd_endpoint_id = libcpc::sl_cpc::sl_cpc_user_endpoint_id_t_enum::SL_CPC_ENDPOINT_USER_ID_0
        as libcpc::sl_cpc::sl_cpc_user_endpoint_id_t;
    let (mut cmd_endpoint, mut cmd_endpoint_ev) =
        common::cpc_open_endpoint(&cpc_handle, cmd_endpoint_id);

    let set_timeout = libcpc::sl_cpc::cpc_timeval_t {
        seconds: 333,
        microseconds: 0,
    };

    match libcpc::set_endpoint_read_timeout(&cmd_endpoint, set_timeout) {
        Ok(_) => (),
        Err(err) => assert!(false, "{err}"),
    };

    match libcpc::get_endpoint_read_timeout(&cmd_endpoint) {
        Ok(get_timeout) => assert_eq!(set_timeout.seconds, get_timeout.seconds),
        Err(err) => assert!(false, "{err}"),
    };

    common::cpc_close_endpoint(
        &cpc_handle,
        &mut cmd_endpoint,
        &mut cmd_endpoint_ev,
        cmd_endpoint_id,
    );
    common::cpc_deinit_internal(&mut cpc_handle);
}

#[test]
#[serial_test::serial]
fn test_cpc_cmd_endpoint_write_timeout() {
    let mut cpc_handle = common::cpc_init();
    let cmd_endpoint_id = libcpc::sl_cpc::sl_cpc_user_endpoint_id_t_enum::SL_CPC_ENDPOINT_USER_ID_0
        as libcpc::sl_cpc::sl_cpc_user_endpoint_id_t;
    let (mut cmd_endpoint, mut cmd_endpoint_ev) =
        common::cpc_open_endpoint(&cpc_handle, cmd_endpoint_id);

    let set_timeout = libcpc::sl_cpc::cpc_timeval_t {
        seconds: 999,
        microseconds: 0,
    };

    match libcpc::set_endpoint_write_timeout(&cmd_endpoint, set_timeout) {
        Ok(_) => (),
        Err(err) => assert!(false, "{err}"),
    };

    match libcpc::get_endpoint_write_timeout(&cmd_endpoint) {
        Ok(get_timeout) => assert_eq!(set_timeout.seconds, get_timeout.seconds),
        Err(err) => assert!(false, "{err}"),
    };

    common::cpc_close_endpoint(
        &cpc_handle,
        &mut cmd_endpoint,
        &mut cmd_endpoint_ev,
        cmd_endpoint_id,
    );
    common::cpc_deinit_internal(&mut cpc_handle);
}

#[test]
#[serial_test::serial]
fn test_cpc_cmd_endpoint_blocking() {
    let mut cpc_handle = common::cpc_init();
    let cmd_endpoint_id = libcpc::sl_cpc::sl_cpc_user_endpoint_id_t_enum::SL_CPC_ENDPOINT_USER_ID_0
        as libcpc::sl_cpc::sl_cpc_user_endpoint_id_t;
    let (mut cmd_endpoint, mut cmd_endpoint_ev) =
        common::cpc_open_endpoint(&cpc_handle, cmd_endpoint_id);

    let mut blocking = false;

    match libcpc::set_endpoint_blocking(&cmd_endpoint, blocking) {
        Ok(_) => (),
        Err(err) => assert!(false, "{err}"),
    };

    match libcpc::get_endpoint_blocking_mode(&cmd_endpoint) {
        Ok(is_blocking) => assert_eq!(is_blocking, blocking),
        Err(err) => assert!(false, "{err}"),
    };

    blocking = true;

    match libcpc::set_endpoint_blocking(&cmd_endpoint, blocking) {
        Ok(_) => (),
        Err(err) => assert!(false, "{err}"),
    };

    match libcpc::get_endpoint_blocking_mode(&cmd_endpoint) {
        Ok(is_blocking) => assert_eq!(is_blocking, blocking),
        Err(err) => assert!(false, "{err}"),
    };

    common::cpc_close_endpoint(
        &cpc_handle,
        &mut cmd_endpoint,
        &mut cmd_endpoint_ev,
        cmd_endpoint_id,
    );
    common::cpc_deinit_internal(&mut cpc_handle);
}

#[test]
#[serial_test::serial]
fn test_cpc_cmd_endpoint_socket_size() {
    let mut cpc_handle = common::cpc_init();
    let cmd_endpoint_id = libcpc::sl_cpc::sl_cpc_user_endpoint_id_t_enum::SL_CPC_ENDPOINT_USER_ID_0
        as libcpc::sl_cpc::sl_cpc_user_endpoint_id_t;
    let (mut cmd_endpoint, mut cmd_endpoint_ev) =
        common::cpc_open_endpoint(&cpc_handle, cmd_endpoint_id);

    let set_socket_size = 6666;

    match libcpc::set_endpoint_socket_size(&cmd_endpoint, set_socket_size) {
        Ok(_) => (),
        Err(err) => assert!(false, "{err}"),
    };

    match libcpc::get_endpoint_socket_size(&cmd_endpoint) {
        Ok(get_socket_size) => more_asserts::assert_ge!(get_socket_size, set_socket_size),
        Err(err) => assert!(false, "{err}"),
    };

    common::cpc_close_endpoint(
        &cpc_handle,
        &mut cmd_endpoint,
        &mut cmd_endpoint_ev,
        cmd_endpoint_id,
    );
    common::cpc_deinit_internal(&mut cpc_handle);
}

#[test]
#[serial_test::serial]
fn test_cpc_cmd_endpoint_max_write_size() {
    let mut cpc_handle = common::cpc_init();
    let cmd_endpoint_id = libcpc::sl_cpc::sl_cpc_user_endpoint_id_t_enum::SL_CPC_ENDPOINT_USER_ID_0
        as libcpc::sl_cpc::sl_cpc_user_endpoint_id_t;
    let (mut cmd_endpoint, mut cmd_endpoint_ev) =
        common::cpc_open_endpoint(&cpc_handle, cmd_endpoint_id);

    match libcpc::get_endpoint_max_write_size(&cmd_endpoint) {
        Ok(_) => (),
        Err(err) => assert!(false, "{err}"),
    };

    common::cpc_close_endpoint(
        &cpc_handle,
        &mut cmd_endpoint,
        &mut cmd_endpoint_ev,
        cmd_endpoint_id,
    );
    common::cpc_deinit_internal(&mut cpc_handle);
}

#[test]
#[serial_test::serial]
fn test_cpc_cmd_endpoint_encryption_state() {
    let mut cpc_handle = common::cpc_init();
    let cmd_endpoint_id = libcpc::sl_cpc::sl_cpc_user_endpoint_id_t_enum::SL_CPC_ENDPOINT_USER_ID_0
        as libcpc::sl_cpc::sl_cpc_user_endpoint_id_t;
    let (mut cmd_endpoint, mut cmd_endpoint_ev) =
        common::cpc_open_endpoint(&cpc_handle, cmd_endpoint_id);

    match libcpc::get_endpoint_encryption_state(&cmd_endpoint) {
        Ok(_) => (),
        Err(err) => assert!(false, "{err}"),
    };

    common::cpc_close_endpoint(
        &cpc_handle,
        &mut cmd_endpoint,
        &mut cmd_endpoint_ev,
        cmd_endpoint_id,
    );
    common::cpc_deinit_internal(&mut cpc_handle);
}

#[test]
#[serial_test::serial]
fn test_cpc_cmd_endpoint_event_options() {
    let mut cpc_handle = common::cpc_init();
    let cmd_endpoint_id = libcpc::sl_cpc::sl_cpc_user_endpoint_id_t_enum::SL_CPC_ENDPOINT_USER_ID_0
        as libcpc::sl_cpc::sl_cpc_user_endpoint_id_t;
    let (mut cmd_endpoint, mut cmd_endpoint_ev) =
        common::cpc_open_endpoint(&cpc_handle, cmd_endpoint_id);

    let read_timeout_seconds = 666;

    let option: libcpc::sl_cpc::cpc_endpoint_event_option_t_enum =
        libcpc::sl_cpc::cpc_endpoint_event_option_t_enum::CPC_ENDPOINT_EVENT_OPTION_READ_TIMEOUT;

    let mut optval = libcpc::sl_cpc::cpc_timeval_t {
        seconds: read_timeout_seconds,
        microseconds: 0,
    };
    let optval_ptr = &mut optval as *mut libcpc::sl_cpc::cpc_timeval_t as *mut std::os::raw::c_void;

    let optlen = std::mem::size_of::<libcpc::sl_cpc::cpc_timeval_t>() as usize;

    match libcpc::set_endpoint_event_option(&cmd_endpoint_ev, option, optval_ptr, optlen) {
        Ok(_) => (),
        Err(err) => assert!(false, "{err}"),
    }

    let option: libcpc::sl_cpc::cpc_endpoint_event_option_t_enum =
        libcpc::sl_cpc::cpc_endpoint_event_option_t_enum::CPC_ENDPOINT_EVENT_OPTION_READ_TIMEOUT;

    let mut optval = libcpc::sl_cpc::cpc_timeval_t {
        seconds: 0,
        microseconds: 0,
    };
    let optval_ptr = &mut optval as *mut libcpc::sl_cpc::cpc_timeval_t as *mut std::os::raw::c_void;

    let mut optlen = std::mem::size_of::<libcpc::sl_cpc::cpc_timeval_t>() as usize;
    let optlen_ptr = &mut optlen as *mut usize;

    match libcpc::get_endpoint_event_option(&cmd_endpoint_ev, option, optval_ptr, optlen_ptr) {
        Ok(_) => assert_eq!(read_timeout_seconds, optval.seconds),
        Err(err) => assert!(false, "{err}"),
    }

    common::cpc_close_endpoint(
        &cpc_handle,
        &mut cmd_endpoint,
        &mut cmd_endpoint_ev,
        cmd_endpoint_id,
    );
    common::cpc_deinit_internal(&mut cpc_handle);
}

#[test]
#[serial_test::serial]
fn test_cpc_cmd_endpoint_event_read_timeout() {
    let mut cpc_handle = common::cpc_init();
    let cmd_endpoint_id = libcpc::sl_cpc::sl_cpc_user_endpoint_id_t_enum::SL_CPC_ENDPOINT_USER_ID_0
        as libcpc::sl_cpc::sl_cpc_user_endpoint_id_t;
    let (mut cmd_endpoint, mut cmd_endpoint_ev) =
        common::cpc_open_endpoint(&cpc_handle, cmd_endpoint_id);

    let set_timeout = libcpc::sl_cpc::cpc_timeval_t {
        seconds: 333,
        microseconds: 0,
    };

    match libcpc::set_endpoint_event_read_timeout(&cmd_endpoint_ev, set_timeout) {
        Ok(_) => (),
        Err(err) => assert!(false, "{err}"),
    };

    match libcpc::get_endpoint_event_read_timeout(&cmd_endpoint_ev) {
        Ok(get_timeout) => assert_eq!(set_timeout.seconds, get_timeout.seconds),
        Err(err) => assert!(false, "{err}"),
    };

    common::cpc_close_endpoint(
        &cpc_handle,
        &mut cmd_endpoint,
        &mut cmd_endpoint_ev,
        cmd_endpoint_id,
    );
    common::cpc_deinit_internal(&mut cpc_handle);
}

#[test]
#[serial_test::serial]
fn test_cpc_cmd_endpoint_event_blocking() {
    let mut cpc_handle = common::cpc_init();
    let cmd_endpoint_id = libcpc::sl_cpc::sl_cpc_user_endpoint_id_t_enum::SL_CPC_ENDPOINT_USER_ID_0
        as libcpc::sl_cpc::sl_cpc_user_endpoint_id_t;
    let (mut cmd_endpoint, mut cmd_endpoint_ev) =
        common::cpc_open_endpoint(&cpc_handle, cmd_endpoint_id);

    let mut blocking = false;

    match libcpc::set_endpoint_event_blocking(&cmd_endpoint_ev, blocking) {
        Ok(_) => (),
        Err(err) => assert!(false, "{err}"),
    };

    match libcpc::get_endpoint_event_blocking_mode(&cmd_endpoint_ev) {
        Ok(is_blocking) => assert_eq!(is_blocking, blocking),
        Err(err) => assert!(false, "{err}"),
    };

    blocking = true;

    match libcpc::set_endpoint_event_blocking(&cmd_endpoint_ev, blocking) {
        Ok(_) => (),
        Err(err) => assert!(false, "{err}"),
    };

    match libcpc::get_endpoint_event_blocking_mode(&cmd_endpoint_ev) {
        Ok(is_blocking) => assert_eq!(is_blocking, blocking),
        Err(err) => assert!(false, "{err}"),
    };

    common::cpc_close_endpoint(
        &cpc_handle,
        &mut cmd_endpoint,
        &mut cmd_endpoint_ev,
        cmd_endpoint_id,
    );
    common::cpc_deinit_internal(&mut cpc_handle);
}
