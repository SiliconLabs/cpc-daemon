pub fn cpc_init() -> libcpc::cpc_handle {
    let instance_name = match std::env::var("RUST_LIBCPC_CPCD_INSTANCE") {
        Ok(instance_name) => instance_name,
        Err(_) => "cpcd_0".to_string(),
    };
    let enable_tracing = true;
    unsafe extern "C" fn reset_callback() {
        println!("CPCd reset callback");
    }

    match libcpc::init(&instance_name, enable_tracing, Some(reset_callback)) {
        Ok(cpc_handle) => cpc_handle,
        Err(err) => {
            assert!(false, "{err}");
            panic!();
        }
    }
}

extern "C" {
    pub fn cpc_deinit(handle: *mut libcpc::sl_cpc::cpc_handle_t) -> ::std::os::raw::c_int;
}

fn _cpc_deinit_internal(cpc: &mut libcpc::cpc_handle) -> Result<(), std::os::raw::c_int> {
    let err = unsafe { cpc_deinit(&mut cpc.cpc as *mut libcpc::sl_cpc::cpc_handle_t) };

    if err != 0 {
        Err(err)
    } else {
        Ok(())
    }
}

pub fn cpc_deinit_internal(cpc_handle: &mut libcpc::cpc_handle) {
    match _cpc_deinit_internal(cpc_handle) {
        Ok(_) => (),
        Err(err) => assert!(false, "{err}"),
    }
}

pub fn cpc_expected_endpoint_state(
    cpc_handle: &libcpc::cpc_handle,
    id: u8,
    expected_state: libcpc::sl_cpc::cpc_endpoint_state_t_enum,
) {
    match libcpc::get_endpoint_state(cpc_handle, id) {
        Ok(state) => assert_eq!(expected_state, state),
        Err(err) => assert!(false, "{err}"),
    }
}

pub fn cpc_not_expected_endpoint_state(
    cpc_handle: &libcpc::cpc_handle,
    id: u8,
    not_expected_state: libcpc::sl_cpc::cpc_endpoint_state_t_enum,
) {
    match libcpc::get_endpoint_state(cpc_handle, id) {
        Ok(state) => assert_ne!(not_expected_state, state),
        Err(err) => assert!(false, "{err}"),
    }
}

pub fn cpc_open_endpoint(
    cpc_handle: &libcpc::cpc_handle,
    id: u8,
) -> (libcpc::cpc_endpoint, libcpc::cpc_endpoint_event) {
    let command_ep_event = match libcpc::init_endpoint_event(cpc_handle, id) {
        Ok(command_ep_event) => command_ep_event,
        Err(err) => {
            assert!(false, "{err}");
            panic!("{err}");
        }
    };

    let now = std::time::Instant::now();

    loop {
        match libcpc::open_endpoint(cpc_handle, id, 1) {
            Ok(command_ep) => {
                cpc_expected_endpoint_state(
                    cpc_handle,
                    id,
                    libcpc::sl_cpc::cpc_endpoint_state_t_enum::SL_CPC_STATE_OPEN,
                );

                return (command_ep, command_ep_event);
            }
            Err(err) => {
                if now.elapsed().as_secs() > 1 {
                    assert!(false, "{err}");
                } else {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
            }
        };
    }
}

pub fn cpc_close_endpoint(
    cpc_handle: &libcpc::cpc_handle,
    endpoint_handle: &mut libcpc::cpc_endpoint,
    endpoint_event_handle: &mut libcpc::cpc_endpoint_event,
    id: u8,
) {
    match libcpc::close_endpoint(endpoint_handle) {
        Ok(_) => (),
        Err(err) => assert!(false, "{err}"),
    };

    cpc_not_expected_endpoint_state(
        cpc_handle,
        id,
        libcpc::sl_cpc::cpc_endpoint_state_t_enum::SL_CPC_STATE_OPEN,
    );

    match libcpc::read_endpoint_event(endpoint_event_handle, 0) {
        Ok(ev) => assert_eq!(
            ev,
            libcpc::sl_cpc::cpc_event_type_t_enum::SL_CPC_EVENT_ENDPOINT_OPENED
        ),
        Err(err) => assert!(false, "{err}"),
    }

    match libcpc::read_endpoint_event(endpoint_event_handle, 0) {
        Ok(ev) => assert_eq!(
            ev,
            libcpc::sl_cpc::cpc_event_type_t_enum::SL_CPC_EVENT_ENDPOINT_CLOSING
        ),
        Err(err) => assert!(false, "{err}"),
    }

    match libcpc::read_endpoint_event(endpoint_event_handle, 0) {
        Ok(ev) => assert_eq!(
            ev,
            libcpc::sl_cpc::cpc_event_type_t_enum::SL_CPC_EVENT_ENDPOINT_CLOSED
        ),
        Err(err) => assert!(false, "{err}"),
    }

    match libcpc::deinit_endpoint_event(endpoint_event_handle) {
        Ok(_) => (),
        Err(err) => assert!(false, "{err}"),
    };
}
