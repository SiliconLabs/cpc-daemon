fn main() {
    // Arguments to initialize libcpc
    let instance_name = match std::env::var("CPCD_INSTANCE") {
        Ok(instance_name) => instance_name,
        Err(_) => "cpcd_0".to_string(),
    };
    let enable_tracing = true;
    unsafe extern "C" fn reset_callback() {
        println!("CPCd reset callback");
    }

    // Initialize libcpc
    let cpc_handle = match libcpc::init(&instance_name, enable_tracing, Some(reset_callback)) {
        Ok(cpc_handle) => {
            println!("init({})", instance_name);
            cpc_handle
        }
        Err(err) => {
            eprintln!("init({}) = {}", instance_name, err);
            panic!();
        }
    };

    // Arguments to open an endpoint
    let ep_id = libcpc::cpc_endpoint_id::User(
        libcpc::sl_cpc_user_endpoint_id_t_enum::SL_CPC_ENDPOINT_USER_ID_0,
    );

    // Open an endpoint
    let mut ep_handle = match cpc_handle.open_endpoint(ep_id, 1) {
        Ok(ep_handle) => {
            println!("open_endpoint({:?})", ep_id);
            ep_handle
        }
        Err(err) => {
            eprintln!("open_endpoint({:?}) = {}", ep_id, err);
            panic!();
        }
    };

    // Arguments to write to an endpoint
    let buffer = "TEST\0".as_bytes().to_vec();
    let write_flags = [libcpc::cpc_endpoint_write_flags_t_enum::CPC_ENDPOINT_WRITE_FLAG_NONE];

    // Write to the endpoint
    match ep_handle.write(&buffer, &write_flags) {
        Ok(_) => println!("write({:?})", ep_id),
        Err(err) => eprintln!("write({:?}) = {}", ep_id, err),
    }

    // Arguments to read from an endpoint
    let read_flags = [libcpc::cpc_endpoint_read_flags_t_enum::CPC_ENDPOINT_READ_FLAG_NONE];

    // Read from the endpoint
    match ep_handle.read(&read_flags) {
        Ok(buffer) => println!("read({:?}) = {:?}", ep_id, buffer),
        Err(err) => eprintln!("read({:?}) = {}", ep_id, err),
    };

    // Close the endpoint
    match ep_handle.close() {
        Ok(_) => println!("close({:?})", ep_id),
        Err(err) => eprintln!("close({:?}) = {}", ep_id, err),
    }
}
