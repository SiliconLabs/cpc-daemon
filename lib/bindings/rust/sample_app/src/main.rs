fn main() {
    // Arguments to initialize libcpc
    let instance_name = match std::env::var("RUST_LIBCPC_CPCD_INSTANCE") {
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
    let ep_enum = libcpc::sl_cpc::sl_cpc_user_endpoint_id_t_enum::SL_CPC_ENDPOINT_USER_ID_0;
    let ep_id = ep_enum as libcpc::sl_cpc::sl_cpc_user_endpoint_id_t;

    // Open an endpoint
    let mut ep_handle = match libcpc::open_endpoint(&cpc_handle, ep_id, 1) {
        Ok(ep_handle) => {
            println!("open_endpoint({:?})", ep_enum);
            ep_handle
        }
        Err(err) => {
            eprintln!("open_endpoint({:?}) = {}", ep_enum, err);
            panic!();
        }
    };

    // Arguments to write to an endpoint
    let buffer = "TEST\0".as_bytes().to_vec();
    let flags = libcpc::sl_cpc::cpc_endpoint_write_flags_t_enum::CPC_ENDPOINT_WRITE_FLAG_NONE
        as libcpc::sl_cpc::cpc_endpoint_write_flags_t;

    // Write to the endpoint
    match libcpc::write_endpoint(&ep_handle, &buffer, flags) {
        Ok(bytes_written) => println!(
            "write_endpoint({:?}, {:?}) = {}",
            ep_enum, buffer, bytes_written
        ),
        Err(err) => eprintln!("write_endpoint({:?}) = {}", ep_enum, err),
    }

    // Arguments to read from an endpoint
    let flags = libcpc::sl_cpc::cpc_endpoint_read_flags_t_enum::CPC_ENDPOINT_READ_FLAG_NONE
        as libcpc::sl_cpc::cpc_endpoint_read_flags_t;

    // Read from the endpoint
    match libcpc::read_endpoint(&ep_handle, flags) {
        Ok(buffer) => println!("read_endpoint({:?}) = {:?}", ep_enum, buffer),
        Err(err) => eprintln!("read_endpoint({:?}) = {}", ep_enum, err),
    };

    // Close the endpoint
    match libcpc::close_endpoint(&mut ep_handle) {
        Ok(_) => println!("close_endpoint({:?})", ep_enum),
        Err(err) => eprintln!("close_endpoint({:?}) = {}", ep_enum, err),
    }
}
