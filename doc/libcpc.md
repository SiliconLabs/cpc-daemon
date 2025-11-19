# CPC Library

Communication with CPC daemon is done with Unix sockets. To abstract these
sockets and the protocol that they use, the CPC library is provided.


## Setup

First, the library must be initialized with `cpc_init`:

```
  int cpc_init(cpc_handle_t *handle, const char* instance_name, bool enable_tracing, cpc_reset_callback_t reset_callback);
```

On success, it returns 0, else a negative value. Arguments are:
 - `handle`, an opaque structure that will be used in other calls to the library
 - `instance_name`, the name of the daemon instance, in case several instances
    of the CPC daemon exists. It can be NULL, in that case the default "cpcd_0"
    will be used
 - `enable_tracing`, to print debug info on stderr
 - `reset_callback`, a callback that is called when the library is not connected to a daemon anymore.
    Note that the callback will execute in the context of a separate thread.

```
  void on_reset(void)
  {
    printf("Secondary has reset!\n");
  }

  ...

  cpc_handle_t lib_handle;
  int ret;

  ret = cpc_init(&lib_handle, "cpcd_0", false, on_reset);
  // check that ret == 0
```


## Opening and Configuring Endpoints

Opening an endpoint is done with `cpc_open_endpoint`:

```
  int cpc_open_endpoint(cpc_handle_t handle, cpc_endpoint_t *endpoint, uint8_t id, uint8_t tx_window_size);
```

On success, it returns a file descriptor, else a negative value. The file
descriptor can be used for polling (eg. with epoll or select). Arguments are:
 - `handle`, the library handle initialized by `cpc_init`
 - `endpoint`, an opaque structure that represents the opened endpoint
 - `id`, id of the endpoint to open
 - `tx_window_size`, the maximum number of packets that can be sent before
   waiting for an acknowledge from the secondary. Currently, only a value of 1
   is supported.

 ```
   cpc_endpoint_t endpoint_90;
   int fd;

   fd = cpc_open_endpoint(lib_handle, &endpoint_90, 90, 1);
   // check that fd > 0
 ```

There are different functions to then configure the endpoints:

```
  int cpc_set_endpoint_read_timeout(cpc_endpoint_t endpoint, cpc_timeval_t timeval);
  int cpc_set_endpoint_write_timeout(cpc_endpoint_t endpoint, cpc_timeval_t timeval);
  int cpc_set_endpoint_blocking(cpc_endpoint_t endpoint, bool blocking);
  int cpc_set_endpoint_socket_size(cpc_endpoint_t endpoint, uint32_t socket_size);
```


## Reading and Writing

Once an endpoint is opened, one can read and write to it with the following
functions:

```
  ssize_t cpc_read_endpoint(cpc_endpoint_t endpoint, void *buffer, size_t count, cpc_endpoint_read_flags_t flags);
  ssize_t cpc_write_endpoint(cpc_endpoint_t endpoint, const void *buffer, size_t count, cpc_endpoint_write_flags_t flags);
```

They return a negative value in case of error, or the number of bytes
read/written.
When reading, the buffer must be at least `SL_CPC_READ_MINIMUM_SIZE` bytes. This
ensures that any packet received from the secondary can be transfered in full to
the application reading it.
When writing, the maximum buffer size is determined by the secondary and writing
buffers larger than this limit will fail. This value can be queried with
`cpc_get_endpoint_max_write_size`.


## Closing Endpoints

When done with an endpoint, close it with `cpc_close_endpoint`:

```
  int cpc_close_endpoint(cpc_endpoint_t *endpoint);
```

On success, 0 is returned, else a negative value.


## Endpoint Events

When dealing with endpoints, it can be interesting to track endpoints' states,
to know when they are opened, closed, in error, etc. The current state of an
endpoint can be queried with:

```
  int cpc_get_endpoint_state(cpc_handle_t handle, uint8_t id, cpc_endpoint_state_t *state);
```

`cpc_endpoint_state_t` is an enum that represents all endpoint states.

The issue with that function is that is hard to know when it should be called,
ie. when an endpoint's state actually changes. To solve that problem, there is
an event API that allows to monitor endpoints' events.

First, the event monitoring should be initialized for the watched endpoint.

```
  int cpc_init_endpoint_event(cpc_handle_t handle, cpc_endpoint_event_handle_t *event_handle, uint8_t endpoint_id);
```

On success, it returns a file descriptor, else a negative value. As for
`cpc_open_endpoint`, the file descriptor can be used for polling operation.
Arguments are:
 - `handle`, the library handle initialized by `cpc_init`
 - `event_handle`, an opaque structure that represents event socket for this
   endpoint
 - `id`, id of the endpoint to monitor

When an event occurs, it can be read using the following function:

```
  int cpc_read_endpoint_event(cpc_endpoint_event_handle_t event_handle, cpc_event_type_t *event_type, cpc_events_flags_t flags);
```

On success, 0 is returned, else a negative value. Arguments are:
 - `event_handle`, handle returned by `cpc_init_endpoint_event`
 - `event_type`, the event that occurred on the endpoint. Currently,
   `event_type` only has events about endpoints' states, but it might be
   extended to support additional events in the future
 - `flags`, can be set to `CPC_ENDPOINT_EVENT_FLAG_NON_BLOCKING` to make this call non-blocking

Finally, when done monitoring an endpoint, resources can be freed with:

```
  int cpc_deinit_endpoint_event(cpc_endpoint_event_handle_t *event_handle);
```

On success, it returns 0, else a negative value.

As for endpoints, these event handles can be configured to make read operations
blocking or non-blocking, and change the timeout value when reads are blocking.


## Example

```
  void on_reset(void)
  {
    printf("Secondary has reset!\n");
  }

  ...

  uint8_t rx_buffer[SL_CPC_READ_MINIMUM_SIZE];
  cpc_endpoint_t ep;
  cpc_handle_t lib_handle;
  ssize_t nb_bytes;
  fd_set fds;
  int ret;
  int fd;

  // 1. Initialize the library
  ret = cpc_init(&lib_handle, "cpcd_0", false, on_reset);
  // check that ret == 0

  // 2. Open the endpoint we want to use for communication
  fd = cpc_open_endpoint(lib_handle, &ep, 90, 1);
  // check that fd > 0

  // Here, select usage is show cased, but note that by default reading an
  // endpoint is blocking, so the behaviour would be the same if this step was
  // skipped and cpc_read_endpoint called without waiting for select to return
  FD_ZERO(&fds);
  FD_SET(ep, &fds);

  ret = select(fd + 1, &fds, NULL, NULL, NULL);
  // check that ret == 1

  // 3. Read data from the endpoint
  nb_bytes = cpc_read_endpoint(ep, rx_buffer, sizeof(rx_buffer), CPC_ENDPOINT_READ_FLAG_NONE);
  // check that nb_bytes > 0

  // 4. Write data (echo what was just received)
  nb_bytes = cpc_write_endpoint(ep, rx_buffer, nb_bytes, CPC_ENDPOINT_WRITE_FLAG_NONE);
  // check that nb_bytes > 0

  // 5. Close the endpoint
  ret = cpc_close_endpoint(&ep);
  // check that ret == 0
```
