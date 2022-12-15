from ctypes import *
from enum import Enum
import signal



class State(Enum):
    SL_CPC_STATE_OPEN = 0
    SL_CPC_STATE_CLOSED = 1
    SL_CPC_STATE_CLOSING = 2
    SL_CPC_STATE_ERROR_DESTINATION_UNREACHABLE = 3
    SL_CPC_STATE_ERROR_SECURITY_INCIDENT = 4
    SL_CPC_STATE_ERROR_FAULT = 5
#end class

class Option(Enum):
    CPC_OPTION_NONE = 0
    CPC_OPTION_BLOCKING = 1
    CPC_OPTION_RX_TIMEOUT = 2
    CPC_OPTION_TX_TIMEOUT = 3
    CPC_OPTION_SOCKET_SIZE = 4
    CPC_OPTION_MAX_WRITE_SIZE = 5
#end class

class EndpointEventOption(Enum):
  CPC_ENDPOINT_EVENT_OPTION_NONE = 0
  CPC_ENDPOINT_EVENT_OPTION_BLOCKING = 1
  CPC_ENDPOINT_EVENT_OPTION_READ_TIMEOUT = 2
#end class

class CPCTimeval(Structure):
    _fields_ = [('seconds', c_int),
                ('microseconds', c_int)]

    def __init__(self, secs):
        """
        Initialize CPCTimeval with the given number of seconds. The argument
        may be a floating point number.
        """
        self.microseconds = int((secs % 1.0) * 1e6)
        self.seconds = int(secs)
#end class

class Endpoint(Structure):

    class Id(Enum):
        SYSTEM          = 0  # System control
        SECURITY        = 1  # Security - related functionality
        BLUETOOTH       = 2  # Bluetooth(BGAPI) endpoint
        RAIL_DOWNSTREAM = 3  # RAIL downstream endpoint
        RAIL_UPSTREAM   = 4  # RAIL upstream endpoint
        ZIGBEE          = 5  # ZigBee EZSP endpoint
        ZWAVE           = 6  # Z-Wave endpoint
        CONNECT         = 7  # Connect endpoint
        GPIO            = 8  # GPIO endpoint for controlling GPIOs on SECONDARYs
        OPENTHREAD      = 9  # Openthread Spinel endpoint
        WISUN           = 10 # WiSun endpoint
        WIFI            = 11 # WiFi endpoint(main control)
        WPAN_15_4       = 12 # 802.15.4 endpoint
        CLI             = 13 # Ascii based CLI for stacks / applications
        BLUETOOTH_RCP   = 14 # Bluetooth RCP endpoint
        ACP             = 15 # ACP endpoint
    #end class

    _fields_ = [("ptr", c_void_p)]

    def __init__(self, cpc_handle):
        self.cpc_handle = cpc_handle

    # int cpc_close_endpoint(cpc_endpoint_t *endpoint)
    def close(self):
        ret = self.cpc_handle.lib_cpc.cpc_close_endpoint(byref(self))
        if ret != 0:
            raise Exception("Failed to close endpoint")
    #end def

    # ssize_t cpc_read_endpoint(cpc_endpoint_t endpoint, void *buffer, size_t count, cpc_endpoint_read_flags_t flags)
    def read(self, nonblock=False):
        count = 4087
        read_buffer = bytearray(count)

        flags = 0
        if nonblock:
            flags = (1 << 0)

        byte_array = bytes(read_buffer)
        byte_count = c_int(count)
        read_flag = c_ubyte(flags)
        ret = self.cpc_handle.lib_cpc.cpc_read_endpoint(self, byte_array, byte_count, read_flag)
        if ret < 0:
            raise Exception("Failed to read endpoint")

        return byte_array[:ret]
    #end def

    # ssize_t cpc_write_endpoint(cpc_endpoint_t endpoint, const void *data, size_t data_length, cpc_endpoint_write_flags_t flags)
    def write(self, data, nonblock=False):
        data_length = len(data)

        flags = 0
        if nonblock:
            flags = (1 << 0)

        byte_array = bytes(data)
        length = c_int(data_length)
        write_flag = c_ubyte(flags)
        ret = self.cpc_handle.lib_cpc.cpc_write_endpoint(self, byte_array, length, write_flag)
        if ret != data_length:
            raise Exception("Failed to write to endpoint")

        return ret
    #end def

    # int cpc_set_endpoint_option(cpc_endpoint_t endpoint, cpc_option_t option, const void *optval, size_t optlen);
    def set_option(self, option, optval):
        if option == Option.CPC_OPTION_BLOCKING:
            optval = c_bool(optval)
        elif option == Option.CPC_OPTION_RX_TIMEOUT or option == Option.CPC_OPTION_TX_TIMEOUT:
            if type(optval) is not CPCTimeval:
                raise Exception("Invalid option type {}, expected CPCTimeval".format(type(optval)))
        elif option == Option.CPC_OPTION_SOCKET_SIZE:
            optval = c_int(optval)
        else:
            # best effort, convert it to int and let the library handle the failure
            optval = c_int(optval)

        opt = c_short(option.value)
        size = c_size_t(sizeof(optval))
        ret = self.cpc_handle.lib_cpc.cpc_set_endpoint_option(self, opt, byref(optval), size)
        if ret != 0:
            raise Exception("Failed to set option")
    #end def

    # int cpc_get_endpoint_option(cpc_endpoint_t endpoint, cpc_option_t option, void *optval, size_t *optlen);
    def get_option(self, option):
        if option == Option.CPC_OPTION_BLOCKING:
            optval = c_bool()
        elif option == Option.CPC_OPTION_RX_TIMEOUT or option == Option.CPC_OPTION_TX_TIMEOUT:
            optval = CPCTimeval(0)
        elif option == Option.CPC_OPTION_SOCKET_SIZE:
            optval = c_int()
        elif option == Option.CPC_OPTION_MAX_WRITE_SIZE:
            optval = c_int()
        else:
            # best effort, try to pass an int and see how it goes
            optval = c_int()

        opt = c_short(option.value)
        size = c_size_t(sizeof(optval))
        input_size = size
        ret = self.cpc_handle.lib_cpc.cpc_get_endpoint_option(self, opt, byref(optval), byref(size))
        if ret != 0 or input_size != size:
            raise Exception("Failed to get option")

        if hasattr(optval, "value"):
            return optval.value
        else:
            return optval
    #end def

    # int cpc_get_endpoint_read_timeout(cpc_endpoint_t endpoint, cpc_timeval_t * timeval);
    @property
    def read_timeout(self):
        return self.get_option(Option.CPC_OPTION_RX_TIMEOUT)
    #end def

    # int cpc_set_endpoint_read_timeout(cpc_endpoint_t endpoint, cpc_timeval_t timeval);
    @read_timeout.setter
    def read_timeout(self, timeout):
        self.set_option(Option.CPC_OPTION_RX_TIMEOUT, timeout)
    #end def

    # int cpc_get_endpoint_write_timeout(cpc_endpoint_t endpoint, cpc_timeval_t * timeval);
    @property
    def write_timeout(self):
        return self.get_option(Option.CPC_OPTION_TX_TIMEOUT)
    #end def

    # int cpc_set_endpoint_write_timeout(cpc_endpoint_t endpoint, cpc_timeval_t timeval);
    @write_timeout.setter
    def write_timeout(self, timeout):
        self.set_option(Option.CPC_OPTION_TX_TIMEOUT, timeout)
    #end def

    # int cpc_get_endpoint_blocking_mode(cpc_endpoint_t endpoint, bool * is_blocking);
    @property
    def blocking(self):
        return self.get_option(Option.CPC_OPTION_BLOCKING)
    #end def

    # int cpc_set_endpoint_blocking(cpc_endpoint_t endpoint, bool blocking);
    @blocking.setter
    def blocking(self, blocking):
        return self.set_option(Option.CPC_OPTION_BLOCKING, blocking)
    #end def

    # int cpc_get_endpoint_socket_size(cpc_endpoint_t endpoint, uint32_t* socket_size);
    @property
    def socket_size(self):
        return self.get_option(Option.CPC_OPTION_SOCKET_SIZE)
    #end def

    # int cpc_set_endpoint_socket_size(cpc_endpoint_t endpoint, uint32_t socket_size);
    @socket_size.setter
    def socket_size(self, size):
        return self.set_option(Option.CPC_OPTION_SOCKET_SIZE, size)
    #end def

    # int cpc_get_endpoint_max_write_size(cpc_endpoint_t endpoint, size_t* max_write_size);
    @property
    def max_write_size(self):
        return self.get_option(Option.CPC_OPTION_MAX_WRITE_SIZE)
    #end def

    # int cpc_get_endpoint_encryption_state(cpc_endpoint_t endpoint, bool* is_encrypted);
    @property
    def encrypted(self):
        return self.get_option(Option.CPC_OPTION_ENCRYPTED)
    #end def
#end class

class Event(Enum):
    ENDPOINT_UNKNOWN                        = 0
    ENDPOINT_OPENED                         = 1
    ENDPOINT_CLOSED                         = 2
    ENDPOINT_CLOSING                        = 3
    ENDPOINT_ERROR_DESTINATION_UNREACHABLE  = 4
    ENDPOINT_ERROR_SECURITY_INCIDENT        = 5
    ENDPOINT_ERROR_FAULT                    = 6
#end class


class EndpointEvent(Structure):

    _fields_ = [("ptr", c_void_p)]

    def __init__(self, cpc_handle):
        self.cpc_handle = cpc_handle
    #end def

    # int cpc_deinit_endpoint_event(cpc_endpoint_event_handle_t *event_handle)
    def close(self):
        ret = self.cpc_handle.lib_cpc.cpc_deinit_endpoint_event(byref(self))
        if ret != 0:
            raise Exception("Failed to close endpoint")
    #end def

    # int cpc_read_endpoint_event(cpc_endpoint_event_handle_t event_handle, cpc_event_type_t *event_type, cpc_events_flags_t flags);
    def read(self, nonblock=False):
        flags = 0
        if nonblock:
            flags = (1 << 0)

        ev = c_uint()
        ret = self.cpc_handle.lib_cpc.cpc_read_endpoint_event(self, byref(ev), flags)
        if ret < 0:
            raise Exception("Failed to read endpoint event")

        return Event(ev.value)
    #end def

    # int cpc_set_endpoint_event_option(cpc_endpoint_event_handle_t event_handle, cpc_endpoint_event_option_t option, const void *optval, size_t optlen);
    def set_option(self, option, optval):
        if option == EndpointEventOption.CPC_ENDPOINT_EVENT_OPTION_BLOCKING:
            optval = c_bool(optval)
        elif option == EndpointEventOption.CPC_ENDPOINT_EVENT_OPTION_READ_TIMEOUT:
            if type(optval) is not CPCTimeval:
                raise Exception("Invalid option type {}, expected CPCTimeval".format(type(optval)))
        elif option == Option.CPC_OPTION_SOCKET_SIZE:
            optval = c_int(optval)
        else:
            # best effort, convert it to int and let the library handle the failure
            optval = c_int(optval)

        opt = c_short(option.value)
        size = c_size_t(sizeof(optval))
        ret = self.cpc_handle.lib_cpc.cpc_set_endpoint_event_option(self, opt, byref(optval), size)
        if ret != 0:
            raise Exception("Failed to set option")
    #end def

    # int cpc_get_endpoint_event_option(cpc_endpoint_event_handle_t event_handle, cpc_endpoint_event_option_t option, void *optval, size_t *optlen);
    def get_option(self, option):
        if option == EndpointEventOption.CPC_ENDPOINT_EVENT_OPTION_BLOCKING:
            optval = c_bool()
        elif option == EndpointEventOption.CPC_ENDPOINT_EVENT_OPTION_READ_TIMEOUT:
            optval = CPCTimeval(0)
        else:
            # best effort, try to pass an int and see how it goes
            optval = c_int()

        opt = c_short(option.value)
        size = c_size_t(sizeof(optval))
        input_size = size
        ret = self.cpc_handle.lib_cpc.cpc_get_endpoint_event_option(self, opt, byref(optval), byref(size))
        if ret != 0 or input_size != size:
            raise Exception("Failed to get option")

        if hasattr(optval, "value"):
            return optval.value
        else:
            return optval
    #end def

    @property
    def blocking(self):
        return self.get_option(EndpointEventOption.CPC_ENDPOINT_EVENT_OPTION_BLOCKING)
    #end def

    @blocking.setter
    def blocking(self, blocking):
        self.set_option(EndpointEventOption.CPC_ENDPOINT_EVENT_OPTION_BLOCKING, blocking)
    #end def

    @property
    def read_timeout(self):
        return self.get_option(EndpointEventOption.CPC_ENDPOINT_EVENT_OPTION_READ_TIMEOUT)
    #end def

    @read_timeout.setter
    def read_timeout(self, timeout):
        self.get_option(EndpointEventOption.CPC_ENDPOINT_EVENT_OPTION_READ_TIMEOUT, timeout)
    #end def
#end class


class CPC(Structure):

    _fields_ = [("ptr", c_void_p)]

    # int cpc_init(cpc_handle_t *handle, const char* instance_name, bool enable_tracing, cpc_reset_callback_t reset_callback)
    def __init__(self, shared_lib_path, instance_name=None, enable_tracing=False, reset_callback=None):
        self.lib_cpc = CDLL(shared_lib_path, use_errno=True)

        self.reset_callback = None

        if instance_name == None:
            name = create_string_buffer(bytes("cpcd_0", 'utf8'))
        else:
            name = create_string_buffer(bytes(instance_name, 'utf8'))

        # populate return type to make sure we return correct values for functions
        # that don't return an int
        self.lib_cpc.cpc_read_endpoint.restype = c_ssize_t
        self.lib_cpc.cpc_write_endpoint.restype = c_ssize_t

        trace = c_bool(enable_tracing)
        if reset_callback != None:
            self.reset_callback = reset_callback
            signal.signal(signal.SIGUSR1, self.reset_cb)

        ret = self.lib_cpc.cpc_init(byref(self), name, trace, None)
        if ret != 0:
            raise Exception("Failed to initialize CPC library")
    #end def

    def reset_cb(self, signum, frame):
        self.reset_callback()
    #end def

    # cpc_restart(cpc_handle_t *handle)
    def restart(self):
        ret = self.lib_cpc.cpc_restart(byref(self))
        if ret != 0:
            raise Exception("Failed to restart CPC library")
    #end def

    # int cpc_open_endpoint(cpc_handle_t handle, cpc_endpoint_t *endpoint, uint8_t id, uint8_t tx_window_size)
    def open_endpoint(self, endpoint_id, tx_window_size=1):
        # convert enum value to integer to make it consumable by C API
        if type(endpoint_id) == Endpoint.Id:
            endpoint_id = endpoint_id.value

        endp_id = c_ubyte(endpoint_id)
        windows = c_ubyte(tx_window_size)

        endpoint = Endpoint(self)
        ret = self.lib_cpc.cpc_open_endpoint(self, byref(endpoint), endp_id, windows)
        if ret < 0:
            raise Exception("Failed to open CPC endpoint {}".format(endpoint_id))

        return endpoint
    #end def

    # int cpc_get_endpoint_state(cpc_handle_t handle, uint8_t id, cpc_endpoint_state_t *state);
    def get_endpoint_state(self, endpoint_id):
        endp_id = c_ubyte(endpoint_id)
        endp_state = c_int()

        ret = self.lib_cpc.cpc_get_endpoint_state(self, endp_id, byref(endp_state))
        if ret != 0:
            raise Exception("Failed to get CPC endpoint state")

        return State(endp_state.value)
    #end def

    # int cpc_init_endpoint_event(cpc_handle_t handle, cpc_endpoint_event_handle_t *event_handle, uint8_t endpoint_id)
    def open_endpoint_event(self, endpoint_id):
        # convert enum value to integer to make it consumable by C API
        if type(endpoint_id) == Endpoint.Id:
            endpoint_id = endpoint_id.value

        endp_id = c_ubyte(endpoint_id)

        event = EndpointEvent(self)
        ret = self.lib_cpc.cpc_init_endpoint_event(self, byref(event), endp_id)
        if ret < 0:
            raise Exception("Failed to open CPC endpoint event {}".format(endpoint_id))

        return event
    #end def

    # const char* cpc_get_library_version();
    def get_library_version(self):
        self.lib_cpc.cpc_get_library_version.restype = c_char_p
        return self.lib_cpc.cpc_get_library_version().decode("utf-8")
    #end def

    # const char* cpc_get_secondary_app_version(cpc_handle_t handle);
    def get_secondary_app_version(self):
        self.lib_cpc.cpc_get_secondary_app_version.restype = c_char_p
        return self.lib_cpc.cpc_get_secondary_app_version(self).decode("utf-8")
    #end def
#end class
