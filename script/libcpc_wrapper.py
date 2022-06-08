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

    # ssize_t cpc_read_endpoint(cpc_endpoint_t endpoint, void *buffer, size_t count, cpc_read_flags_t flags)
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

    # ssize_t cpc_write_endpoint(cpc_endpoint_t endpoint, const void *data, size_t data_length, cpc_write_flags_t flags)
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
    def set_option(self, option, optval, optlen):
        opt = c_short(option.value)
        size = c_short(optlen)
        value = c_short(optval)
        ret = self.cpc_handle.lib_cpc.cpc_set_endpoint_option(self, opt, byref(value), size)
        if ret != 0:
            raise Exception("Failed to set option")
    #end def

    # int cpc_get_endpoint_option(cpc_endpoint_t endpoint, cpc_option_t option, void *optval, size_t *optlen);
    def get_option(self, option):
        opt = c_short(option.value)
        size = c_short()
        value = c_short()
        ret = self.cpc_handle.lib_cpc.cpc_get_endpoint_option(self, opt, byref(value), byref(size))
        if ret != 0:
            raise Exception("Failed to get option")

        return value.value, size.value
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
#end class
