from ctypes import *
from enum import Enum
import signal

class cpc_handle_t(Structure):
    _fields_ = [("ptr", c_void_p)]
#end class

class cpc_endpoint_t(Structure):
    _fields_ = [("ptr", c_void_p)]
#end class

class Endpoint(Enum):
    SL_CPC_ENDPOINT_SYSTEM = 0                  #/< System control
    SL_CPC_ENDPOINT_SECURITY = 1                #/< Security - related functionality
    SL_CPC_ENDPOINT_BLUETOOTH = 2               #/< Bluetooth(BGAPI) endpoint
    SL_CPC_SLI_CPC_ENDPOINT_RAIL_DOWNSTREAM = 3 #/< RAIL downstream endpoint
    SL_CPC_SLI_CPC_ENDPOINT_RAIL_UPSTREAM = 4   #/< RAIL upstream endpoint
    SL_CPC_ENDPOINT_ZIGBEE = 5                  #/< ZigBee EZSP endpoint
    SL_CPC_ENDPOINT_ZWAVE = 6                   #/< Z-Wave endpoint
    SL_CPC_ENDPOINT_CONNECT = 7                 #/< Connect endpoint
    SL_CPC_ENDPOINT_GPIO = 8                    #/< GPIO endpoint for controlling GPIOs on SECONDARYs
    SL_CPC_ENDPOINT_OPENTHREAD = 9              #/< Openthread Spinel endpoint
    SL_CPC_ENDPOINT_WISUN = 10                  #/< WiSun endpoint
    SL_CPC_ENDPOINT_WIFI = 11                   #/< WiFi endpoint(main control)
    SL_CPC_ENDPOINT_15_4 = 12                   #/< 802.15.4 endpoint
    SL_CPC_ENDPOINT_CLI = 13                    #/< Ascii based CLI for stacks / applications
    SL_CPC_ENDPOINT_BLUETOOTH_RCP = 14          #/< Bluetooth RCP endpoint
    SL_CPC_ENDPOINT_ACP = 15                    #/< ACP endpoint
#end class

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
    
class CPC:

    reset_callback = None

    def __init__(self, shared_lib_path):
        try:
            self.lib_cpc = CDLL(shared_lib_path)
        except Exception as e:
            print(e)
    #end def
    
    def reset_cb(self, signum, frame):
        self.reset_callback()
    #end def
    
    # int cpc_init(cpc_handle_t *handle, const char* instance_name, bool enable_tracing, cpc_reset_callback_t reset_callback)
    def cpc_init(self, handle, instance_name, enable_tracing, reset_callback):
        if instance_name == None:
            name = create_string_buffer(bytes("cpcd_0", 'utf8'))
        else:
            name = create_string_buffer(bytes(instance_name, 'utf8'))
        #end if
        trace = c_bool(enable_tracing)
        if reset_callback != None:
            self.reset_callback = reset_callback
            signal.signal(signal.SIGUSR1, self.reset_cb)
        #end if
        ret = self.lib_cpc.cpc_init(byref(handle), name, trace, None)
        return ret
    #end def
    
    # int cpc_open_endpoint(cpc_handle_t handle, cpc_endpoint_t *endpoint, uint8_t id, uint8_t tx_window_size)
    def cpc_open_endpoint(self, handle, endpoint, endpoint_id, tx_window_size):
        endp_id = c_ubyte(endpoint_id)
        windows = c_ubyte(tx_window_size)
        ret = self.lib_cpc.cpc_open_endpoint(handle, byref(endpoint), endp_id, windows)
        return ret
    #end def
    
    # int cpc_close_endpoint(cpc_endpoint_t *endpoint)
    def cpc_close_endpoint(self, endpoint):
        ret = self.lib_cpc.cpc_close_endpoint(byref(endpoint))
        return ret
    #end def
    
    # cpc_restart(cpc_handle_t *handle)
    def cpc_restart(self, handle):
        ret = self.lib_cpc.cpc_restart(byref(handle))
        return ret
    #end def
    
    # ssize_t cpc_read_endpoint(cpc_endpoint_t endpoint, void *buffer, size_t count, cpc_read_flags_t flags)
    def cpc_read_endpoint(self, endpoint, buffer, count, flags):
        byte_count = c_int(count)
        read_flag = c_ubyte(flags)
        byte_array = bytes(buffer)
        p = c_char_p(byte_array)
        ret = self.lib_cpc.cpc_read_endpoint(endpoint, p, byte_count, read_flag)
        buffer[0:ret] = p.value[0:ret]
        return ret
    #end def
    
    # ssize_t cpc_write_endpoint(cpc_endpoint_t endpoint, const void *data, size_t data_length, cpc_write_flags_t flags)
    def cpc_write_endpoint(self, endpoint, data, data_length, flags):
        length = c_int(data_length)
        write_flag = c_ubyte(flags)
        byte_array = bytes(data)
        byte_buffer = c_char_p(byte_array)
        p = cast(byte_buffer, c_void_p)
        ret = self.lib_cpc.cpc_write_endpoint(endpoint, p, length, write_flag)
        return ret
    #end def
    
    # int cpc_get_endpoint_state(cpc_handle_t handle, uint8_t id, cpc_endpoint_state_t *state);
    def cpc_get_endpoint_state(self, handle, endpoint_id, state):
        endp_id = c_ubyte(endpoint_id)
        endp_state = c_int(state)
        ret = self.lib_cpc.cpc_get_endpoint_state(handle, endp_id, byref(endp_state))
        return ret, type(state)(endp_state.value)
    #end def
    
    # int cpc_set_endpoint_option(cpc_endpoint_t endpoint, cpc_option_t option, const void *optval, size_t optlen);
    def cpc_set_endpoint_option(self, endpoint, option, optval, optlen):
        opt = c_short(option.value)
        size = c_short(optlen)
        value = c_short(optval)
        ret = self.lib_cpc.cpc_set_endpoint_option(endpoint, opt, byref(value), size)
        return ret
    #end def
    
    # int cpc_get_endpoint_option(cpc_endpoint_t endpoint, cpc_option_t option, void *optval, size_t *optlen);
    def cpc_get_endpoint_option(self, endpoint, option, optval, optlen):
        opt = c_short(option.value)
        size = c_short(optlen)
        value = c_short(optval)
        ret = self.lib_cpc.cpc_get_endpoint_option(endpoint, opt, byref(value), byref(size))
        return ret, type(optval)(value.value), type(optlen)(size.value)
    #end def
    
#end class