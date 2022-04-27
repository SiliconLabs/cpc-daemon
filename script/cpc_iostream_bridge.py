import socket
import threading
import libcpc_wrapper
import sys
import signal
import time
from optparse import OptionParser

verbose = False
reset_flag = False
client = None
endpoint = None
threads = None
stop_flag = False

def client_read(client, cpc, endpoint, event):
    global stop_flag
    ret, size, dummy = cpc.cpc_get_endpoint_option(endpoint, libcpc_wrapper.Option.CPC_OPTION_MAX_WRITE_SIZE, 0, 0)
    verboseprint("Write size: {}".format(size))
    while not stop_flag:
        try:
            buffer = client.recv(size)
            length = len(buffer)
            assert length != 0
            ret = cpc.cpc_write_endpoint(endpoint, buffer, length, 0)
            assert ret != 0
        except:
            event.set()
            break
        #end try
    #end while
#end def

def client_write(client, cpc, endpoint, event):
    global stop_flag
    buffer = bytearray(4087)
    while not stop_flag:
        try:
            length = cpc.cpc_read_endpoint(endpoint, buffer, len(buffer), 0)
            assert length != 0
            verboseprint(' '.join(format(x, '02x') for x in buffer[0:length]))
            client.sendall(buffer[0:length])
        except:
            event.set()
            break
        #end try
    #end while
#end def
            
def reset_thread(cpc, handle):

    global reset_flag

    while True:
        
        while not reset_flag:
            time.sleep(0.5)
            
        verboseprint("Secondary Reset")
            
        for i in range(0, 10):
            ret = cpc.cpc_restart(handle)
            if ret == 0:
                break
            #end if
            time.sleep(0.1)
        #end for
        
        reset_flag = False
    #end while
#end def
            
def reset_callback():
    global reset_flag
    reset_flag = True
#end def
    
def verboseprint(str_):
    if verbose:
        print("BRIDGE: " + str_)
    else:   
        pass
    #end if
#end def
        
def program_exit(signum, frame):
    sys.exit(0)
#end def

if __name__ == '__main__':
    usage = "usage: %prog [options]"
    parser = OptionParser()

    parser.add_option("-n", "--name",
                      dest="instance_name", type='str',
                      help="CPC instance name")
                      
    parser.add_option("-v", "--verbose",
                      action="store_true", dest="verbose", default=False,
                      help="Activate verbose print")

    parser.add_option("-p", "--port",
                      dest="port_number", type='int',
                      help="Telnet port number")
                      
    parser.add_option("-l", "--library",
                      dest="lib_name", type='str',
                      help="CPC lib wrapper name + path")

    (options, args) = parser.parse_args()
    
    verbose = options.verbose
    
    signal.signal(signal.SIGINT, program_exit)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((socket.gethostname(), options.port_number))
    server.listen(1)
    
    verboseprint("Listen OK")

    cpc = libcpc_wrapper.CPC(options.lib_name)
    handle = libcpc_wrapper.cpc_handle_t()
    ret = cpc.cpc_init(handle, options.instance_name, verbose, reset_callback)
    
    if ret != 0:
        verboseprint("CPC Init fail: {}".format(ret))
    else:
        verboseprint("CPC Init success")
    #end if
        
    reset_t = threading.Thread(target=reset_thread, args=(cpc, handle))
    reset_t.start()

    event = threading.Event()
    
    while True:
        while True:
        
            client = server.accept()[0]
            
            verboseprint("Client accept")
            
            endpoint = libcpc_wrapper.cpc_endpoint_t()
            ret = cpc.cpc_open_endpoint(handle, endpoint, libcpc_wrapper.Endpoint.SL_CPC_ENDPOINT_CLI.value, 1)
                
            if ret < 0:
                verboseprint("CPC CLI Endpoint fail to open: {}".format(ret))
                client.close()
            else:
                verboseprint("CPC CLI Endpoint success")
                break
            #end if
        #end while

        event.clear()

        threads = (threading.Thread(target=client_read, args=(client, cpc, endpoint, event)),\
                   threading.Thread(target=client_write, args=(client, cpc, endpoint, event)))
        threads[0].start()
        threads[1].start()

        event.wait()

        ret = cpc.cpc_close_endpoint(endpoint)
        if ret != 0:
            client.close()
            sys.exit(0)
        #end if
            
        verboseprint("Client close")
        client.close()

        threads[0].join()
        threads[1].join()
    #end while
#end main