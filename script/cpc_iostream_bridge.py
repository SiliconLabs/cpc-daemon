import socket
import threading
import libcpc_wrapper
import sys
import signal
import time
import argparse

verbose = False
reset_flag = False
client = None
endpoint = None
threads = None
stop_flag = False

def client_read(client, endpoint, event):
    global stop_flag
    size = endpoint.get_option(libcpc_wrapper.Option.CPC_OPTION_MAX_WRITE_SIZE)
    verboseprint("Write size: {}".format(size))
    while not stop_flag:
        try:
            buffer = client.recv(size)
            assert len(buffer) != 0
            ret = endpoint.write(buffer)
            assert ret != 0
        except:
            event.set()
            break
        #end try
    #end while
#end def

def client_write(client, endpoint, event):
    global stop_flag
    while not stop_flag:
        try:
            buffer = endpoint.read()
            assert len(buffer) != 0
            verboseprint(' '.join(format(x, '02x') for x in buffer))
            client.sendall(buffer)
        except:
            event.set()
            break
        #end try
    #end while
#end def

def reset_thread(cpc):

    global reset_flag

    while True:

        while not reset_flag:
            time.sleep(0.5)

        verboseprint("Secondary Reset")

        for i in range(0, 10):
            ret = cpc.restart()
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
    parser = argparse.ArgumentParser()
    group = parser.add_argument_group('required arguments')

    group.add_argument("-i", "--instance",
                      dest="instance_name", type=str, required=True,
                      help="CPC instance name")

    group.add_argument("-l", "--library",
                      dest="lib_name", type=str, required=True,
                      help="CPC lib wrapper name + path")

    group.add_argument("-p", "--port",
                      dest="port_number", type=int, required=True,
                      help="Telnet port number")

    parser.add_argument("-v", "--verbose",
                      action="store_true", dest="verbose", default=False,
                      help="Activate verbose print")

    args = parser.parse_args()

    verbose = args.verbose

    signal.signal(signal.SIGINT, program_exit)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((socket.gethostname(), args.port_number))
    server.listen(1)

    verboseprint("Listen OK")

    try:
        cpc = libcpc_wrapper.CPC(args.lib_name, args.instance_name, verbose, reset_callback)
        verboseprint("CPC Init success")
    except:
        verboseprint("CPC Init fail")

    reset_t = threading.Thread(target=reset_thread, args=(cpc,))
    reset_t.start()

    event = threading.Event()

    while True:
        while True:

            client = server.accept()[0]

            verboseprint("Client accept")

            try:
                endpoint = cpc.open_endpoint(libcpc_wrapper.Endpoint.Id.CLI)
                verboseprint("CPC CLI Endpoint success")
                break
            except Exception as e:
                verboseprint("CPC CLI Endpoint fail to open")
                verboseprint(e)
                client.close()
        #end while

        event.clear()

        threads = (threading.Thread(target=client_read, args=(client, endpoint, event)),\
                   threading.Thread(target=client_write, args=(client, endpoint, event)))
        threads[0].start()
        threads[1].start()

        event.wait()

        try:
            endpoint.close()
        except:
            client.close()
            sys.exit(0)
        #end if

        verboseprint("Client close")
        client.close()

        threads[0].join()
        threads[1].join()
    #end while
#end main
