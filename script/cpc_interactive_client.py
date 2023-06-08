#!/usr/bin/python

import cmd, sys
import libcpc
import time
from optparse import OptionParser

SL_CPC_ENDPOINT_USER_ID_0 = 90
SL_CPC_ENDPOINT_USER_ID_9 = 99

class CPCInteractiveClient(cmd.Cmd):

  intro = """
              Welcome to the CPC Interactive Client
              Please ensure that the CPC daemon is running and has connected
              to the secondary before using this script.
              For a list of commands, type help or ?
          """
  prompt = "> "

  open_endpoints = dict()

  def __init__(self, completekey, instance, lib_name):
    super().__init__(completekey=completekey)
    lib_name = lib_name or "/usr/local/lib/libcpc.so"
    instance = instance or "cpcd_0"
    self.cpc = libcpc.CPC(lib_name, instance, True, None)

  def do_open_endpoint(self, arg):
    'Open endpoint by endpoint id: > open_endpoint 90'
    if int(arg) > SL_CPC_ENDPOINT_USER_ID_9 or int(arg) < SL_CPC_ENDPOINT_USER_ID_0:
      print("Invalid endpoint id")
      return
    # check if endpoint is already open
    if arg in CPCInteractiveClient.open_endpoints:
      print("Endpoint {} is already open".format(arg))
      return
    try:
      CPCInteractiveClient.open_endpoints[arg] = self.cpc.open_endpoint(int(arg), 1)
      print("Opened endpoint {}".format(arg))
    except:
      print("Failed to open endpoint {}".format(arg))

  def do_write(self, arg):
    'Write data on endpoint: > write 90 hello'
    ep, data = arg.split(maxsplit=1)
    if ep not in CPCInteractiveClient.open_endpoints:
      print("Endpoint {} is not open".format(ep))
      return
    buffer = bytes(data, encoding='utf8')
    try:
      CPCInteractiveClient.open_endpoints[ep].write(buffer) == len(buffer)
      print("Wrote '{}' to endpoint {}".format(buffer.decode(), ep))
    except:
      print("Failed to write to endpoint {}".format(ep))

  def do_read(self, arg):
    'Read data from an endpoint: read 90'
    ep = arg
    if ep not in CPCInteractiveClient.open_endpoints:
      print("Endpoint {} is not open".format(ep))
      return
    try:
      # non-blocking read
      rx_buffer = CPCInteractiveClient.open_endpoints[ep].read(True)
      print("Read '{}' from endpoint {}".format(rx_buffer.decode(), ep))
    except:
      print("Failed to read data from endpoint {}".format(ep))

  def do_close_endpoint(self, arg):
    'Close endpoint: > close 90'
    ep = arg
    if ep not in CPCInteractiveClient.open_endpoints:
      print("Endpoint {} is not open".format(ep))
      return
    try:
      CPCInteractiveClient.open_endpoints[ep].close()
    except:
      print("Failed to close endpoint {}".format(ep))
      return

    # wait for endpoint to close
    while True:
      try:
        state = self.cpc.get_endpoint_state(int(ep))

        if state == libcpc.State.SL_CPC_STATE_CLOSED:
          print("Endpoint {} closed".format(ep))
          # delete endpoint from table
          CPCInteractiveClient.open_endpoints.pop(ep, None)
          break
        else:
          print("Waiting for endpoint {} to close".format(ep))
          time.sleep(1)
        print("Closed endpoint {}".format(ep))
      except:
        print("Error getting endpoint {} state".format(ep))

  def do_quit(self, arg):
    'Close all endpoints and quit application: > quit'
    for ep in list(CPCInteractiveClient.open_endpoints.keys()):
      self.do_close_endpoint(ep)
    
    sys.exit()

if __name__ == '__main__':
  usage = "usage: %prog [options]"
  parser = OptionParser()

  parser.add_option("-i", "--instance",
                dest="instance_name", type='str',
                help="CPC instance name, e.g. cpcd_0")

  parser.add_option("-l", "--library",
                dest="lib_name", type='str',
                help="Full path of CPC library, e.g. /usr/local/lib/libcpc.so")

  (options, args) = parser.parse_args()

  CPCInteractiveClient(completekey='tab', instance=options.instance_name, lib_name=options.lib_name).cmdloop()

