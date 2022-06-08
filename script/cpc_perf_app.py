#!/usr/bin/python
import sys
import fire
import libcpc_wrapper
import threading
import time
import datetime
import os

# CLI Command Status ----------------------------------------------------------
COMMAND_RESPONSE_SUCESS = 0
COMMAND_RESPONSE_IN_PROGRESS = 1
COMMAND_RESPONSE_ERROR = 2
COMMAND_SENT_FAILED = 3
COMMAND_READ_RESPONSE_FAILED = 4

# Tracing Function ------------------------------------------------------------

def Trace(string, verbose_level, error):
  if error == True:
    sys.stderr.write("CPC Perf: " + string + "\n")
  if verbose_level == True:
    print("CPC Perf: " + string)
  else:
    pass

# CPC_Context Class -----------------------------------------------------------

class CPC_Context():
  """ CPC Class to store CPC context objects"""
  def __init__(self, cpc_instance, lib_path, verbose):
    self.verbose = verbose
    # Initialize CPC lib, it will raise an exception in case of failure
    self.cpc = libcpc_wrapper.CPC(lib_path, cpc_instance, self.verbose, self.on_reset)

  def on_reset(self):
    # TODO validate
    Trace("CPC Daemon restarted. CPC Lib must be restarted as well", True, True)
    self.cpc.restart()

  def open_endpoint(self, endpoint_id):
    return self.cpc.open_endpoint(endpoint_id)

  def close_endpoint(self, endpoint):
    endpoint.close()

  def write_endpoint(self, endpoint, data):
    endpoint.write(data)

  def read_endpoint(self, endpoint):
    try:
      data = endpoint.read()
      return data, len(data)
    except:
      return -1, -1

  def get_endpoint_option(self, endpoint, option):
    value, _ = endpoint.get_option(option)
    return value

  def set_endpoint_option(self, endpoint, option, value, size):
    endpoint.set_option(value, size)

# CLI Class -------------------------------------------------------------------

class CLI():
  """
  CLI Class to interact with the CPC CLI Endpoint.
  The structure of the command response is specific to the Perfomance Test.
  """
  def __init__(self, cpc_context, verbose):
    self.verbose = verbose
    self.cpc_context = cpc_context
    # Open CLI endpoint
    self.cli_endpoint = self.cpc_context.open_endpoint(libcpc_wrapper.Endpoint.Id.CLI)

  def send_command(self, command):
    # Send command over CLI endpoint
    command_buffer = bytes(command, encoding='utf8')
    try:
      self.cpc_context.write_endpoint(self.cli_endpoint, command_buffer)
    except:
      Trace("CLI command send failed", True, True)
      return COMMAND_SENT_FAILED, 0

    # Receive command response
    data = ""
    while True:
      data_part, length = self.cpc_context.read_endpoint(self.cli_endpoint)
      if length == -1:
        Trace("CLI command response reception failed", True, True)
        return COMMAND_READ_RESPONSE_FAILED, 0
      data_part = data_part.decode('utf8', 'strict')
      result = data_part.find(">")
      data += data_part
      if result != -1:
        break
    result = data.find("Success")
    if result == -1:
      result = data.find("In Progress")
      if result == -1:
        Trace("CLI command failed:\n" + data, True, True)
        return COMMAND_RESPONSE_ERROR, 0
      else:
        Trace("CLI command in progress", self.verbose, False)
        return COMMAND_RESPONSE_IN_PROGRESS, 0
    else:
      Trace("CLI command succeeded", self.verbose, False)
    return COMMAND_RESPONSE_SUCESS, data

# Worker Class ----------------------------------------------------------------

class Worker():
  """
  Worker Class
  Each worker has a temporary endpoint associted to it.
  Each worker has its own thread.
  """
  def __init__(self, cpc_context, type, endpoint_id, data_size, start_event, timer_elapsed_event, verbose):
    self.verbose = verbose
    self.cpc_context = cpc_context
    self.type = type
    self.data_size = data_size
    self.bytes_count = 0
    self.start_time = None
    self.stop_time = None
    self.error_state = False
    self.endpoint_id = endpoint_id
    self.endpoint = self.cpc_context.open_endpoint(int(self.endpoint_id))
    self.thread = threading.Thread(target=self.task, args=(start_event, timer_elapsed_event))
    self.thread.daemon = True
    self.thread.start()

  def task(self, start_event, timer_elapsed_event):
    timer_elapsed = False

    # Wait for signal before starting worker process
    start_event.wait()
    self.start_time = datetime.datetime.now()

    # Enter while loop for rx/tx operations until test timer elapsed
    if self.type == "read":
      # TODO set endpoint rx timeout: Not working since we need to pass a timeval struct
      #timeout = libcpc_wrapper.timeval()
      #timeout.tv_sec = 1
      #timeout.tv_usec = 0
      #ret = self.cpc_context.set_endpoint_option(self.endpoint_handle, libcpc_wrapper.Option.CPC_OPTION_RX_TIMEOUT, timeout)
      #if ret == -1:
      #  Trace("Set endpoint rx timeout failed", True, True)
      #  return
      while True:
        if timer_elapsed_event.is_set():
          self.stop_time = datetime.datetime.now()
          self.close()
          return
        data, length = self.cpc_context.read_endpoint(self.endpoint)
        if length == -1:
          Trace("Data reception failed", True, True)
          self.error()
          return
        self.bytes_count += length

    if self.type == "write":
      buffer = bytearray(self.data_size)
      # TODO set endpoint tx timeout: Not working since we need to pass a timeval struct
      # TODO validate payload size is compatible with secondary
      #self.cpc_context.get_endpoint_option(self.endpoint_handle, libcpc_wrapper.Option.CPC_OPTION_MAX_WRITE_SIZE, 0, 0)
      while True:
        if timer_elapsed_event.is_set():
          self.stop_time = datetime.datetime.now()
          self.close()
          return
        try:
          self.cpc_context.write_endpoint(self.endpoint, buffer)
          self.bytes_count += self.data_size
        except:
          Trace("Data send failed", True, True)
          self.error()
          return

  def wait(self):
    self.thread.join()

  def get_report(self):
    # TODO retrieve error state
    delta_date = self.stop_time - self.start_time
    delta = delta_date.total_seconds()
    return delta, self.bytes_count

  def error(self):
    self.stop_time = datetime.datetime.now()
    self.error_state = True
    self.close()

  def close(self):
    try:
      self.cpc_context.close_endpoint(self.endpoint)
    except:
      Trace("CPC Worker Endpoint fail to close", True, True)

# Test Class ------------------------------------------------------------------

class Test:
  """
  Test Class
  A test send/receive data on a given number of temporary endpoints for a given
  number of seconds.
  """
  def on_timeout(self):
    self.timer_elapsed_event.set()

  def __init__(self, cpc_instance, lib_path, test_type, number_of_endpoints, data_size, duration_sec, verbose):
    self.cpc_context = CPC_Context(cpc_instance, lib_path,verbose)
    self.cli = CLI(self.cpc_context, verbose)
    self.type = test_type
    self.number_of_endpoints = number_of_endpoints
    self.data_size = data_size
    self.duration = duration_sec
    self.workers = []
    self.start_event = threading.Event()
    self.timer_elapsed_event = threading.Event()
    self.timer = threading.Timer(self.duration, self.on_timeout)
    self.verbose = verbose
    self.report = ""

  def create_secondary_test(self):
    # Send Command to create test
    if self.type == "read":
      arg_type = "1"
    elif self.type == "write":
      arg_type = "0"
    command_buffer = "cpc_perf create_test " +  str(self.data_size) + " " + str(self.duration) + " " + arg_type
    Trace("Send command: " + command_buffer, self.verbose, False)
    status, data = self.cli.send_command(command_buffer + "\n")
    if status != COMMAND_RESPONSE_SUCESS:
      return -1
    # Parse command answer for data
    test_id, result, prompt = data.split('\n')
    test_id_index = test_id.find("=")
    test_id = test_id[(test_id_index+1):]
    test_id = test_id.strip()
    return test_id

  def create_secondary_worker(self):
    # Send command over CLI endpoint to create worker
    command_buffer = "cpc_perf create_worker " + self.id
    Trace("Send command: " + command_buffer, self.verbose, False)
    status, data = self.cli.send_command(command_buffer + "\n")
    if status != COMMAND_RESPONSE_SUCESS:
      return -1
    # Parse command answer for data
    endpoint_id, status, prompt = data.split('\n')
    endpoint_id_index = endpoint_id.find("=")
    endpoint_id = endpoint_id[(endpoint_id_index+1):]
    endpoint_id = endpoint_id.strip()
    return endpoint_id

  def get_worker_report(self, worker, test_id, endpoint_id):
    # Get Host worker info
    host_time, host_bytes_count = worker.get_report()

    # Send command over CLI endpoint to get the secondary worker report
    command_buffer = "cpc_perf get_worker_report " + str(test_id) + " " + str(endpoint_id)
    Trace("Send command: " + command_buffer, self.verbose, False)
    status, data = self.cli.send_command(command_buffer + "\n")
    if status != COMMAND_RESPONSE_SUCESS:
      return -1 , -1, -1, -1, -1
    time_ms, bytes_count, status, prompt = data.split('\n')
    time_ms_index = time_ms.find("=")
    time_ms = time_ms[(time_ms_index+1):]
    time_ms = time_ms.strip()
    bytes_count_index = bytes_count.find("=")
    bytes_count = bytes_count[(bytes_count_index+1):]
    bytes_count = bytes_count.strip()
    sec_bytes_count = int(bytes_count)

    # If the secondary report that the worker is in a error state
    if time_ms == 0:
      return 0, 0, 0, 0, 0

    # Get the maximum time for throughput calculation
    sec_time = int(time_ms)/1000
    time_calc = max(host_time, sec_time)

    # Calculate throughput
    host_throughput = round(host_bytes_count*8/time_calc)
    sec_throughput = round(sec_bytes_count*8/time_calc)

    return time_calc, host_bytes_count, host_throughput, sec_bytes_count, sec_throughput

  def run_test(self):
    # Send Command to create test
    test_id = self.create_secondary_test()
    if test_id == -1:
      raise SystemExit()
    self.id = test_id

    # Create temporay endpoint(s) and their respective thread
    for index in range (self.number_of_endpoints):
      endpoint_id = self.create_secondary_worker()
      if endpoint_id == -1:
        raise SystemExit()
      worker = Worker(self.cpc_context, self.type, endpoint_id, self.data_size, self.start_event, self.timer_elapsed_event, self.verbose)
      self.workers.append(worker)

    # Send to command to start the test
    command_buffer = "cpc_perf start_test " +  self.id
    Trace("Send command: " + command_buffer, self.verbose, False)
    status, data = self.cli.send_command(command_buffer + "\n")
    if status != COMMAND_RESPONSE_SUCESS:
      raise SystemExit()

    # Signal workers to start the test
    self.timer.start()
    self.start_event.set()

    # Wait for all workers to finish
    for worker in self.workers:
      worker.wait()

    # Send command to stop the test
    # and re-send until secondary has complete its test as well
    command_buffer = "cpc_perf stop_test " +  self.id
    while True:
      Trace("Send command: " + command_buffer, self.verbose, False)
      status, data = self.cli.send_command(command_buffer + "\n")
      if status == COMMAND_RESPONSE_SUCESS:
        break
      elif status == COMMAND_RESPONSE_IN_PROGRESS:
        time.sleep(1)
        continue
      else:
        raise SystemExit()

    # Retrieve results for each worker and build report
    tot_host_throughput = 0
    tot_sec_throughput = 0
    if self.type == "read":
      host_report_str = " bytes received, rx throughput = "
      sec_report_str = " bytes transmitted, tx throughput = "
      tot_host_report_str = "rx"
      tot_sec_report_str = "tx"
    elif self.type == "write":
      host_report_str = " bytes transmitted, tx throughput = "
      sec_report_str = " bytes received, rx throughput = "
      tot_host_report_str = "tx"
      tot_sec_report_str = "rx"
    for worker in self.workers:
      time_calc, host_bytes_count, host_throughput, sec_bytes_count, sec_throughput = self.get_worker_report(worker, self.id, worker.endpoint_id)
      if time_calc == -1:
        raise SystemExit()
      if time_calc > 0:
        self.report += "Worker " + str(worker.endpoint_id) + " time: " + str(time_calc) + " seconds\n"
        self.report += "Host Worker " + str(worker.endpoint_id) + ": " + str(host_bytes_count) + host_report_str + str(host_throughput) + " bps\n"
        self.report += "Secondary Worker " + str(worker.endpoint_id) + ": " + str(sec_bytes_count) + sec_report_str + str(sec_throughput) + " bps\n"
      else:
        self.report += "Secondary Worker " + str(worker.endpoint_id) + " in error state\n"
      tot_host_throughput += host_throughput
      tot_sec_throughput += sec_throughput

    # Delete Test on Secondary
    command_buffer = "cpc_perf delete_test " +  str(self.id)
    Trace("Send command: " + command_buffer, self.verbose, False)
    status, data = self.cli.send_command(command_buffer + "\n")
    if status != COMMAND_RESPONSE_SUCESS:
      raise SystemExit()

    # Print report
    self.report += "Total Host " + tot_host_report_str + " throughput = " + str(tot_host_throughput) + " bps\n"
    self.report += "Total Secondary " + tot_sec_report_str + " throughput = " + str(tot_sec_throughput) + " bps\n"
    print("\n" + self.report)


# Perf Class ------------------------------------------------------------------

class Perf:
  """
  Run CPC performance test in read/write on a configurable number of CPC endpoints.
  """
  def read(self, cpc_instance = "cpcd_0", lib_path = "build/libcpc.so", number_of_endpoints: int = 1, data_size: int = 768, time_sec: int = 10, verbose = False):
    """
    :param number_of_endpoints: number of temporary endpoints to test on
    :param data_size: size of the payload data to use
    :param time_sec: duration in seconds of the test
    """
    test = Test(cpc_instance, lib_path, "read", number_of_endpoints, data_size, time_sec, verbose)
    test.run_test()
    return 'Test completed'

  def write(self, cpc_instance = "cpcd_0", lib_path = "build/libcpc.so", number_of_endpoints: int = 1, data_size: int = 768, time_sec: int = 10, verbose = False):
    """
    :param number_of_endpoints: number of temporary endpoints to test on
    :param data_size: size of the payload data to use
    :param time_sec: duration in seconds of the test
    """
    test = Test(cpc_instance, lib_path, "write", number_of_endpoints, data_size, time_sec, verbose)
    test.run_test()
    return 'Test completed'

# Entry Point -----------------------------------------------------------------

if __name__ == '__main__':
  fire.Fire(Perf)
