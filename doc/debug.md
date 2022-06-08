# CPCd Debug

## Tracing
Traces are additional logs about the daemon events.

### stdout Tracing
When the `stdout_trace` option is enabled, traces will be shown on the standard output.

### File Tracing
Traces can be saved to a file when the `trace_to_file` option is enabled.
The target folder is specified with the `trace_folder` option.
To minimize performance impact, save files to volatile storage.

### Library Tracing
`cpclib` is traced with a runtime argument to the `cpc_init` function.
Traces are then sent over `stderr` with the associated timestamp.

### Considerations
Tracing will have an impact on overall performance and should only be enabled during development.

## Statistics
Statistics can be printed to the standard output using the `--print-stats <interval>` argument.
Provide the interval, in seconds, as a parameter.

Also, the secondary must have `SL_CPC_DEBUG_CORE_EVENT_COUNTERS` enabled.

## Debugging with GDB
To add debug symbols to the CPCd binary, the `debug` target group must be specified:
```
mkdir build
cmake ../ -DTARGET_GROUP=debug
make
```

If the application needs to be interrupted, use `SIGSTOP` (CTRL+Z).
