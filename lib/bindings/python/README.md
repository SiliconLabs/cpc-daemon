# Libcpc Python Bindings

CPC stands for Co-Processor Communication. It provides a way to share a physical
link between multiple stack protocols. Refer to the [CPC Daemon project](https://github.com/SiliconLabs/cpc-daemon)
for more details.

CPC comes into two parts:
 - a daemon, called cpcd
 - a library, libcpc.so, used to interact with the daemon

This project provides Python bindings for the library, allowing for fast
prototyping and scripting.


# Usage

The basic example below shows how to connect to the daemon, open endpoint 90,
and exchange a message on that endpoint:

```
import libcpc

cpc = libcpc.CPC("/usr/lib/libcpc.so", "cpcd_0", enable_tracing=False, reset_callback=None)

ep = cpc.open_endpoint(90)
ep.write(b'foobar')
reply = ep.read()

ep.close()
```


# Installation

There are two different ways to make the `libcpc` module accessible

## Set PYTHONPATH

When working on the libcpc module, it is convenient to just make it available
for import with PYTHONPATH like so:

    export PYTHONPATH=$PYTHONPATH:<daemon directory>/lib/bindings/python/src/libcpc

## Create a package with pip

These bindings are still in development and they rely on libcpc.so which is not
part of this package. For that reason, bindings are not published in PyPi
repositories. Fortunately, it's quite easy to build the package.

First, make sure you have the dependencies installed:

    python3 -m pip install --upgrade build

Then, in this directory, next to the pyproject.toml, run:

    python3 -m build

You should see the following in the `dist` folder:

    dist/
    ├── libcpc-0.0.1-py3-none-any.whl
    └── libcpc-0.0.1.tar.gz

Finally, install the package by running pip install on the wheel file:

    python3 -m pip install libcpc-0.0.1-py3-none-any.whl

