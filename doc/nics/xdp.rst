..  Copyright (c) 2023-2024, ByteDance Ltd. and/or its Affiliates
    Author: Wenlong Luo <luowenlong.linl@bytedance.com>

.. _nic_xdp:

AF_XDP
======

With the help of XDP, Libtpa can also coexist with the Linux kernel
networking stack.
This page shows the steps to run Libtpa with DPDK AF_XDP.

Prerequisites
-------------
- A Linux Kernel (version >= v5.10) with the XDP sockets configuration option
  enabled (CONFIG_XDP_SOCKETS=y).
- libbpf(version >= v0.7.0) and libxdp(vesion >= v1.2.2).
- dpdk(version >= v22.11).
- clang/llvm(version >= 10).

.. attention::

    It may cause kernel panic with old kernels (such as 5.4).
    A newer kernel version might help (say, 5.10).

Install Dependencies
--------------------
.. highlight:: sh

Building BPF programs relies on clang and LLVM.
::

    apt install clang llvm

libbpf/libxdp
::

    apt install libbpf-dev libxdp-dev

.. note::

    It's been tested on Debian 12.
    You can also build libbpf and libxdp from source as shown in below
    Appendix section.

Build Libtpa with Xdp
---------------------
::

    ./configure --with-xdp
    make install

.. hint::

    If it reports error like "asm/types.h file not found", you can
    install ``gcc-multilib`` to fix it.

Setup Test Enviroment
---------------------

Libtpa ships with a script to demo the AF_XDP usage with an veth pair.
::

    cd demo/xdp
   ./xdp_setup.sh

After that, two directories are created named by the corresponding
net namespace. Each directory has an auto-generated Libtpa config
file that is ready to run: we don't support ``tpa run`` for xdp yet.

Run Libtpa Applications
-----------------------

**demo1: swing and techo**
::

    cd tpans1
    ip netns exec tpans1 techo

::

    cd tpans2
    ip netns exec tpans2 swing -c 192.168.0.22 5678

**demo2: tperf**
::

    cd tpans1
    ip netns exec tpans1 tperf -s

::

    cd tpans2
    ip netns exec tpans2 tperf -c 192.168.0.22 -t rw

Limitations
-----------
- In the current implementation, we only support one channel for network
  device. So we should set eth channel to one before running Libtpa with
  XDP.
- AF_XDP did not support offload features, like TX/RX checksum, TSO, etc.
- Our XDP program only support driver mode now.

Appendix
--------
Buliding Libxdp and Libbpf From Source
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Libxdp
""""""
::

    git clone https://github.com/xdp-project/xdp-tools.git
    git checkout v1.2.2
    ./configure
    LIBDIR=/usr/local/lib make libxdp_install

Libbpf
""""""
::

    git clone https://github.com/libbpf/libbpf.git
    git checkout v0.7.0
    cd src/
    LIBDIR=/usr/local/lib make install

XDP Libtpa Config File Demo
^^^^^^^^^^^^^^^^^^^^^^^^^^^
::

    net {
        name = $ETH_DEV
        ip = $ip
        gw = $gw
    }

    dpdk {
        extra_args = "--no-pci --vdev net_af_xdp0,iface=$ETH_DEV,start_queue=0,queue_count=1,xdp_prog=/usr/share/tpa/xdp_flow_steering.o"
    }
