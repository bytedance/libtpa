..  Copyright (c) 2021-2023, ByteDance Ltd. and/or its Affiliates
    Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>

Libtpa Quick Start
==================

Introduction
------------

Libtpa(Transport Protocol Acceleration) is a DPDK based userspace TCP
stack implementation.

Below is a quick guide on how to build libtpa and run the first libtpa
application.

Build Libtpa
------------

Install Mellanox OFED
~~~~~~~~~~~~~~~~~~~~~

Libtpa currently supports Mellanox NIC only. The Mellanox OFED has to
be installed.  It can be downloaded from
`here <https://network.nvidia.com/products/infiniband-drivers/linux/mlnx_ofed/>`_.
Then run below command to install it::

    ./mlnxofedinstall --dpdk --upstream-libs

Install Dependencies
~~~~~~~~~~~~~~~~~~~~

For debian system, you can simply run following command at the
libtpa source dir to install the dependencies:

.. code-block:: text

    ./buildtools/install-dep.deb.sh --with-meson

Build Libtpa
~~~~~~~~~~~~

With all setup, you can build libtpa simply by::

    make
    make install

Run First Libtpa Application
----------------------------

Before running a libtpa application, hugepages need to be allocated first.
Here is a `guide from DPDK <https://doc.dpdk.org/guides/linux_gsg/sys_reqs.html#use-of-hugepages-in-the-linux-environment>`_.

Then it's ready to run your first libtpa application: swing,
a telnet-like tool, to verify everything is set up correctly.

.. code-block:: text

    # tpa run swing 192.168.1.12 22
    :: TPA_CFG='net { name=eth0; mac=fa:16:3e:30:4f:90; ip=192.168.1.10; mask=255.255.255.0; \
                   gw=192.168.1.1; ip6=fe80::f816:3eff:fe30:4f90/64; } dpdk { pci=0000:00:05.0; } '
    :: cmd=swing 192.168.1.12 22
    EAL: Detected CPU lcores: 8
    EAL: Detected NUMA nodes: 1
    EAL: Detected static linkage of DPDK
    EAL: Selected IOVA mode 'PA'
    EAL: Probe PCI driver: mlx5_pci (15b3:1018) device: 0000:00:05.0 (socket -1)
    mlx5_net: Default miss action is not supported.
    :: connecting to 192.168.1.12:22 ... [connected]
    > < SSH-2.0-OpenSSH_9.0

If you see something similar like above, it means you are all set up and
ready to write and run your own libtpa applications.

What's Next
-----------

Libtpa has no POSIX API support so far. You could reference
:ref:`Libtpa Programming Guide <prog_guide>` on how to program with
libtpa's customized APIs.

Meanwhile, you might want to try :ref:`Redis with Libtpa <redis_libtpa>`
to get some clues on where libtpa might be applied.
