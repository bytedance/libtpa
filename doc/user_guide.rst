..  SPDX-License-Identifier: BSD-3-Clause
    Copyright (c) 2021-2023, ByteDance Ltd. and/or its Affiliates
    Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>

Libtpa User Guide
=================

Introduction
------------

Libtpa(Transport Protocol Acceleration) is a DPDK based userspace TCP
stack implementation.

Libtpa is fast. It boosts the :ref:`redis benchmark <redis_libtpa>`
performance more than 5 times, from 0.21m rps to 1.14m rps. Meanwhile, the
p99 latency is greatly decreased, from 0.815ms to 0.159ms.

Libtpa is also sort of stable, all kudos to the comprehensive testing.
Libtpa has more than 200 tests. Together with the :ref:`testing arguments
matrix <matrix_shell>`, it can result in a big variety of test cases.
Therefore, most of the bugs are captured before deployment.

.. caution::

   Although libtpa has been tested heavily inside Bytedance **data center**,
   it's still recommended to run as much testing as you can before deployment,
   for libtpa is still under active development and it's just v1.0-**rc0**
   being released. Tons of changes have been made since the last stable release.

Embedded TCP Stack
~~~~~~~~~~~~~~~~~~

There are two things that might be kind of special about libtpa.

The first one is that libtpa is an embedded TCP stack implementation that
supports run-to-completion mode only. It creates no datapath thread
by itself. Instead, it's embedded in the application thread.

Acceleration for Specific TCP Connections
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The other special thing about libtpa is that it's not a standalone
TCP/IP stack implementation. Instead, it lives together with the host
TCP/IP stack: libtpa just takes control of the specific TCP connections
needed to be accelerated. Taking redis as an example, if redis is
accelerated by libtpa, then all TCP connections belonging to redis will
go to libtpa.  All other connections (TCP or none TCP, such as UDP)
go to where it belongs: the host stack.

There is a huge advantage about that. If libtpa crashes, except the
application accelerated by libtpa is affected, none other workloads
would be affected.

Having said that, it requires some special support from NIC. Section
:ref:`Requirements<requirements>` gives a bit more information about
that.

.. _requirements:

Requirements
------------

Due to the novel design described above (to just accelerate some specific
TCP connections), libtpa requires
`flow bifurcation <https://doc.dpdk.org/guides/howto/flow_bifurcation.html>`_
support from NIC.

Most NICs have flow bifurcation support with the help of SR-IOV.
But they require some internal DPDK/Linux patches (or even firmwares)
to satisfy the libtpa needs.

On the other hand, Mellanox NIC has native flow bifurcation support
that doesn't require SR-IOV. More importantly, it doesn't require any
internal stuff. Libtpa works well with Mellanox NIC just with the
upstream DPDK.

Therefore, libtpa currently only supports Mellanox NIC.

Build Libtpa
------------

**Install Mellanox OFED:**

Libtpa currently supports Mellanox NIC only. The Mellanox OFED has to
be installed.  It can be downloaded from
`here <https://network.nvidia.com/products/infiniband-drivers/linux/mlnx_ofed/>`_.
Then run below command to install it::

    ./mlnxofedinstall --dpdk --upstream-libs

**Install Dependencies:**

For debian system, you can simply run following command at the
libtpa source dir to install the dependencies::

    ./buildtools/install-dep.deb.sh

Or below if a complain about low meson version is met afterwards:

.. code-block:: text

   ./buildtools/install-dep.deb.sh --with-meson

**Build Libtpa**

With all setup, you can build libtpa simply by::

    make
    make install

.. note::
    It's not needed to build DPDK alone. Libtpa will build DPDK when
    necessary, say when it's not built yet or when the build mode is
    changed. If you want to rebuild DPDK, you could::

        make distclean
        make

    Moreover, you don't even need to clone DPDK first. Libtpa will do it
    for you. Therefore, what all you need is to execute the ``make`` command.

.. note::

    Libtpa currently supports DPDK v19.11, v20.11 and v22.11. Both v19.11
    and v20.11 are tested heavily inside Bytedance. V20.11.3 is the default
    DPDK version being used. V22.11 support was just added recently.

    If you want to switch to another DPDK version we currently support, say
    v22.11, you could::

        export DPDK_VERSION=v22.11
        make
        make install


Run Libtpa Applications
-----------------------

Before running a libtpa application, hugepages need to be allocated first.
Here is a `guide from DPDK <https://doc.dpdk.org/guides/linux_gsg/sys_reqs.html#use-of-hugepages-in-the-linux-environment>`_.
After that, you are ready to run libtpa applications. And there are
two ways.

**Run directly with the correct configs**

.. code-block:: text

    # cat tpa.cfg
    net {
        name = eth0
        ip   = 192.168.1.10
        gw   = 192.168.1.1
        mask = 255.255.255.0
    }

    dpdk {
        pci = 0000:00:05.0
    }

    # swing 192.168.1.12 22
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

**Run with the libtpa wrapper**

There is a more convenient way to do this: run it with the libtpa wrapper.

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

As you can see, it fills the correct ipv4 cfgs for you. Moreover, it also
sets ipv6 configs when it exists.

.. note::

    ``tpa run`` selects the first valid eth (when it is a Mellanox device and
    has at least one IP address). If you have multiple valid eth devices, you
    can control which one to use with the ``TPA_ETH_DEV`` env var::

        TPA_ETH_DEV=eth1 tpa run ...

Libtpa Builtin Applications
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Libtpa ships few applications, for testing and debug purposes. It's also
a good source for learning how to program with libtpa customized APIs.
You can check :ref:`here <prog_guide>` for a detailed programming guide.

**swing**

It's a debug tool quite similar to telnet. It's a handy tool to check
whether libtpa (or the networking) works or not. Meanwhile, it's also
a short example on how to write a libtpa client program. Above section
already presents some examples.

.. code-block:: text
   :caption: Swing Usage

   # swing -h
   usage: swing [options] server port

   Supported options are:
     -z                    enable zero copy write

**techo**

It's another debug tool, which simply echos back what it receives from the
client. It's normally used together with swing, to check the libtpa TCP
connection. Like swing, it can also serve as an example on how to write
a libtpa server program. The usage is simple: just provide the port to
listen on.

.. code-block:: text
   :caption: Techo Example

   # techo 5678
   EAL: Detected CPU lcores: 8
   EAL: Detected NUMA nodes: 1
   EAL: Detected static linkage of DPDK
   EAL: Selected IOVA mode 'PA'
   EAL: Probe PCI driver: mlx5_pci (15b3:1018) device: 0000:00:05.0 (socket -1)
   mlx5_net: Default miss action is not supported.
   :: listening on port 5678 ...

**tperf**

As the name sugguests, it's a benchmark tool. Below is the usage. You
can check :ref:`loopback mode <loopback_mode>` section for examples.

.. code-block:: text
   :caption: Tperf Usage

   # tperf -h
   usage: tperf [options]

          tperf -s [options]
          tperf -t test [options]

   Tperf, a libtpa performance benchmark.

   Client options:
     -c server         run in client mode (the default mode) and specifies the server
                       address (default: 127.0.0.1)
     -t test           specifies the test mode, which is listed below
     -p port           specifies the port to connect to (default: 4096)
     -d duration       specifies the test duration (default: 10s)
     -m message_size   specifies the message size (default: 1000)
     -n nr_thread      specifies the thread count (default: 1)
     -i                do integrity verification (default: off)
     -C nr_conn        specifies the connection to be created for each thread (default: 1)
     -W 0|1            disable/enable zero copy write (default: on)
     -S start_cpu      specifies the starting cpu to bind

   Server options:
     -s                run in server mode
     -n nr_thread      specifies the thread count (default: 1)
     -l addr           specifies local address to listen on
     -p port           specifies the port to listen on (default: 4096)
     -S start_cpu      specifies the starting cpu to bind

   The supported test modes are:
     * read            read data from the server end
     * write           write data to the server end
     * rw              test read and write simultaneously
     * rr              send a request (with payload) to the server and
                       expects a response will be returned from the server end
     * crr             basically does the same thing like rr, except that a
                        connection is created for each request

Run Multiple Libtpa Instances
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

You can run as many libtpa instances as the hardware resources permit.
Libtpa uses ``TPA_ID`` as the unique identifier of a specific instance.
This ID could be generated by libtpa at runtime, with a pattern of
"program_name[$num_postfix]". Taking swing as an example, if no swing instance
has been running, the ID then will be "swing". If one more swing
instance starts, it then will be "swing1", and so on.

Having said that, it's still recommended to set the TPA_ID by your own::

    TPA_ID=client tpa run swing ....

That is because most of libtpa tools require the TPA_ID. Therefore,
specifying the TPA_ID by yourself gives you a bit more control, especially
when you want to run multiple instances of the same application.

.. _loopback_mode:

Loopback Mode
~~~~~~~~~~~~~

Libtpa supports loopback mode differently compared with the ``lo`` interface.
Again, it requires physical loopback support from the NIC. That said, the
packet will actually go into the NIC and then go back to the same host again.

Below is an example demonstrating that. We run two libtpa applications on
the same host, one is the tperf server, and the other one is the tperf client.

.. code-block:: text
   :caption: Tperf Server

   # TPA_ID=server taskset -c 1 tperf -s -n 1
   EAL: Detected 96 lcore(s)
   EAL: Detected 2 NUMA nodes
   EAL: Detected static linkage of DPDK
   EAL: Selected IOVA mode 'PA'
   EAL: No available hugepages reported in hugepages-1048576kB
   EAL: Probing VFIO support...
   EAL: Probe PCI driver: mlx5_pci (15b3:1017) device: 0000:5e:00.1 (socket 0)
   mlx5_pci: Default miss action is not supported.

.. code-block:: text
   :caption: Tperf Client

   # TPA_ID=client taskset -c 2 tperf -c 127.0.0.1 -t rr -m 1
   EAL: Detected 96 lcore(s)
   EAL: Detected 2 NUMA nodes
   EAL: Detected static linkage of DPDK
   EAL: Selected IOVA mode 'PA'
   EAL: No available hugepages reported in hugepages-1048576kB
   EAL: Probing VFIO support...
   EAL: Probe PCI driver: mlx5_pci (15b3:1017) device: 0000:5e:00.1 (socket 0)
   mlx5_pci: Default miss action is not supported.
       0 RR .0 min=4.10us avg=4.43us max=96.51us count=224809
       1 RR .0 min=4.10us avg=4.38us max=79.36us count=228426
       2 RR .0 min=4.10us avg=4.36us max=84.22us count=229371
       3 RR .0 min=4.10us avg=4.36us max=135.17us count=229385
       4 RR .0 min=4.10us avg=4.36us max=81.41us count=229366
       5 RR .0 min=4.10us avg=4.36us max=77.31us count=229459
       6 RR .0 min=4.10us avg=4.36us max=78.08us count=229349
       7 RR .0 min=4.10us avg=4.36us max=105.47us count=229238
       8 RR .0 min=4.10us avg=4.36us max=77.82us count=229565
       9 RR .0 min=4.10us avg=4.36us max=87.04us count=229363

   ---
    0 nr_conn=1 nr_zero_io_conn=0

.. note::

    Apparently, libtpa will not be able to connect to the loopback
    TCP connections if the other end is Linux kernel TCP/IP stack.
    Above works only because both the client and server are running
    with libtpa.

Tools
-----

As a DPDK based userspace stack implementation, it's proud to say
that libtpa has a rich set of tools.

sock list
~~~~~~~~~

tpa sock-list (or ``tpa sk`` in short) lists the socks. Some basic usages
are listed below.

**list active socks**::

    # tpa sk
    sid=4 192.168.1.10:55569 192.168.1.10:4096 worker=0 established
    sid=5 192.168.1.10:55555 192.168.1.10:4096 worker=0 established
    sid=6 192.168.1.10:55589 192.168.1.10:4096 worker=0 established
    sid=7 192.168.1.10:55609 192.168.1.10:4096 worker=0 established


**list all socks, including closed socks**::

    # tpa sk -a
    sid=[0] 192.168.1.10:55588 192.168.1.10:4096 worker=0 closed
    sid=[1] 192.168.1.10:55586 192.168.1.10:4096 worker=0 closed
    sid=[2] 192.168.1.10:55607 192.168.1.10:4096 worker=0 closed
    sid=[3] 192.168.1.10:55614 192.168.1.10:4096 worker=0 closed
    sid=4 192.168.1.10:55569 192.168.1.10:4096 worker=0 established
    sid=5 192.168.1.10:55555 192.168.1.10:4096 worker=0 established
    sid=6 192.168.1.10:55589 192.168.1.10:4096 worker=0 established
    sid=7 192.168.1.10:55609 192.168.1.10:4096 worker=0 established


.. _sock_latency:

**list socks with (very) detailed info**

``tpa sk -v`` dumps very detailed info for each sock. Actually, it's
so verbose that it might be very hard to find something useful with
a glimpse. Instead, you could combine it with a grep command to filter
out the parts you care most about. For example, below combo shows read
and write latencies measured by libtpa::

    # tpa sk -v | grep -e sid -e _lat
    sid=0 192.168.1.10:54157 192.168.1.10:4096 worker=0 established
            write_lat.submit(avg/max)       : 0.0/16.1us
            write_lat.xmit(avg/max)         : 0.1/52.5us
            write_lat.complete(avg/max)     : 4.2/102.1us
            read_lat.submit(avg/max)        : 0.1/16.1us
            read_lat.drain(avg/max)         : 0.2/49.6us
            read_lat.complete(avg/max)      : 0.2/49.7us
            read_lat.last_write(avg/max)    : 4.8/102.8us

Above output deserves some explanation. For write operation, there are
four stages:

#. send data by invoking the tpa write API
#. submit the write request to the sock txq
#. fetch the data from txq, encap with tcp/eth/ip header and send it to NIC
#. get the ack which denotes the data is received by the remote

- ``write_lat.submit`` denotes the latency from stage 1 to stage 2.
- ``write_lat.xmit`` denotes the latency from stage 1 to stage 3.
- ``write_lat.complete`` denotes the latency from stage 1 to stage 4.

And there are four similar stages for read operation:

#. receive the packet from NIC
#. go through the libtpa TCP stack and deliver it to the sock rxq
#. APP reads the data by the libtpa read API
#. APP finishes the processing of the data by invoking the corresponding
   iov.iov_read_done callback.

- ``read_lat.submit`` denotes the latency from stage 1 to stage 2.
- ``read_lat.drain`` denotes the latency from stage 1 to stage 3.
- ``read_lat.complete`` denotes the latency from stage 1 to stage 4.

sock stats
~~~~~~~~~~

tpa sock-stats (or ``tpa ss`` in short) shows some key sock stats in a
real-time view, say rx/tx rated, etc::

    # tpa ss
    sid    state        rx.mpps   rx.MB/s   tx.mpps   tx.MB/s   retrans.kpps retrans.KB/s connection
    4      established  0.116     115.764   0.116     115.764   0            0            192.168.1.10:55569-192.168.1.10:4096
    5      established  0.116     115.764   0.116     115.764   0            0            192.168.1.10:55555-192.168.1.10:4096
    6      established  0.116     115.764   0.116     115.764   0            0            192.168.1.10:55589-192.168.1.10:4096
    7      established  0.116     115.765   0.116     115.765   0            0            192.168.1.10:55609-192.168.1.10:4096
    total  4            0.463     463.058   0.463     463.058   0            0            -

.. _st_tool:

sock trace
~~~~~~~~~~

tpa sock-trace (or ``tpa st`` in short) is the most handy (and yet the
most powerful) tool libtpa provides. The sock trace implementation in
libtpa is so lightweight that it's enabled by default. Therefore, we
could always know what's exactly going on under the hoods.

To demonstrates what a trace looks like, let's run the swing first::

    # TPA_ID=client swing 127.0.0.1 5678
    EAL: Detected 8 lcore(s)
    EAL: Detected 1 NUMA nodes
    EAL: Detected static linkage of DPDK
    EAL: Selected IOVA mode 'PA'
    EAL: No available hugepages reported in hugepages-1048576kB
    EAL: Probing VFIO support...
    EAL: Probe PCI driver: mlx5_pci (15b3:1018) device: 0000:00:05.0 (socket 0)
    mlx5_pci: Default miss action is not supported.
    :: connecting to 127.0.0.1:5678 ... [connected]
    > hello world
    < hello world

    >

Then we run below to check the trace:

.. code-block:: text

       # tpa st client -o relative-time
       :: /var/run/tpa/client/trace/socktrace-2542693 0        8320   2023-12-04.16:28:44.914847   0      192.168.1.10:55895 -> 192.168.1.10:5678
       0.000000 192.168.1.10:55895 192.168.1.10:5678 worker=0
       0.003519 xmit syn: snd_isn=1406571739 rto=0 rxq_size=2048 txq_size=512
   1=> 0.003519 xmit pkt: seq=0 len=0 hdr_len=78 nr_seg=1 ts=3 snd_wnd=0 cwnd=0 ssthresh=0 |  SYN
   2=> 0.004599 tcp_rcv: seq=0 len=0 nr_seg=1 wnd=65535 .-rcv_nxt=+1406571912 | ack=1 .-snd_una=+1 .-snd_nxt=+0 | ACK SYN
       0.004599        > ts.val=3657668934 ts_recent=0 last_ack_sent=2888395384 ts_ecr=637298365
       0.004599        > rtt=1080 srtt=8640 rttvar=2160 rto=101080
       0.004599 state => established rxq_left=0 txq_left=0
   3=> 0.004599 xmit pkt: seq=1 len=0 hdr_len=66 nr_seg=1 ts=4 snd_wnd=65535 cwnd=16384 ssthresh=1048576 |  ACK
       0.004599 xmit data: seq=1 off=0 len=12 budget=16384 | NON-ZWRITE
   4=> 2.885346 xmit pkt: seq=1 len=12 hdr_len=66 nr_seg=2 ts=2817 snd_wnd=65535 cwnd=16384 ssthresh=1048576 |  ACK
       2.885346 txq update: inflight=1 to_send=0 free=511
       2.886416 tcp_rcv: seq=1 len=0 nr_seg=1 wnd=2799 .-rcv_nxt=+0 | ack=13 .-snd_una=+12 .-snd_nxt=+12 | ACK
       2.886416        > ts.val=3657671748 ts_recent=3657671748 last_ack_sent=1 ts_ecr=637298365
       2.886416        > [0] una=13 partial_ack=0 desc.seq=1 desc.len=12 latency=1070 acked_len=12 | NON-ZWRITE
       2.886416 txq update: inflight=0 to_send=0 free=512
       2.886416        > rtt=1070 srtt=8630 rttvar=1630 rto=101078
   5=> 2.886416 tcp_rcv: seq=1 len=12 nr_seg=1 wnd=2800 .-rcv_nxt=+0 | ack=13 .-snd_una=+0 .-snd_nxt=+12 | ACK
       2.886416        > enqueued.len=12 rcv_wnd=2867188 rxq_rxq_readable_count=1 rxq_free_count=2047
       2.886416        > ts.val=3657671748 ts_recent=3657671748 last_ack_sent=1 ts_ecr=637298365
       2.886416 xmit pkt: seq=13 len=0 hdr_len=66 nr_seg=1 ts=2818 snd_wnd=2867200 cwnd=16384 ssthresh=1048576 |  ACK

The line mark 1 to 3 denotes the typical TCP handshake process. At line
mark 4, 12 bytes of TCP payload ("hello world") have been sent. And at
line mark 5, we got the reply (from techo).

As you can see, we can even get the precise latency from the trace. Note
that swing is a debug tool and there is a 1ms delay (usleep(1000)) for
each loop. That's the reason why the above latency looks quite big.

Libtpa does a bit more to make the trace more powerful: libtpa archives
the trace automatically when it gets recovered from something abnormal,
such as retrans. Besides that, libtpa notes down the recovery time::

    # tpa st | grep rto | head
    /var/log/tpa/client/socktrace194   ...  2023-12-04.16:55:00.070575  ... rto-107.447ms
    /var/log/tpa/client/socktrace193   ...  2023-12-04.16:55:00.068062  ... rto-214.160ms
    /var/log/tpa/client/socktrace192   ...  2023-12-04.16:55:00.065471  ... rto-214.160ms
    /var/log/tpa/client/socktrace191   ...  2023-12-04.16:55:00.062957  ... rto-234.977ms
    /var/log/tpa/client/socktrace190   ...  2023-12-04.16:55:00.060359  ... rto-214.160ms
    /var/log/tpa/client/socktrace189   ...  2023-12-04.16:55:00.057774  ... rto-214.160ms
    /var/log/tpa/client/socktrace188   ...  2023-12-04.16:55:00.055150  ... rto-184.099ms
    /var/log/tpa/client/socktrace187   ...  2023-12-04.16:55:00.052640  ... rto-178.073ms
    /var/log/tpa/client/socktrace186   ...  2023-12-04.16:55:00.050103  ... rto-181.962ms
    /var/log/tpa/client/socktrace185   ...  2023-12-04.16:55:00.047533  ... rto-179.440ms

Then you can run below command to check what exactly happened::

    tpa st /var/log/tpa/client/socktrace194

The sock trace is so convenient and powerful that libtpa doesn't even
have tools like tcpdump.


worker stats
~~~~~~~~~~~~

``worker`` is the processing unit in libtpa: all TCP packets are processed
there. ``tpa worker`` dumps all the worker status::

    # tpa worker
    worker 0
            tid                             : 2483926
            cycles.busy                     : 590875284682
            cycles.outside_worker           : 379177649718
            cycles.total                    : 1595269726942
            last_run                        : 0.000000s ago
            last_poll                       : 0.000000s ago
            avg_runtime                     : 0.4us
            avg_starvation                  : 0.0us
            max_runtime                     : 10.268ms
            max_starvation                  : 322.983ms
            nr_tsock                        : 4
            nr_tsock_total                  : 8
            dev_txq.size                    : 4096
            nr_ooo_mbuf                     : 0
            nr_in_process_mbuf              : 0
            nr_write_mbuf                   : 0
            dev_txq[0].nr_pkt               : 0
            dev_rxq[0].nr_pkt               : 0
            TCP_RTO_TIME_OUT                : 48
            ERR_NO_SOCK                     : 52
            PKT_RECV                        : 334407737
            BYTE_RECV                       : 334407349000
            BYTE_RECV_FASTPATH              : 334407349000
            PKT_XMIT                        : 334407365
            BYTE_XMIT                       : 334407357512
            BYTE_RE_XMIT                    : 24000
            ZWRITE_FALLBACK_PKTS            : 8
            ZWRITE_FALLBACK_BYTES           : 512
            PURE_ACK_IN                     : 20
            PURE_ACK_OUT                    : 332
            SYN_XMIT                        : 28

Most of them are quite self-explanatory. The ``starvation`` metric
denotes the time runs outside the libtpa worker. Sometimes if
something goes wrong, these metrics might give a hint which part
(libtpa itself or the application code) is likely wrong.

mem stats
~~~~~~~~~

``tpa mem`` dumps memory related stats::

    # tpa mem
    mempool stats
    =============

                name  total    free     cache ...
     mbuf-mempool-n0  185344   180728   0/569
    zwrite-mbuf-mp-0-n0  494250   493737   0/508
    hdr-mbuf-mp-0-n0  185344   184831   0/499

    rte_malloc stats
    ================

    Heap id:0
            Heap name:socket_0
            Heap_size:1073741824,
            Free_size:334795136,
            Alloc_size:738946688,
            Greatest_free_size:334794880,
            Alloc_count:447,
            Free_count:2,

    memseg stats
    ============

            base=0x100200000 size=1073741824 pagesize=2097152 nr_page=512 socket=0 external=no
            base=0x7f8321197000 size=536870912 pagesize=4096 nr_page=131072 socket=256 external=yes

cfg
~~~

Libtpa is a highly customizable project. You could either customize
it through the config file or through the ``tpa cfg`` tool. For
example, below command disables TSO::

    tpa cfg set tcp.tso 0

You can reference :ref:`Config Options<config_options>` section for
more detailed information about config options.

neigh
~~~~~

``tpa neigh`` dumps neighbors. It dumps both ARP and ICMPv6 neighbors.

version
~~~~~~~

``tpa -vv`` dumps detailed version information for both the installed
and running version::

    # tpa -vv
    installed: v1.0-rc0
    running:
    --------
    TPA_ID     pid      program  version   uptime
    client     2517834  tperf    v1.0-rc0  2023-12-04 15:20:15, up 21s
    server     2517867  tperf    v1.0-rc0  2023-12-04 15:20:28, up 9s

.. _config_options:

Config Options
--------------

**Config File**

Libtpa has a customized config file format. It's really simple though::

    section_name {
        key1 = val1
        key2 = val2
    }

It can also be in compact mode::

    section_name { key1 = val1; key2 = val2; }

.. note::

   There are some things worth noting about the current homemade format:

   - the semicolon(``;``) is always needed for the compact mode. It's easy
     to forget the last one.

   - the equal mark(``=``) is a reserved char even for value. Therefore,
     it's illegal to write something like below::

         pci = 0000:00:05.0,arg1=val1

     In such case, instead, you should use the double quotation mark (note
     that we don't support single quotation mark)::

         pci = "0000:00:05.0,arg1=val1"

**Customize**

There are two ways to do customize before startup:

- through config file

  Libtpa finds config file in below order:

  - ./tpa.cfg
  - /etc/tpa.cfg

- through the env var with the compact cfg mode::

    TPA_CFG="tcp { tso = 0; }" tpa run tperf ...

**Config Options**

All libtpa config options are divided in sections. The runtime libtpa
displays the config options in a slightly different format: section_name.key.
``tpa cfg list`` lists all the config options libtpa supports::

    # tpa cfg list
    log.level                2
    log.file                 N/A
    net.ip                   192.168.1.10
    net.mask                 255.255.255.0
    net.gw                   192.168.1.1
    net.ip6                  ::
    net.gw6                  ::
    net.mac                  fa:16:3e:30:4f:90
    net.name                 eth0
    net.bonding              N/A
    trace.enable             1
    trace.more_trace         0
    trace.trace_size         8KB
    trace.nr_trace           2048
    trace.no_wrap            0
    tcp.nr_max_sock          32768
    tcp.pkt_max_chain        45
    tcp.usr_snd_mss          0
    tcp.time_wait            1m
    tcp.keepalive            2m
    tcp.delayed_ack          1ms
    tcp.tso                  1
    tcp.rx_merge             1
    tcp.opt_ts               1
    tcp.opt_ws               1
    tcp.opt_sack             1
    tcp.retries              7
    tcp.syn_retries          7
    tcp.rcv_queue_size       2048
    tcp.snd_queue_size       512
    tcp.cwnd_init            16384
    tcp.cwnd_max             1073741824
    tcp.rcv_ooo_limit        2048
    tcp.drop_ooo_threshold   33792
    tcp.measure_latency      0
    tcp.rto_min              100ms
    tcp.write_chunk_size     16KB
    tcp.local_port_range     41000 64000
    shell.postinit_cmd       N/A
    dpdk.socket-mem          1024
    dpdk.pci                 0000:00:05.0
    dpdk.extra_args          N/A
    dpdk.mbuf_cache_size     512
    dpdk.mbuf_mem_size       0
    dpdk.numa                0
    dpdk.huge-unlink         1
    offload.flow_mark        1
    offload.sock_offload     0
    offload.port_block_offload 1
    pktfuzz.enable           0
    pktfuzz.log              N/A
    archive.enable           1
    archive.flush_interval   60

Some options could be modified at runtime. For example, below command
disables trace (which is enabled by default)::

    tpa cfg set trace.enale 0

Some options are read-only and can only be set once at startup time,
such as net related configs (right, libtpa currently doesn't support
changing IP address at runtime). An error will be reported if one tries
to modify them::

    # tpa cfg set net.ip 192.168.1.12
    failed to set cfg opt: net.ip: try to set a readonly option

Feature List
------------

**TCP Features:**

- New Reno
- fast retransmission
- timed out retransmission
- spurious fast retransmission detection
- congestion window validation
- selective ACK
- delayed ACK
- keepalive
- zero window probe
- protect against wrapped sequence numbers (PAWS)
- timestamp option
- window scale option
- maximum segment size(MSS) option

**Other Features:**

- IPv6
- TSO
- checksum offload
- jumbo frame
- multiple thread
- zero copy read
- zero copy write
- epoll like interface

Supported Hardwares
-------------------

**platforms:**

- AMD64
- ARM (not well tested)

**NICs:**

- Mellanox NIC (from ConnectX-4 to ConnectX-7)
