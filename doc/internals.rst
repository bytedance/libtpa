..  Copyright (c) 2021-2023, ByteDance Ltd. and/or its Affiliates
    Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>

Libtpa Internals
================

Introduction
------------

This documentation describes some internal implementation details about
libtpa. Hopefully, it will make it a bit easier for you to understand
the implementation if you want to contribute or do customization for
your own needs.

Zero Copy
---------

Zero copy is a must for high performance. Libtpa supports both zero copy
write and read. Like the :ref:`programming guide <prog_guide>` described,
libtpa introduces an extended iovec struct, tpa_iovec, to complement the
zero copy implementation.

Zero Copy Write
~~~~~~~~~~~~~~~

A write request from both ``tpa_write`` and ``tpa_zwritev`` will be turned
to one or more ``tx_desc``, depending the iov count, write size and the config
``tcp.write_chunk_size`` (which is set to 16KB by default).

.. code-block:: c

    struct tx_desc {
        void *addr;
        uint64_t phys_addr;
        uint32_t len;
        uint32_t flags;
        void (*write_done)(void *base, void *param);
        void *base;
        void *param;

        uint32_t seq;
        uint32_t reserved;
        uint64_t ts_us;

        /* cacheline 2 */
        uint64_t tsc_start;
        uint64_t tsc_submit;
        uint64_t tsc_xmit;

        /* for none zero copy write */
        void *pkt;
    } __attribute__((__aligned__(64)));

``tx_desc`` has a few more fields compared with ``tpa_iovec``, where

- ``seq`` denotes the TCP seq assigned to this desc
- ``ts_us`` denotes the transmit timestamp

The three tsc_xxx fields are used for latency measurement:

- ``tsc_start`` denotes the timestamp at the beginning of the write API.
- ``tsc_submit`` denotes the timestamp when the write is submitted to the
  TCP txq.
- ``tsc_xmit`` denotes the timestamp when the data is going to be
  transmitted.

You can check the :ref:`user guide <sock_latency>` on how to check the sock
latency with the help of those fields.

Since it's zero copy write, the APP can't free the write buffer when the API
returns: the buffer is still referenced by libtpa and it may even have to be
retransmitted. Therefore, the APP can free it only when libtpa no longer
references it, that is when the data is ACKed by the remote end. And that's
what the ``iov_write_done`` field for.

The function ``tcp_xmit_data`` then will fetch those tx descs and encap them
with a TCP header and then send them out by the familiar DPDK API ``rte_eth_tx_burst``.
Note that DPDK only deals with rte_mbuf. Therefore, we have to turn the tx desc
to rte_mbuf. Libtpa does not use the DPDK API to do the external buffer
attachment, instead, it comes up with something a bit more lightweight:

.. code-block:: c

    /*
     * A more lightweight external buf attach for zero copy write implementation.
     */
    static inline void packet_attach_extbuf(struct packet *pkt, void *virt_addr,
                                            uint64_t phys_addr, uint16_t data_len)
    {
        pkt->mbuf.buf_addr = virt_addr;
        pkt->mbuf.buf_iova = phys_addr;
        pkt->mbuf.pkt_len  = data_len;
        pkt->mbuf.data_len = data_len;
        pkt->mbuf.data_off = 0;
    }

To consume as less memory as possible, libtpa creates one ``zwrite_pkt_pool``
mempool for each worker. Mbufs from this pool only has room for the ``rte_mbuf``
struct and 128 bytes of private data(for holding the ``struct packet`` meta data):
the data room is set to zero, as they don't hold any data after all.

There is another advantage of introducing ``zwrite_pkt_pool``. Libtpa
only allocates mbufs from this pool for one purpose: attaching them to
external bufs. Therefore, we don't have to reset them while freeing them.
They will get reset automatically every time we attach them to new
external bufs. Therefore, it's more lightweight.

Zero Copy Read
~~~~~~~~~~~~~~

It's a bit tricky to implement zero copy read, as it's the DPDK but not
the application to prepare the receive buffer (the mbuf). Therefore,
to get the zero copy semantics, we have to pass the mbuf to the
application. Like what we have to deal with for zero copy write, the
rte_mbuf has to be freed somewhere and somewhen. The callback
``iov_read_done`` is the answer: the user has to invoke it when it
no longer needs the corresponding iov.

Below is the key code snippet of zero copy read implementation:

.. code-block:: c

    static void iov_buf_free(void *addr, void *param)
    {
        struct packet *pkt = param;

        if (--pkt->nr_read_seg == 0) {
            /* ... */
            packet_free(pkt);
        }
    }

    static inline size_t pkt_to_iov_one_seg(struct tpa_iovec *iov,
                                            struct packet *head,
                                            struct packet *pkt)
    {
        iov->iov_base = tcp_payload_addr(pkt);
        iov->iov_phys = tcp_payload_phys_addr(pkt);
        iov->iov_len  = pkt->l5_len;
        iov->iov_read_done = iov_buf_free;
        iov->iov_param     = head;

        /* ... */
        return iov->iov_len;
    }

Tracing
-------

Judging the complexity of the TCP protocol, we really need something that
can give us internal insights when something goes wrong. Tcpdump is a
great tool, but we normally use it to debug the issue after it has already
happened. Therefore, it relies on that the issue is reproduce-able.
Apparently, tcpdump is so heavy that it can not be enabled all the time.

Tracing is the solution after much thought. Tracing implemented in libtpa
has two characteristics: 

- it's filled in binary format only. Therefore, it's lightweight

- it's a ring buffer. Therefore, it will not eat our disk or memory.

Thus, tracing is always enabled in libtpa. The overhead is so small that
it can be ignored. As you can see from the :ref:`redis bencharmk <redis_libtpa>`
test, tracing brings less than 3% performance penalty. More importantly,
we now could know exactly what happens with the :ref:`tpa st <st_tool>`
tool when something goes wrong.

Below goes quickly about the tracing implementation. As stated above, a
trace is a ring buffer of ``trace_record``:

.. code-block:: c

    struct trace_record {
        union {
            struct {
                uint8_t type;
                uint8_t u8;
                uint16_t u16;
                uint32_t u32;
            };

            struct {
                uint64_t _type:8;
                uint64_t u56:56;
            };
        };
    };

    #define TYPE_RECORD(_type, ...) record = &trace->records[(trace->off++) & trace->mask]; \
                                    record->type = _type;                           	    \
                                    __VA_ARGS__
    #define DATA_RECORD(...)        record = &trace->records[(trace->off++) & trace->mask]; \
                                    record->type = TT_data;                                 \
                                    __VA_ARGS__


The trace record is with fixed size: 8 bytes. The first byte is type. We then just have
the space for one 8-bit, one 16-bit and one 32-bit payload. Note that the 56-bit is
used only for tracing the timestamp payload so far.

.. code-block:: c

    #define R8(x)                   (record->u8 = x)
    #define R16(x)                  (record->u16 = x)
    #define R32(x)                  (record->u32 = x)
    #define R56(x)                  (record->u56 = x)


Below comes one specific trace declaration, trace_tcp_rcv_pkt:

.. code-block:: c

    DECLARE_TRACE(tcp_rcv_pkt, 2,
        TRACE_ARGS(
            uint32_t seq _AD_ uint32_t ack  _AD_  uint16_t wnd _AD_
            uint16_t len _AD_ uint8_t flags _AD_  uint8_t nr_seg
        ),

        TRACE_RECORDS(
            TYPE_RECORD(TT_tcp_rcv_pkt, R32(seq); R16(wnd); R8(flags));
            DATA_RECORD(R32(ack); R16(len); R8(nr_seg));
        ),

        TRACE_PARSER(
            trace_printf("tcp_rcv: seq=%u len=%u nr_seg=%u wnd=%hu .-rcv_nxt=%+d | ack=%u .-snd_una=%+d .-snd_nxt=%+d | %s\n",
                         rcv_seq(seq), len, nr_seg, wnd, (int)(seq - ctx->rcv_nxt),
                         snd_seq(ack), (int)(ack - ctx->snd_una), (int)(ack - ctx->snd_nxt),
                         tcp_flags_to_str(flags));
        )
    )

As you can see, libtpa only uses 2 records (16 bytes) for tracing a
received packet.

Since it's a ring buffer, the data will get overwritten eventually.
Assume there was a networking issue and got recovered later,
then the trace will get overwritten with new data transferred and
received. If you dump the live sock trace, you will find everything
normal. Therefore, it doesn't really help. libtpa automatically
archives the trace when it gets recovered from something abnormal
(such as out of order receive, retransmission, etc). In another
word, the scene is captured, you then can examine it by the
``tpa st`` tool any time you want (as far as it is not flushed).
For example,

.. code-block:: text

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


Mem File
--------

Libtpa makes use of memory files a lot, including the tracing file mentioned
above. Since the data is produced in one process (the libtpa instance) and
parsed in another process (the ``tpa st`` tool), the data format has to be
the same. Otherwise, the parser simply won't work. It's kind of like the
ABI issue. And it's really hard to maintain the data format unchanged for
a project under active development.

Libtpa solves this issue by embedding the parser into the mem file:

.. code-block:: c

    /* the disk layout */
    struct mem_file_hdr {
        uint64_t magic;
        uint64_t size;
        uint64_t data_offset;
        uint64_t parser_offset;
        char name[MEM_FILE_NAME_LEN];
    } __attribute__((__aligned__(64)));

Therefore, a mem file will always be parse-able. Taking the sock trace
file as example, the trace file will always print something meaningful
as far as we have it.

Neigh
-----

The neigh implementation in libtpa is a bit special. Libtpa injects the
neigh solicitation in the worker thread by DPDK, while it receives and
handles the response in the ctrl thread by the AF_PACKET socket.

It works well, since, by the current design, libtpa is not a standalone
TCP/IP stack. We need to handle neigh response in the worker thread as
well if you want to make libtpa be a standalone TCP/IP stack.

Libtpad
-------

Userspace stack is special compared with the kernel stack. If the userspace
stack process quits (either normally, or abnormally, say crash), no one will
do the cleanup job for those established socks. Those socks may keep as the
established state forever as far as the remote end doesn't send us anything.
Note that the stack is not even aware of those connections, therefore, the
kernel stack would also do nothing.

Therefore, libtpa introduces a daemon process for each instance. The daemon
basically enters to sleep mode when it starts. It will get woken up when
the corresponding instance is dead (either normally or abnormally). It
then will do the missing cleanup work: terminating active socks.

The terminating process is also kind of tricky, as it simply forges
a TCP RST packet and sends it out by, again, the AF_PACKET socket.

Keepalive
---------

Like what the libtpad section described, userspace stack lacks some
support to do sock cleanup. Besides the daemon process, there is actually
one more elegant solution: the TCP keepalive feature. It could detect
half open connections and then close them as early as possible (well,
with a few minutes delay).

Thus, keepalive is enabled by default in libtpa. You should not
disable it unless you know what you are doing.

Offload
-------

As stated in the :ref:`requirements <requirements>` section, libtpa
leverages the flow bifurcation to steer the packets of interest to itself.
It's the rte_flow interface doing the job under the hood.

More specifically, it's the QUEUE action to steer specific packets to
a specific worker, therefore, the shared-nothing model.

.. _matrix_shell:

Matrix Shell
------------

A test tool often comes with many arguments. Taking `tperf <https://github.com/bytedance/libtpa/tree/main/app/tperf>`_
as an example, it has arguments -t test, -m message_size, -n nr_thread, etc.
Each argument may have many options. For example, test could be read, write,
rw, etc. message_size could be 1, 4KB, 16KB, etc. If we treat that as a
argument matrix, we then can test a lot of different combinations:

.. code-block:: text

   # cat test.ms
   params:
     test: [read, write, rw]
     message_size: [1, 4KB, 16KB]
     nr_thread: [1, 4]
   end

   echo "testing with params: nr_thread=$nr_thread test=$test message_size=$message_size"


The above test.ms would then split to 3 * 3 * 2 = 18 test cases:

.. code-block:: text

    ms-list test.ms --short | nl
         1  test/test=read__message_size=1__nr_thread=1
         2  test/test=read__message_size=1__nr_thread=4
         3  test/test=read__message_size=4KB__nr_thread=1
         4  test/test=read__message_size=4KB__nr_thread=4
         5  test/test=read__message_size=16KB__nr_thread=1
         6  test/test=read__message_size=16KB__nr_thread=4
         7  test/test=write__message_size=1__nr_thread=1
         8  test/test=write__message_size=1__nr_thread=4
         9  test/test=write__message_size=4KB__nr_thread=1
        10  test/test=write__message_size=4KB__nr_thread=4
        11  test/test=write__message_size=16KB__nr_thread=1
        12  test/test=write__message_size=16KB__nr_thread=4
        13  test/test=rw__message_size=1__nr_thread=1
        14  test/test=rw__message_size=1__nr_thread=4
        15  test/test=rw__message_size=4KB__nr_thread=1
        16  test/test=rw__message_size=4KB__nr_thread=4
        17  test/test=rw__message_size=16KB__nr_thread=1
        18  test/test=rw__message_size=16KB__nr_thread=4
