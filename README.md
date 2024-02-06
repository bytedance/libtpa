Libtpa(Transport Protocol Acceleration) is a DPDK based userspace TCP
stack implementation.

Libtpa is fast. It boosts the [redis benchmark](doc/redis.rst) performance
more than 5 times, from 0.21m rps to 1.14m rps. Meanwhile, the p99 latency
is greatly decreased, from 0.815ms to 0.159ms.

Libtpa is also sort of stable, all kudos to the comprehensive testing.
Libtpa has more than 200 tests. Together with the testing arguments
matrix, it can result in a big variety of test cases. Therefore,
most of the bugs are captured before deployment.

:warning: Although libtpa has been tested heavily inside Bytedance **data center**,
it's still recommended to run as much testing as you can before deployment,
for libtpa is still under active development and it's just v1.0-**rc0**
being released. Tons of changes have been made since the last stable release.

# Embedded TCP Stack

There are two things that might be kind of special about libtpa.

The first one is that libtpa is an embedded TCP stack implementation that
supports run-to-completion mode only. It creates no datapath thread
by itself. Instead, it's embedded in the application thread.

# Acceleration for Specific TCP Connections

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

# What's Next

You might want to check below docs for more detailed information:

-  [quick start guide](doc/quick_start.rst)
-  [user guide](doc/user_guide.rst)
-  [programming guide](doc/prog_guide.rst)
-  [contribution guide](CONTRIBUTING.md)
-  [internals](doc/internals.rst)
