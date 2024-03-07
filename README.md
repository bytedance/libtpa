Libtpa(Transport Protocol Acceleration) is a DPDK based userspace TCP
stack implementation.

Libtpa is fast. It boosts the [redis benchmark](https://bytedance.github.io/libtpa/redis.html) performance
more than 5 times, from 0.21m rps to 1.14m rps. Meanwhile, the p99 latency
is greatly decreased, from 0.815ms to 0.159ms.

Libtpa is also sort of stable, all kudos to the comprehensive testing.
Libtpa has more than 200 tests. Together with the testing arguments
matrix, it can result in a big variety of test cases. Therefore,
most of the bugs are captured before deployment.

# Coexisting with the Host Stack

What distinguishes Libtpa from many other userspace TCP stacks is its
ability to coexist natively with the Linux kernel networking stack,
facilitated by a mechanism called [flow bifurcation](https://bytedance.github.io/libtpa/nics/intro.html).
Libtpa just takes control of the specific TCP connections needed to
be accelerated.
Taking Redis as an example, if redis is accelerated by Libtpa, then
all TCP connections belonging to Redis will go to Libtpa.
All other connections (TCP or none TCP, such as UDP) would go to
the Linux kernel networking stack instead.

There is a huge advantage about that. If Libtpa crashes, except the
application accelerated by Libtpa is affected, none other workloads
would be affected.

:warning: Although Libtpa has been tested heavily inside Bytedance **data center**,
it's still recommended to run as much testing as you can before deployment,
for Libtpa is still under active development and it's just v1.0-**rc0**
being released. Tons of changes have been made since the last stable release.

# What's Next

You might want to check below docs for more detailed information:

-  [quick start guide](https://bytedance.github.io/libtpa/quick_start.html)
-  [user guide](https://bytedance.github.io/libtpa/user_guide.html)
-  [programming guide](https://bytedance.github.io/libtpa/prog_guide.html)
-  [contribution guide](CONTRIBUTING.md)
-  [internals](https://bytedance.github.io/libtpa/internals.html)
