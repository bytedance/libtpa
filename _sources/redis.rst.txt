..  Copyright (c) 2021-2023, ByteDance Ltd. and/or its Affiliates
    Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>

.. _redis_libtpa:

Redis with Libtpa
=================

Introduction
------------

This page shows how to build and run redis with libtpa acceleration.

In summary, libtpa boosts the redis GET benchmark performance more
than 5 times, from 0.21m rps to 1.14m rps. Meanwhile, the p99 latency
is greatly decreased, from 0.815ms to 0.159ms.

Build Redis
-----------

.. code-block:: text

   cd demo/redis
   ./build.sh

.. caution::

    Libtpa has to be installed (by executing make install) before
    building redis. Otherwise, redis build would fail.

Benchmark
---------

Start redis with::

    taskset -c 1 tpa run ./redis/src/redis-server --protected-mode no

With Sock Trace (the Default)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: text

    # taskset -c 1-20 redis-benchmark -h 192.168.1.10 --threads 20 -c 100 -t get -n 10000000
    ====== GET ======
      10000000 requests completed in 9.02 seconds
      100 parallel clients
      3 bytes payload
      keep alive: 1
      host configuration "save": 3600 1 300 100 60 10000
      host configuration "appendonly": no
      multi-thread: yes
      threads: 20

    Latency by percentile distribution:
    0.000% <= 0.015 milliseconds (cumulative count 171)
    50.000% <= 0.079 milliseconds (cumulative count 5583384)
    75.000% <= 0.095 milliseconds (cumulative count 8015454)
    87.500% <= 0.111 milliseconds (cumulative count 9164793)
    93.750% <= 0.119 milliseconds (cumulative count 9459320)
    96.875% <= 0.135 milliseconds (cumulative count 9764778)
    98.438% <= 0.151 milliseconds (cumulative count 9874730)
    99.219% <= 0.183 milliseconds (cumulative count 9925242)
    99.609% <= 0.383 milliseconds (cumulative count 9961301)
    99.805% <= 0.679 milliseconds (cumulative count 9980886)
    99.902% <= 0.823 milliseconds (cumulative count 9990402)
    99.951% <= 0.919 milliseconds (cumulative count 9995228)
    99.976% <= 0.999 milliseconds (cumulative count 9997681)
    99.988% <= 1.063 milliseconds (cumulative count 9998865)
    99.994% <= 1.127 milliseconds (cumulative count 9999429)
    99.997% <= 1.183 milliseconds (cumulative count 9999695)
    99.998% <= 1.255 milliseconds (cumulative count 9999858)
    99.999% <= 1.287 milliseconds (cumulative count 9999936)
    100.000% <= 1.311 milliseconds (cumulative count 9999963)
    100.000% <= 1.351 milliseconds (cumulative count 9999981)
    100.000% <= 1.383 milliseconds (cumulative count 9999993)
    100.000% <= 2.127 milliseconds (cumulative count 9999996)
    100.000% <= 2.167 milliseconds (cumulative count 9999998)
    100.000% <= 2.175 milliseconds (cumulative count 9999999)
    100.000% <= 2.511 milliseconds (cumulative count 10000000)
    100.000% <= 2.511 milliseconds (cumulative count 10000000)

    Cumulative distribution of latencies:
    87.127% <= 0.103 milliseconds (cumulative count 8712681)
    99.414% <= 0.207 milliseconds (cumulative count 9941442)
    99.568% <= 0.303 milliseconds (cumulative count 9956775)
    99.627% <= 0.407 milliseconds (cumulative count 9962749)
    99.692% <= 0.503 milliseconds (cumulative count 9969217)
    99.761% <= 0.607 milliseconds (cumulative count 9976114)
    99.825% <= 0.703 milliseconds (cumulative count 9982461)
    99.894% <= 0.807 milliseconds (cumulative count 9989381)
    99.946% <= 0.903 milliseconds (cumulative count 9994569)
    99.979% <= 1.007 milliseconds (cumulative count 9997861)
    99.993% <= 1.103 milliseconds (cumulative count 9999267)
    99.998% <= 1.207 milliseconds (cumulative count 9999761)
    100.000% <= 1.303 milliseconds (cumulative count 9999954)
    100.000% <= 1.407 milliseconds (cumulative count 9999993)
    100.000% <= 1.503 milliseconds (cumulative count 9999995)
    100.000% <= 3.103 milliseconds (cumulative count 10000000)

    Summary:
      throughput summary: 1109139.38 requests per second
      latency summary (msec):
              avg       min       p50       p95       p99       max
            0.081     0.008     0.079     0.127     0.167     2.511

Without Sock Trace
~~~~~~~~~~~~~~~~~~

Run below to disable trace::

   tpa cfg set trace.enable 0

Then start the test again:

.. code-block:: text

    # taskset -c 1-20 redis-benchmark -h 192.168.1.10 --threads 20 -c 100 -t get -n 10000000
    ====== GET ======
      10000000 requests completed in 8.77 seconds
      100 parallel clients
      3 bytes payload
      keep alive: 1
      host configuration "save": 3600 1 300 100 60 10000
      host configuration "appendonly": no
      multi-thread: yes
      threads: 20

    Latency by percentile distribution:
    0.000% <= 0.015 milliseconds (cumulative count 243)
    50.000% <= 0.079 milliseconds (cumulative count 6375418)
    75.000% <= 0.087 milliseconds (cumulative count 7608571)
    87.500% <= 0.103 milliseconds (cumulative count 8981182)
    93.750% <= 0.119 milliseconds (cumulative count 9550252)
    96.875% <= 0.127 milliseconds (cumulative count 9698107)
    98.438% <= 0.143 milliseconds (cumulative count 9853538)
    99.219% <= 0.175 milliseconds (cumulative count 9925384)
    99.609% <= 0.343 milliseconds (cumulative count 9961212)
    99.805% <= 0.647 milliseconds (cumulative count 9980991)
    99.902% <= 0.799 milliseconds (cumulative count 9990437)
    99.951% <= 0.903 milliseconds (cumulative count 9995162)
    99.976% <= 0.991 milliseconds (cumulative count 9997708)
    99.988% <= 1.055 milliseconds (cumulative count 9998797)
    99.994% <= 1.119 milliseconds (cumulative count 9999404)
    99.997% <= 1.167 milliseconds (cumulative count 9999698)
    99.998% <= 1.223 milliseconds (cumulative count 9999863)
    99.999% <= 1.271 milliseconds (cumulative count 9999926)
    100.000% <= 1.343 milliseconds (cumulative count 9999965)
    100.000% <= 1.391 milliseconds (cumulative count 9999981)
    100.000% <= 1.463 milliseconds (cumulative count 9999992)
    100.000% <= 2.543 milliseconds (cumulative count 9999996)
    100.000% <= 2.583 milliseconds (cumulative count 9999998)
    100.000% <= 2.607 milliseconds (cumulative count 9999999)
    100.000% <= 2.655 milliseconds (cumulative count 10000000)
    100.000% <= 2.655 milliseconds (cumulative count 10000000)

    Cumulative distribution of latencies:
    89.812% <= 0.103 milliseconds (cumulative count 8981182)
    99.484% <= 0.207 milliseconds (cumulative count 9948387)
    99.591% <= 0.303 milliseconds (cumulative count 9959097)
    99.653% <= 0.407 milliseconds (cumulative count 9965254)
    99.715% <= 0.503 milliseconds (cumulative count 9971516)
    99.784% <= 0.607 milliseconds (cumulative count 9978430)
    99.849% <= 0.703 milliseconds (cumulative count 9984855)
    99.909% <= 0.807 milliseconds (cumulative count 9990856)
    99.952% <= 0.903 milliseconds (cumulative count 9995162)
    99.980% <= 1.007 milliseconds (cumulative count 9998011)
    99.993% <= 1.103 milliseconds (cumulative count 9999302)
    99.998% <= 1.207 milliseconds (cumulative count 9999829)
    99.999% <= 1.303 milliseconds (cumulative count 9999947)
    100.000% <= 1.407 milliseconds (cumulative count 9999985)
    100.000% <= 1.503 milliseconds (cumulative count 9999995)
    100.000% <= 3.103 milliseconds (cumulative count 10000000)

    Summary:
      throughput summary: 1140771.25 requests per second
      latency summary (msec):
              avg       min       p50       p95       p99       max
            0.077     0.008     0.079     0.119     0.159     2.655

Appendix
--------

Hardware
~~~~~~~~

.. code-block:: text

   Intel(R) Xeon(R) Platinum 8260 CPU @ 2.40GHz
   Mellanox ConnectX-5 25Gbps

Results with Kernel TCP
~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: text

   # taskset -c 1-20 redis-benchmark -h 192.168.1.10 --threads 20 -c 100 -t get -n 10000000
   ====== GET ======
     10000000 requests completed in 47.44 seconds
     100 parallel clients
     3 bytes payload
     keep alive: 1
     host configuration "save": 3600 1 300 100 60 10000
     host configuration "appendonly": no
     multi-thread: yes
     threads: 20

   Latency by percentile distribution:
   0.000% <= 0.047 milliseconds (cumulative count 1)
   50.000% <= 0.399 milliseconds (cumulative count 5397185)
   75.000% <= 0.519 milliseconds (cumulative count 7518625)
   87.500% <= 0.607 milliseconds (cumulative count 8779787)
   93.750% <= 0.751 milliseconds (cumulative count 9384364)
   96.875% <= 0.783 milliseconds (cumulative count 9748247)
   98.438% <= 0.799 milliseconds (cumulative count 9852298)
   99.219% <= 0.823 milliseconds (cumulative count 9928968)
   99.609% <= 0.847 milliseconds (cumulative count 9963131)
   99.805% <= 0.887 milliseconds (cumulative count 9982340)
   99.902% <= 0.959 milliseconds (cumulative count 9990268)
   99.951% <= 1.079 milliseconds (cumulative count 9995194)
   99.976% <= 1.199 milliseconds (cumulative count 9997680)
   99.988% <= 1.327 milliseconds (cumulative count 9998830)
   99.994% <= 1.487 milliseconds (cumulative count 9999405)
   99.997% <= 1.655 milliseconds (cumulative count 9999702)
   99.998% <= 1.855 milliseconds (cumulative count 9999849)
   99.999% <= 2.135 milliseconds (cumulative count 9999924)
   100.000% <= 2.303 milliseconds (cumulative count 9999962)
   100.000% <= 2.511 milliseconds (cumulative count 9999981)
   100.000% <= 2.607 milliseconds (cumulative count 9999991)
   100.000% <= 2.639 milliseconds (cumulative count 9999996)
   100.000% <= 2.647 milliseconds (cumulative count 9999998)
   100.000% <= 2.663 milliseconds (cumulative count 10000000)
   100.000% <= 2.663 milliseconds (cumulative count 10000000)

   Cumulative distribution of latencies:
   0.006% <= 0.103 milliseconds (cumulative count 593)
   0.155% <= 0.207 milliseconds (cumulative count 15510)
   1.130% <= 0.303 milliseconds (cumulative count 112989)
   61.612% <= 0.407 milliseconds (cumulative count 6161174)
   74.006% <= 0.503 milliseconds (cumulative count 7400583)
   87.798% <= 0.607 milliseconds (cumulative count 8779787)
   90.085% <= 0.703 milliseconds (cumulative count 9008465)
   98.855% <= 0.807 milliseconds (cumulative count 9885486)
   99.852% <= 0.903 milliseconds (cumulative count 9985242)
   99.927% <= 1.007 milliseconds (cumulative count 9992734)
   99.959% <= 1.103 milliseconds (cumulative count 9995868)
   99.978% <= 1.207 milliseconds (cumulative count 9997760)
   99.987% <= 1.303 milliseconds (cumulative count 9998661)
   99.991% <= 1.407 milliseconds (cumulative count 9999141)
   99.994% <= 1.503 milliseconds (cumulative count 9999441)
   99.996% <= 1.607 milliseconds (cumulative count 9999639)
   99.998% <= 1.703 milliseconds (cumulative count 9999762)
   99.998% <= 1.807 milliseconds (cumulative count 9999822)
   99.999% <= 1.903 milliseconds (cumulative count 9999873)
   99.999% <= 2.007 milliseconds (cumulative count 9999898)
   99.999% <= 2.103 milliseconds (cumulative count 9999918)
   100.000% <= 3.103 milliseconds (cumulative count 10000000)

   Summary:
     throughput summary: 210774.81 requests per second
     latency summary (msec):
             avg       min       p50       p95       p99       max
           0.454     0.040     0.399     0.767     0.815     2.663
