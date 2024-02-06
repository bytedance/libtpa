..  SPDX-License-Identifier: BSD-3-Clause
    Copyright (c) 2021-2024, ByteDance Ltd. and/or its Affiliates
    Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>

.. _nic_guide:

Introduction
============

Due to the novel design of Libtpa, being able to coexist with the Linux
kernel networking stack, Libtpa requires NIC hardware feature called
`flow bifurcation <https://doc.dpdk.org/guides/howto/flow_bifurcation.html>`_.

Most modern NICs have flow bifurcation support with the help of SR-IOV.
But many require some internal DPDK/Linux patches (or even firmwares)
to satisfy the Libtpa needs.

On the other hand, Mellanox NIC has native flow bifurcation support
that doesn't require SR-IOV. More importantly, it doesn't require any
internal stuff. Libtpa works well with Mellanox NIC just with the
upstream DPDK.

Therefore, Libtpa currently only supports Mellanox NIC.
And you can follow :ref:`this page<nic_mlnx>` for the guide on how to
build Libtpa with Mellanox NICs.
