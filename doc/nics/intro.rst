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
that doesn't require SR-IOV.

This document lists the NICs that Libtpa currently supports, with some
extra information you may need to set it up correctly for enabling Libtpa.

You might want to try the :ref:`AF_XDP<nic_xdp>` virtual NIC if you
don't have the NICs listed here.
This will give you a quick glimpse of what Libtpa looks like.
