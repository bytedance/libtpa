..  SPDX-License-Identifier: BSD-3-Clause
    Copyright (c) 2023-2024, ByteDance Ltd. and/or its Affiliates
    Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>

.. _nic_mlnx:

Mellanox NICs
=============

Libtpa supports Mellanox NICs from ConnectX-4 to Connect-7.

To build Libtpa with Mellanox NICs, the Mellanox OFED has to be installed.
It can be downloaded from
`here <https://network.nvidia.com/products/infiniband-drivers/linux/mlnx_ofed/>`_.
Then run below command to install it::

    ./mlnxofedinstall --dpdk --upstream-libs
