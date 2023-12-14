#!/bin/bash
#
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021-2023, ByteDance Ltd. and/or its Affiliates
# Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>

apt update

pkg_list="libnl-3-dev
	  libnl-route-3-dev
	  libnuma-dev
	  libpcap-dev
	  pkg-config
	  net-tools
	  ethtool"

deb_version=$(awk -F '.' '{print $1}' /etc/debian_version)
[ "$deb_version" -eq 12 ] && pkg_list+=" libsystemd-dev"

apt install -y $pkg_list

for arg in $@; do
	case $arg in
	"--with-meson")
		apt install -y python3-pip
		python3 -m pip install meson==0.56.2
		python3 -m pip install ninja==1.10
		python3 -m pip install pyelftools
		;;

	"--with-sphinx")
		apt install -y python3-pip python3-sphinx
		python3 -m pip install sphinx_rtd_theme
		;;
	esac
done
