#!/bin/bash
#
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021, ByteDance Ltd. and/or its Affiliates
# Author: Yuanhan Liu <liuyuanhan.131@bytedance.com>

set_test_version()
{
	[ -n "$(git tag --points-at HEAD)" ] && {
		echo "warn: we already got a tag on head commit: $(git tag --points-at HEAD)" 1>&2
		return
	}

	major=$(date +'%Y%m%d')
	minor=0
	while true; do
		tag="t$major.$minor"
		[ -z "$(git tag -l $tag)" ] && break

		let minor+=1
	done

	echo ":: set new test tag: $tag" 1>&2

	git tag $tag
}

is_dev_branch()
{
	[ $(git rev-parse --abbrev-ref HEAD) = "next" ]
}

git status 1>/dev/null 2>&1 || {
	if [ -n "$TPA_VERSION" ]; then
		echo v$TPA_VERSION
	else
		echo "none"
	fi
	exit
}

if [ "$BUILD_MODE" = 'test' ]; then
	set_test_version
	desc_arg="--tags"
fi

version=$(git describe $desc_arg --dirty=+)
is_dev_branch && version="$version-dev"
[ -n "$TPA_SUB_VERSION" ] && version="$version-$TPA_SUB_VERSION"
echo $version
