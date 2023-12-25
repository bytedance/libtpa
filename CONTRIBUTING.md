# Contribution

You can either send us a GitHub pull request, or send patches to the [mailing
list](https://groups.google.com/g/libtpa), libtpa@googlegroups.com. Note that
it's encouraged to send emails though.

# Coding Style
Libtpa basically follows the [DPDK coding style](https://doc.dpdk.org/guides/contributing/coding_style.html),
with a noticeable exception on function definition: the function type
should not be on a line by itself. For example:

```c
static char *function(int a1, int a2, float fl, int a4)
{
```

# About the next Branch

The development of libtpa normally lands to the next branch first. You
should make patches based on this branch for contribution.

That also means the next branch is meant to be unstable. Rebases may even
happen frequently there.
