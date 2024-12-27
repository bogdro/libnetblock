# LibNetBlock #

LibNetBlock - a library which blocks programs from accessing the network.

The function replacements in LibNetBlock return an error instead of calling
the original operating system functions which allow various kinds of network
access. Thus, access to the OS function is effectively blocked.

Read the info documentation (type `info doc/libnetblock.info`) to get more
information.

Project homepage: <https://libnetblock.sourceforge.io/>.

Author: Bogdan Drozdowski, bogdro (at) users . sourceforge . net

License: GPLv3+

## WARNING ##

The `dev` branch may contain code which is a work in progress and committed
just for tests. The code here may not work properly or even compile.

The `master` branch may contain code which is committed just for quality tests.

The tags, matching the official packages on SourceForge,
should be the most reliable points.
