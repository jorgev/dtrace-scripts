#!/usr/sbin/dtrace -s

pid$1::RapidPoller??PollLoop():720
{
	printf("%Y: %s %s", walltimestamp, execname, copyinstr(arg0));
}

