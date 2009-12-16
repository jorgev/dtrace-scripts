#!/usr/sbin/dtrace -s

pid$1::RapidPoller??PollLoop():761
{
	printf("%s %s",execname,copyinstr(arg0));
}

