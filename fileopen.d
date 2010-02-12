#!/usr/sbin/dtrace -s

syscall::open:entry
{
	printf("%s %s",execname,copyinstr(arg0));
}

