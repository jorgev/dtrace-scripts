syscall::open:entry /execname=="nobud"/
{
	printf("%s %s",execname,copyinstr(arg0));
}

