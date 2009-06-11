syscall::open:entry /execname=="nobuagent"/
{
	printf("%s %s",execname,copyinstr(arg0));
}

