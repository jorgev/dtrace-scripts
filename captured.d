#!/usr/sbin/dtrace -s

/*
 * This is an objective c probe for a project that i am working on.  Note that arg2 is actually
 * the first argument to the call, not the third.  arg0 is a this pointer, arg1 is a pointer to
 * _cmd, which is a selector.  The actual arguments follow from there.  In this case, the first
 * argument (arg2) is an NSString.  The actual string is a 17-byte offset from the address of
 * the NSString*, which may be subject to change at any time, of course.
 */

objc$target:CloudUploader:-uploadFile?:entry
{
	printf("%-16s %s", execname, copyinstr(arg2 + 17));
}

