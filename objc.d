#!/usr/sbin/dtrace -s

/*
 */

objc$target:CloudUploader:-uploadFile?:entry
{
	trace(execname);
}

