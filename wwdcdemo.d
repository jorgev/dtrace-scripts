#!/usr/sbin/dtrace -s

pid123:libBlack:black_box:entry
{
	@hits = count();
	@keys = quantize(arg0);
	self->entry_time = timestamp;
}

pid123:libBlack:black_box:return
{
	@rc[arg1] = count();
}
 
