#!/usr/sbin/dtrace -s

/* I wrote this probe for my buddy Clay, who wanted to track all reads/writes
 * from a particular process with offset into the file and byte count
 */

#pragma D option quiet
#pragma D option defaultargs
#pragma D option switchrate=10hz

dtrace:::BEGIN
{
	printf("O %12s %8s %4s %s\n", "OFFSET", "COUNT", "MS", "FILENAME");
	min_ns = $1 * 1000000;
}

fbt::hfs_vnop_read:entry
/execname == "kernel_task"/
{
	this->read = (struct vnop_read_args *)arg0;
	self->path = this->read->a_vp->v_name;
	self->bytes = this->read->a_uio->uio_resid_64;
	self->offset = this->read->a_uio->uio_offset;
	self->start = timestamp;
}

fbt::hfs_vnop_write:entry
/execname == "kernel_task"/
{
	this->write = (struct vnop_write_args *)arg0;
	self->path = this->write->a_vp->v_name;
	self->bytes = this->write->a_uio->uio_resid_64;
	self->offset = this->write->a_uio->uio_offset;
	self->start = timestamp;
}

fbt::hfs_vnop_read:return,
fbt::hfs_vnop_write:return
/execname == "kernel_task" && self->path == "nvme.data" && self->start && (timestamp - self->start) >= min_ns/
{
	this->iotime = (timestamp - self->start) / 1000000;;
	this->dir = probefunc == "hfs_vnop_read" ? "R" : "W";
	printf("%s %12d %8d %4d %s\n", this->dir, self->offset, self->bytes, this->iotime,
			self->path != NULL ? stringof(self->path) : "<null>");
	self->path = 0;
	self->bytes = 0;
	self->offset = 0;
	self->start = 0;
}
