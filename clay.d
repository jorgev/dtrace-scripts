#!/usr/sbin/dtrace -s

/* I wrote this probe for my buddy Clay, who wanted to track all reads/writes
 * from a particular process with offset into the file and byte count
 */

#pragma D option quiet

dtrace:::BEGIN
{
	printf("O %12s %8s %s\n", "OFFSET", "COUNT", "FILENAME");
}

fbt::hfs_vnop_read:entry
/execname == "pdiFilterTest"/
{
	this->read = (struct vnop_read_args *)arg0;
	printf("R %12d %8d %s\n", this->read->a_uio->uio_offset, this->read->a_uio->uio_resid_64, stringof(this->read->a_vp->v_name));
}

fbt::hfs_vnop_write:entry
/execname == "pdiFilterTest"/
{
	this->write = (struct vnop_write_args *)arg0;
	printf("W %12d %8d %s\n", this->write->a_uio->uio_offset, this->write->a_uio->uio_resid_64, stringof(this->write->a_vp->v_name));
}
