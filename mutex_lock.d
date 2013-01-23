#!/usr/sbin/dtrace -s

#pragma D option quiet

pid48220::pthread_mutex_lock:entry
/arg0 == $1/
{
    self->mutex = arg0;
    self->s = timestamp;
}

pid48220::pthread_cond_wait:entry
/arg1 == $1/
{
    self->mutex = arg1;
    self->s = timestamp;
}

pid48220::pthread_mutex_lock:return,
pid48220::pthread_cond_wait:return
/self->mutex == $1/
{
	printf("%10d %-20s 0x%016x %12d\n", tid, probefunc, self->mutex, (timestamp - self->s) / 1000000);
}
