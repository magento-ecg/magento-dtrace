#!/usr/sbin/dtrace  -s


#pragma D option bufsize=120m
#pragma D option quiet

dtrace:::BEGIN {
    /* indent depth */
    depth = 0;
}
php_request_startup:
{
    ts=timestamp;
    printf("start: pid=%d, fn=%s,uri=%s, method=%s\n",pid, copyinstr(arg0), copyinstr(arg1),copyinstr(arg2));
    self->mpid=pid;
}

php*:::function-entry
{
    printf("%*s",depth,"");
    printf("=>%s::%s\t(%s:%d,%dms)\n",copyinstr(arg3),copyinstr(arg0),copyinstr(arg1),arg2,(timestamp-ts)/1000000);
    depth += 2;
}


php*:::function-return
{
    depth -= 2;
    printf("%*s",depth,"");
    printf("<=%s::%s\t(%s:%d,%dms)\n",copyinstr(arg3),copyinstr(arg0),copyinstr(arg1),arg2,(timestamp-ts)/1000000);

}

/* get statistic about HTTPD requests from USDT probe */
httpd*:::request-done
/ self->mpid == pid /
{
	printf("Request finished in %dms\nstat: %3d %16s:%-5d %16s:%-5d  %-6s %s\n",
	    (timestamp-ts)/1000000,
	    args[1]->rq_status,
	    args[0]->ci_local, args[1]->rq_lport, args[0]->ci_remote,
	    args[1]->rq_rport, args[1]->rq_method, args[1]->rq_uri);
	self->mpid = 0; /* reset pid after reply */
}

