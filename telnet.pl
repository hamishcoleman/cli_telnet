#!/usr/bin/perl -w
use strict;
#
# what kind of krazy hardening process removes telnet?
#

use Socket;
use FileHandle;

sub do_connect {
    my $host = shift;
    my $port = shift;

    my $ipaddr   = inet_aton($host);
    my $sockaddr = sockaddr_in($port, $ipaddr);
    my $proto = getprotobyname('tcp');
    my $fh    = new FileHandle;

    if (!socket($fh, PF_INET, SOCK_STREAM, $proto)) {
            die "socket error";
    }
    if (!connect($fh, $sockaddr)) {
            die "connect error";
    }
    $fh->autoflush(1);
    return $fh;
}

sub syswrite_all {
    my $fh = shift;
    my $buf = shift;

    my $len = length($buf);
    my $offset = 0;
    while($len)  {
        my $written = syswrite($$fh, $buf, $len, $offset);
        $written || return 0;
        $offset += $written;
        $len    -= $written;
    }
    return 1;
}

sub handle_telnet_options {
    my $fh = shift;
    my $buf = shift;
    # A really simple option processor.  Some servers just dont continue on
    # to sending normal data until you complete a negotiation..
    #
    # The defaults are simple.
    # Any request from them to DO gets a WONT reply, but any info that they
    # WILL gets a DO reply
    #
    # There are a couple of options we do want to handle though

    while (ord(substr($buf,0,1)) == 0xff) {
        my $cmd = ord(substr($buf,1,1));
        my $option = ord(substr($buf,2,1));
        my $prefixsize = 2;
        if ($cmd == 253) {
            # They are asking us to "DO (option code)"
            $prefixsize ++;

            my $reply;
            if ($option == 0x18) {
                # Will Terminal Type
                $reply = "\xff" . chr(251) . chr($option);
            } else {
                # just say we "WON'T (option code)"
                $reply = "\xff" . chr(252) . chr($option);
            }
            syswrite($$fh, $reply);
        } elsif ($cmd == 251) {
            # They are telling they "WILL (option code)"
            $prefixsize ++;

            # Just agree with "DO (option code)"
            my $reply = "\xff" . chr(253) . chr($option);
            syswrite($$fh, $reply);
        } elsif ($cmd == 250) {
            # suboption start
            if ($option == 0x18) {
                my $param = ord(substr($buf,3,1));
                $prefixsize ++;

                if ($param != 1) {
                    ...
                }
                # hardcode the terminal type
                my $reply = "\xff\xfa\x18\x00xterm\xff\xf0";
                syswrite($$fh, $reply);
            } else {
                ...
            }
        }
        $buf = substr($buf, $prefixsize);
    }
    return $buf;
}

sub main {
    my $host = shift @ARGV || die "Remote host not supplied";;
    my $port = shift @ARGV || 23;

    my $fh = do_connect($host, $port);

    my $stdin_fileno = fileno(*STDIN);
    my $sock_fileno = fileno($fh);

    # Set up for select
    my $readfds_init = "";
    vec($readfds_init, $stdin_fileno, 1) = 1;
    vec($readfds_init,  $sock_fileno, 1) = 1;
    my $exceptfds_init = $readfds_init;

    # Loop, reading from one socket and writing to the other like a good
    # proxy program
    SELECT:
    while(1) {
        my $readfds = $readfds_init;
        my $exceptfds = $exceptfds_init;
        my $nfound = select($readfds, undef, $exceptfds, 1024);
        if ($nfound == 0) {
            next;
        }

        # if either these have their error flag set, exit
        if (vec($exceptfds, $stdin_fileno, 1)) { last SELECT; }
        if (vec($exceptfds, $sock_fileno, 1)) { last SELECT; }

        if (vec($readfds, $stdin_fileno, 1)) {
            # reading from user
            my $buf;
            sysread(\*STDIN, $buf, 1024);
            length($buf) || last SELECT;

            # if buf contains local interrupt, handle that

            syswrite_all($fh, $buf) || last SELECT;
        }
        if (vec($readfds, $sock_fileno, 1)) {
            # reading from network
            my $buf;
            sysread($fh, $buf, 1024);
            length($buf) || last SELECT;

            # if buf contains telnet options, handle them
            # (cheat by assuming they are all at the start of a packet)
            if (ord(substr($buf,0,1)) == 0xff) {
                $buf = handle_telnet_options($fh, $buf);
            }

            syswrite_all(\*STDOUT, $buf) || last SELECT;
        }
    }

    $fh->close();

    exit(0);
}
unless(caller) { main(); }
