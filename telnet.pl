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

# Copy stuff from one filehandle to another
sub do_copy {
  my($pIn, $pOut) = @_;
  my ($buf, $len, $offset, $br);
  
  $len = sysread($$pIn, $buf, 1024);
  $len || return 0;

  $offset = 0;
  while($len)  {
    $br = syswrite($$pOut, $buf, $len, $offset);
    $br || return 0;
    $offset += $br;
    $len    -= $br;
  }
  return 1;
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

            syswrite_all(\*STDOUT, $buf) || last SELECT;
        }
    }

    $fh->close();

    exit(0);
}
unless(caller) { main(); }
