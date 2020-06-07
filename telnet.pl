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

sub main {
    my $host = shift @ARGV || die "Remote host not supplied";;
    my $port = shift @ARGV || 23;

    my $fh = do_connect($host, $port);

    my $stdin_fileno = fileno(*STDIN);
    my $sock_fileno = fileno($fh);

    # Set up for select
    my ($rin, $rout, $ein, $eout);
    $rin = "";
    vec($rin, $stdin_fileno, 1) = 1;
    vec($rin,  $sock_fileno, 1) = 1;
    $ein = $rin;

    # Loop, reading from one socket and writing to the other like a good
    # proxy program
    SELECT:
    while(1) {
        my $nfound = select($rout = $rin, undef, $eout = $ein, 1024);
        if ($nfound == 0) {
            next;
        }

        # if either these have their error flag set, exit
        if (vec($eout, $stdin_fileno, 1)) { last SELECT; }
        if (vec($eout, $sock_fileno, 1)) { last SELECT; }

        if (vec($rout, $stdin_fileno, 1)) {
            # reading from user
            do_copy(\*STDIN, $fh) || last SELECT;
        }
        if (vec($rout, $sock_fileno, 1)) {
            # reading from network
            do_copy($fh, \*STDOUT) || last SELECT;
        }
    }

    $fh->close();

    exit(0);
}
unless(caller) { main(); }
