#!/usr/bin/perl -w
use strict;
#
# what kind of krazy hardening process removes telnet?
#

use Socket;
use FileHandle;

my $host = $ARGV[0];
my $port = $ARGV[1];

$host || die "Remote host not supplied";
$port || ($port=23);

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

# These hashes hold the source and destination file handles for the
# file numbers we use in select()
my (%rfds, %wfds);
my ($stdin_fileno, $sock_fileno) = (fileno(*STDIN), fileno($fh));
$rfds{$stdin_fileno} = \*STDIN;
$rfds{$sock_fileno}  = $fh;
$wfds{$stdin_fileno} = $fh;
$wfds{$sock_fileno}  = \*STDOUT;

# Set up for select
my $rin = "";
vec($rin, $stdin_fileno, 1) = 1;
vec($rin,  $sock_fileno, 1) = 1;
my $ein = $rin;

my ($rout, $eout);

# Loop, reading from one socket and writing to the other like a good
# proxy program
SELECT: while(1) {
  my $nfound = select($rout = $rin, undef, $eout = $ein, 1024);
  $nfound || next SELECT;

  (vec($eout, $stdin_fileno, 1) || vec($eout, $sock_fileno, 1)) && last SELECT;

  foreach my $key (keys(%rfds)) {
    if(vec($rout, $key, 1)) {
      do_copy($rfds{$key}, $wfds{$key}) || last SELECT;
    }
  }
  # next SELECT;
}

$fh->close();

exit(0);

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

