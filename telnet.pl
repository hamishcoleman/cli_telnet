#!/usr/bin/perl -w
use warnings;
use strict;
#
# what kind of krazy hardening process removes telnet?
#

package Telnet::Options;
use warnings;
use strict;

sub new {
    my $class = shift;
    my $self = {};
    bless $self, $class;
    $self->{buf} = '';
    $self->{bufpos} = 0;
    $self->{tosend} = '';
    return $self;
}

sub _bufset {
    my $self = shift;
    $self->{buf} = shift;
    $self->{bufpos} = 0;
}

sub _bufinc {
    my $self = shift;
    my $inc = shift || 1;
    $self->{bufpos} += $inc;
}

sub _bufpeek {
    my $self = shift;
    return ord(substr($self->{buf},$self->{bufpos},1));
}

sub _bufget {
    my $self = shift;
    my $ch = $self->_bufpeek();
    $self->_bufinc();
    return $ch;
}

sub _bufret {
    my $self = shift;
    return substr($self->{buf}, $self->{bufpos});
}

sub _send {
    my $self = shift;
    for my $i (@_) {
        $self->{tosend} .= chr($i);
    }
}

sub _sendstr {
    my $self = shift;
    $self->{tosend} .= shift;
}

sub get_reply {
    my $self = shift;
    my $reply = $self->{tosend};
    $self->{tosend} = '';
    return $reply;
}

use constant {
    SUBEND   => 240,
    SUBBEGIN => 250,
    WILL     => 251,
    WONT     => 252,
    DO       => 253,
    DONT     => 254,
    IAC      => 255,

    OPT_ECHO     => 1,
    OPT_TERMTYPE => 24,
};

sub _sub_termtype {
    my $self = shift;
    my $cmd = shift;

    if ($cmd != 1) {
        # 1 == SEND;
        warn("SUB TERM-TYPE $cmd");
        ...;
    }

    # hardcode the terminal type
    $self->_send(IAC, SUBBEGIN, OPT_TERMTYPE, 0); # 0 == IS
    $self->_sendstr('xterm');
    $self->_send(IAC, SUBEND);
}

sub _IAC_250 { # SUBBEGIN
    my $self = shift;
    my $option = $self->_bufget();
    my @bytes;

    # We assume that no sequence spans a single buffer
    while ($self->_bufpeek() != IAC) {
        push @bytes, $self->_bufget();
    }
    $self->_bufget(); # Consume the IAC

    # We assume no IAC occurs within the SUB Begin/End block
    my $end = $self->_bufget();
    if ($end != SUBEND) {
        warn("Got IAC $end during SB block");
        ...;
    }

    if ($option == OPT_TERMTYPE) {
        $self->_sub_termtype(@bytes);
    } else {
        warn("OPT $option");
        ...;
    }
}

sub _IAC_251 { # WILL
    my $self = shift;
    my $option = $self->_bufget();

    $self->_send(IAC, DO, $option);
    $self->{flags}{WILL}{$option} = 1;
}

sub _IAC_253 {  # DO
    my $self = shift;
    my $option = $self->_bufget();

    my $reply = WONT;
    if ($option == OPT_TERMTYPE) {
        $reply = WILL;
    }

    $self->_send(IAC, $reply, $option);
}

sub parse {
    my $self = shift;
    $self->_bufset(shift);

    # Assume no midstream IAC sequences - just look at the first byte
    # We also assume that no sequence spans a single buffer

    while ($self->_bufpeek() == IAC) {
        $self->_bufget(); # Consume the IAC
        my $cmd = $self->_bufget();
        my $method = "_IAC_$cmd";

        if ($self->can($method)) {
            $self->$method();
        } else {
            warn("CMD $cmd");
            ...
        }
    }
    return $self->_bufret();
}

sub Echo {
    my $self = shift;
    return $self->{flags}{WILL}{1};
}

package Telnet::Connection;
use warnings;
use strict;

use Socket;
use FileHandle;

# FIXME: install a whole library for one function?
# TODO:
# - allow missing Term::Readkey library
use Term::ReadKey;

sub new {
    my $class = shift;
    my $self = {};
    bless $self, $class;
    $self->{options} = Telnet::Options->new();
    $self->{local_raw} = undef;
    return $self;
}

sub hostname {
    my $self = shift;
    $self->{host} = shift;
}

sub port {
    my $self = shift;
    $self->{port} = shift;
}

sub connect {
    my $self = shift;

    my $ipaddr   = inet_aton($self->{host});
    my $sockaddr = sockaddr_in($self->{port}, $ipaddr);
    my $proto = getprotobyname('tcp');
    my $fh    = new FileHandle;

    if (!socket($fh, PF_INET, SOCK_STREAM, $proto)) {
            die "socket error";
    }
    if (!connect($fh, $sockaddr)) {
            die "connect error";
    }
    $fh->autoflush(1);

    my $stdin_fileno = fileno(*STDIN);
    my $sock_fileno = fileno($fh);

    # Set up for select
    my $readfds_init = "";
    vec($readfds_init, $stdin_fileno, 1) = 1;
    vec($readfds_init,  $sock_fileno, 1) = 1;

    $self->{readfds_init} = $readfds_init;
    $self->{remote} = $fh;
}

# Try hard to write the whole buf
sub _write {
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

sub write_local {
    my $self = shift;
    my $buf = shift;
    return _write(\*STDOUT, $buf);
}

sub write_remote {
    my $self = shift;
    my $buf = shift;
    return _write($self->{remote}, $buf);
}

sub read_local {
    my $self = shift;
    my $buf;
    sysread(\*STDIN, $buf, 1024);
    return $buf;
}

sub read_remote {
    my $self = shift;
    my $buflen = shift || 1024;
    my $buf;
    sysread($self->{remote}, $buf, $buflen);
    return $buf;
}

sub loop {
    my $self = shift;

    if ($self->{local_raw}) {
        ReadMode('raw');
    }

    # TODO:
    # - repeating ourselves from self->connect()
    my $stdin_fileno = fileno(*STDIN);
    my $sock_fileno = fileno($self->{remote});

    # Loop, reading from one socket and writing to the other like a good
    # proxy program
    while(1) {
        my $readfds = $self->{readfds_init};
        my $exceptfds = $self->{readfds_init};

        my $nfound = select($readfds, undef, $exceptfds, 1024);
        if ($nfound == 0) {
            next;
        }

        # if either these have their error flag set, exit
        last if (vec($exceptfds, $stdin_fileno, 1));
        last if (vec($exceptfds, $sock_fileno, 1));

        # reading from user
        if (vec($readfds, $stdin_fileno, 1)) {
            my $buf = $self->read_local();
            length($buf) || last;

            # Again, we are cheating, since we assume interesting things are
            # only in the first byte
            #
            # TODO:
            # - maybe allow disabling the escape code
            #
            # if buf contains local interrupt, handle that
            if (ord(substr($buf,0,1)) == 0x1d) {
                ReadMode('restore');
                # return to user code to handle the escape sequence
                # (Note that we throw away the whole buffer here)
                return 1;
            }

            # TODO:
            # - local_raw changes all of "signals", "line_mode" and "NL to CR"
            if ($self->{local_raw} && substr($buf,0,1) eq "\n") {
                substr($buf,0,1) = "\r";
            }

            $self->write_remote($buf) || last;
        }

        # reading from network
        if (vec($readfds, $sock_fileno, 1)) {
            my $buf = $self->read_remote();
            length($buf) || last;

            $buf = $self->{options}->parse($buf);
            my $reply = $self->{options}->get_reply();
            if ($reply) {
                $self->write_remote($reply) || last;
            }

            # After processing options, check if the Echo is now defined
            # Kind of a hack, but if the far end is echoing, we should send
            # all chars to it
            if (!defined($self->{local_raw}) && $self->{options}->Echo()) {
                ReadMode('raw');
                $self->{local_raw} = 1;
            }

            $self->write_local($buf) || last;
        }
    }
    ReadMode('restore');
    return 0;
}

package main;
use warnings;
use strict;

use FileHandle;

my $menu_entries;

sub menu_send_check_echo {
    my $conn = shift;
    $conn->write_local("filename? ");
    my $filename = $conn->read_local();
    chomp($filename);

    my $fh = FileHandle->new($filename, "r");
    if (!defined($fh)) {
        $conn->write_local("Could not open\n");
        return 1;
    }

    $conn->write_local("---sending---\n");
    while (!$fh->eof()) {
        my $ch = $fh->getc();
        last if (!defined($ch));

        # HACK!
        if ($ch eq "\n") {
            $ch = "\r";
        }

        $conn->write_remote($ch) || return 0;
READ:
        my $rx = $conn->read_remote(1);
        if (length($rx) == 1 && ord($rx) == 0) {
            # sometimes, it sends us nuls..
            goto READ;
        }

        if (length($rx) == 0) {
            $conn->write_local("---ZEROREAD---\n");
            return 1;
        }
        $conn->write_local($rx);

        # HACK!
        if ($ch eq "\r") {
            $ch = "\n";
            goto READ;
        }

        if ($ch ne $rx) {
            $conn->write_local("---MISMATCH---\n");
            return 1;
        }
    }
    $conn->write_local("---done---\n");
    return 1;
}

sub menu_help {
    my $conn = shift;

    my $buf = '';
    $buf .= "Commands:\n\n";
    for my $name (sort(keys(%{$menu_entries}))) {
        $buf .= $name . "\n";
    }
    $conn->write_local($buf);
    return 1;
}

sub menu_quit {
    return 0;
}

$menu_entries = {
    send_check_echo => \&menu_send_check_echo,
    help => \&menu_help,
    quit => \&menu_quit,
};
$menu_entries->{'?'} = $menu_entries->{help};
$menu_entries->{h} = $menu_entries->{help};
$menu_entries->{q} = $menu_entries->{quit};

sub menu {
    my $conn = shift;
    $conn->write_local("telnet.pl> ");
    my $buf = $conn->read_local();
    chomp $buf;

    if (!$buf) {
        # return to telnet session
        return 1;
    }

    if (defined($menu_entries->{$buf})) {
        my $result = $menu_entries->{$buf}($conn);
        if ($result == 0) {
            # request exit program
            return 0;
        }
    } else {
        $conn->write_local("Invalid command: ".$buf."\n");
    }

    # Tail recurse for more commands
    return menu($conn);
}


sub main {
    my $host = shift @ARGV || die "Remote host not supplied";;
    my $port = shift @ARGV || 23;

    my $conn = Telnet::Connection->new();
    $conn->hostname($host);
    $conn->port($port);
    $conn->connect();

    while(1) {
        if ($conn->loop() == 0) {
            last;
        }

        if (menu($conn) == 0) {
            last;
        }
    }

    exit(0);
}
unless(caller) { main(); }
