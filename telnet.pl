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

package main;
use warnings;
use strict;

use Socket;
use FileHandle;

# FIXME: install a whole library for one function?
# TODO:
# - allow missing Term::Readkey library
use Term::ReadKey;

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

sub main {
    my $host = shift @ARGV || die "Remote host not supplied";;
    my $port = shift @ARGV || 23;

    my $fh = do_connect($host, $port);

    my $options = Telnet::Options->new();
    my $opt_echo = undef;

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

            # Again, we are cheating, since we assume interesting things are
            # only in the first byte
            #
            # if buf contains local interrupt, handle that
            if (ord(substr($buf,0,1)) == 0x1d) {
                # TODO:
                # - local menu
                last SELECT;
            } elsif ($opt_echo && substr($buf,0,1) eq "\n") {
                substr($buf,0,1) = "\r";
            }

            syswrite_all($fh, $buf) || last SELECT;
        }
        if (vec($readfds, $sock_fileno, 1)) {
            # reading from network
            my $buf;
            sysread($fh, $buf, 1024);
            length($buf) || last SELECT;

            $buf = $options->parse($buf);
            my $reply = $options->get_reply();
            if ($reply) {
                syswrite_all($fh, $reply) || last SELECT;
            }
            if (!defined($opt_echo) && $options->Echo()) {
                # Kind of a hack, but if the far end is echoing, we should send
                # all chars to it
                ReadMode('raw');
                $opt_echo = 1;
            }

            syswrite_all(\*STDOUT, $buf) || last SELECT;
        }
    }

    $fh->close();

    ReadMode(0);
    exit(0);
}
unless(caller) { main(); }
