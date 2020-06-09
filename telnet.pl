#!/usr/bin/perl -w
use warnings;
use strict;
#
# what kind of krazy hardening process removes telnet?
#
#
# TODO:
# - allow disabling the menu escape code
# - Telnet::Connection local_raw controls the handling of all of "signals",
#   "line_mode" and "NL to CR" - possibly need to break that out


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
    return $self->{flags}{WILL}{OPT_ECHO()};
}

package Telnet::Connection;
use warnings;
use strict;

use Socket;
use FileHandle;
use IO::Select;

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
    $self->{select} = IO::Select->new();
    $self->{loop_stop} = 0;

    # Default to STDIN for local
    $self->local(\*STDIN);

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

sub menu {
    my $self = shift;
    $self->{menu} = shift;
}

sub menumode {
    my $self = shift;
    $self->{menumode} = shift;
}

sub loop_stop {
    my $self = shift;
    $self->{loop_stop} = 1;
}

sub remote {
    my $self = shift;
    my $set = shift;
    if (defined($set)) {
        $self->{remote} = $set;
        $self->{select}->add($set);
    }
    return $self->{remote};
}

sub local {
    my $self = shift;
    my $set = shift;
    if (defined($set)) {
        $self->{local} = $set;
        $self->{select}->add($set);
    }
    return $self->{local};
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
    $self->remote($fh);
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
    # we dont use $self->local(), because that is STDIN
    return _write(\*STDOUT, $buf);
}

sub write_remote {
    my $self = shift;
    my $buf = shift;
    return _write($self->remote(), $buf);
}

sub read_local {
    my $self = shift;
    my $buf;
    sysread($self->local(), $buf, 1024);
    return $buf;
}

sub read_remote {
    my $self = shift;
    my $buflen = shift || 1024;
    my $buf;
    sysread($self->remote(), $buf, $buflen);
    return $buf;
}

sub _loop_read_local {
    my $self = shift;

    my $buf = $self->read_local();
    length($buf) || return 0;

    # in menu mode, all local input goes to the menu
    if ($self->{menumode}) {
        $self->{menu}->add_buf($self, $buf);
        return 1;
    }

    # Again, we are cheating, since we assume interesting
    # things are only in the first byte.
    #
    # if buf contains local interrupt, handle that
    if (ord(substr($buf,0,1)) == 0x1d) {
        $self->menumode(1);
        $self->{menu}->add_buf($self, substr($buf,1));
        return 1;
    }

    # Ensure we send CR to remote
    if ($self->{local_raw} && substr($buf,0,1) eq "\n") {
        substr($buf,0,1) = "\r";
    }

    $self->write_remote($buf) || return 0;
    return 1;
}

sub _loop_read_remote {
    my $self = shift;

    my $buf = $self->read_remote();
    length($buf) || return 0;

    $buf = $self->{options}->parse($buf);
    my $reply = $self->{options}->get_reply();
    if ($reply) {
        $self->write_remote($reply) || return 0;
    }

    # After processing options, check if the Echo is now defined
    # Kind of a hack, but if the far end is echoing, we should
    # send all chars to it
    if (!defined($self->{local_raw}) && $self->{options}->Echo()) {
        ReadMode('raw');
        $self->{local_raw} = 1;
    }

    $self->write_local($buf) || return 0;
    return 1;
}

sub loop {
    my $self = shift;

    if ($self->{local_raw}) {
        ReadMode('raw');
    }

    # Loop, reading from one socket and writing to the other like a good
    # proxy program
    LOOP:
    while(!$self->{loop_stop}) {
        if ($self->{menumode}) {
            $self->{menu}->prompt($self);
        }

        $! = 0;
        my @can_r = $self->{select}->can_read(10);
        if (scalar(@can_r)==0) {
            if ($! != 0) {
                # an error occured
                last LOOP;
            }
        }

        for my $fh (@can_r) {
            if ($fh == $self->local()) {
                # reading from local user
                $self->_loop_read_local() || last LOOP;
            }

            if ($fh == $self->remote()) {
                # reading from network
                $self->_loop_read_remote() || last LOOP;
            }
        }
    }
    ReadMode('restore');
    return 0;
}

package Menu;
use warnings;
use strict;

sub new {
    my $class = shift;
    my $self = {};
    bless $self, $class;
    $self->{buf} = '';
    $self->{need_prompt} = 0;
    $self->register('help', \&_help);
    $self->register('quit', \&_quit);
    $self->register('q', \&_quit);
    return $self;
}

# Add some bytes to the buffer to be processed, possibly causing actions
sub add_buf {
    my $self = shift;
    my $conn = shift;
    my $buf = shift;

    for my $ch (split(//, $buf)) {
        if ($conn->{local_raw}) {
            # need to echo
            $conn->write_local($ch);
        }

        if ($ch eq "\x08" || $ch eq "\x7f") {
            # we only get backspace in local raw mode
            $conn->write_local(" \x08");
            substr($self->{buf}, -1,1,'');
            next;
        }

        if ($ch eq "\r" || $ch eq "\n") {
            my $command = $self->{buf};
            $self->{buf} = '';
            $self->command($conn, $command);
            next;
        }

        # TODO:
        # - could try to handle cmdline history etc too..

        $self->{buf} .= $ch;
    }

    if (length($self->{buf}) == 0) {
        $self->{need_prompt} = 1;
    }
}

sub prompt {
    my $self = shift;
    my $conn = shift;

    if ($self->{need_prompt}==1) {
        $conn->write_local("telnet.py> ");
        $self->{need_prompt} = 0;
    }
}

sub command {
    my $self = shift;
    my $conn = shift;
    my $line = shift;

    if (!$line) {
        $conn->menumode(0);
        return;
    }

    # TODO:
    # - parse into command and args

    if (!defined($self->{entries}{$line})) {
        $conn->write_local("Invalid command: ".$line."\n");
        return;
    }

    $self->{entries}->{$line}($self,$conn);
}

sub register {
    my $self = shift;
    my $name = shift;
    my $func = shift;

    $self->{entries}{$name} = $func;
}

sub _help {
    my $menu = shift;
    my $conn = shift;

    my $buf = '';
    $buf .= "Commands:\n\n";
    for my $name (sort(keys(%{$menu->{entries}}))) {
        $buf .= $name . "\n";
    }
    $conn->write_local($buf);
}

sub _quit {
    my $menu = shift;
    my $conn = shift;

    $conn->loop_stop();
}


package main;
use warnings;
use strict;

use FileHandle;

sub menu_send_chars_check {
    my $menu = shift;
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

sub menu_send_text_check {
    my $menu = shift;
    my $conn = shift;
    $conn->write_local("maxbuf? ");
    my $maxbuf = $conn->read_local();
    chomp($maxbuf);
    if (!$maxbuf) {
        $maxbuf = 28;
        $conn->write_local("maxbuf=$maxbuf\n");
    }

    $conn->write_local("filename? ");
    my $filename = $conn->read_local();
    chomp($filename);

    my $fh = FileHandle->new($filename, "r");
    if (!defined($fh)) {
        $conn->write_local("Could not open\n");
        return 1;
    }

    $conn->write_local("---sending---\n");
    while (<$fh>) {
        my $retries = 0;
RETRY:
        $retries ++;
        if ($retries > 3) {
            $conn->write_local("---TOOMANY---n");
            return 1;
        }
        my $tosend = $_;
        chomp($tosend);

        while (length($tosend)) {
            my $send = substr($tosend, 0, $maxbuf);
            $conn->write_remote($send) || return 0;

            my $tocheck = $send;
            while (length($tocheck)) {
                my $rx = $conn->read_remote();
                $conn->write_local($rx);

                # HACK
                # FIXME - it does wierd when line is >80char
                while (substr($rx, 0, 1) eq "\r") { $rx = substr($rx, 1); }
                while (substr($rx, 0, 1) eq "\x00") { $rx = substr($rx, 1); }
                while (substr($rx, 0, 1) eq "\n") { $rx = substr($rx, 1); }

                my $check = substr($tocheck, 0, length($rx));
                if ($rx ne $check) {
                    $conn->write_local("---BAD:$check---\n");

                    goto RETRY;
                    return 1;
                }
                $tocheck = substr($tocheck, length($rx));
            }

            $tosend = substr($tosend, length($send));
        }

        my $ch = "\r";
        $conn->write_remote($ch);
READ:
        my $rx = $conn->read_remote(1);
        if (length($rx) == 0) {
            $conn->write_local("---ZEROREAD---\n");
            return 1;
        }
        if (length($rx) == 1 && ord($rx) == 0) {
            # sometimes, it sends us nuls..
            goto READ;
        }

        $conn->write_local($rx);

        if ($ch ne $rx) {
            $conn->write_local("---MISMATCH---\n");
            return 1;
        }

        if ($ch eq "\r") {
            $ch = "\n";
            goto READ;
        }

    }
    $conn->write_local("---done---\n");
    return 1;
}

sub main {
    my $host = shift @ARGV || die "Remote host not supplied";;
    my $port = shift @ARGV || 23;

    my $menu = Menu->new();
    $menu->register('send_chars_check', \&menu_send_chars_check);
    $menu->register('send_text_check', \&menu_send_text_check);

    my $conn = Telnet::Connection->new();
    $conn->menu($menu);
    $conn->hostname($host);
    $conn->port($port);
    $conn->connect();

    $conn->loop();
    exit(0);
}
unless(caller) { main(); }
