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

sub copy_remote_rx {
    my ($self, $set) = @_;
    if (@_ == 2) {
        $self->{copy_remote_rx} = $set;
    }
    return $self->{copy_remote_rx};
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

    my $copy_remote_rx = $self->copy_remote_rx();
    if (defined($copy_remote_rx)) {
        $copy_remote_rx->remote_rx($self, $buf);
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

    my @args = split(/\s+/, $line);
    my $cmd = shift @args;

    if (!defined($self->{entries}{$cmd})) {
        $conn->write_local("Invalid command: ".$cmd."\n");
        return;
    }

    $self->{entries}->{$cmd}($self,$conn,@args);
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

package Intercept::test;
use warnings;
use strict;

sub new {
    my $class = shift;
    my $self = {};
    bless $self, $class;
    return $self;
}

sub start {
    my $self = shift;
    my $conn = shift;
    my $arg1 = shift;

    $conn->write_local("start, arg1: ".$arg1."\n");
    $conn->copy_remote_rx($self);
}

sub remote_rx {
    my $self = shift;
    my $conn = shift;
    my $buf = shift;

    $conn->write_local(".:".$buf.":.");
}

package Intercept::send_chars_check;
use warnings;
use strict;

sub new {
    my $class = shift;
    my $self = {};
    bless $self, $class;
    return $self;
}

sub start {
    my $self = shift;
    my $conn = shift;
    my $filename = shift;

    my $fh = FileHandle->new($filename, "r");
    if (!defined($fh)) {
        $conn->write_local("Could not open $filename\n");
        return 1;
    }
    $self->{conn} = $conn;
    $self->{fh} = $fh;

    $conn->copy_remote_rx($self);
    $conn->write_local("---sending---\n");
    $self->_send1();
}

sub _stop {
    my $self = shift;
    my $conn = $self->{conn};

    $conn->write_local("---done---\n");
    $conn->copy_remote_rx(undef);
}

sub _send1 {
    my $self = shift;
    my $conn = $self->{conn};

    my $ch = $self->{fh}->getc();
    if (!defined($ch)) {
        $self->_stop();
        return;
    }

    # HACK!
    if ($ch eq "\n") {
        $ch = "\r";
    }

    $self->{expect} = $ch;
    $conn->write_remote($ch);
}

sub _recv1 {
    my $self = shift;
    my $conn = $self->{conn};
    my $ch = shift;

    if (ord($ch) == 0) {
        # ignore null chars
        return;
    }

    if (!defined($self->{expect})) {
        $conn->write_local("---expect is null---\n");
        $self->_stop();
    }

    if ($ch ne $self->{expect}) {
        $conn->write_local("---MISMATCH---\n");
        $self->_stop();
    }

    # HACK!
    if ($ch eq "\r") {
        $self->{expect} = "\n";
        return;
    }

    # send next char
    $self->_send1();
}

sub remote_rx {
    my $self = shift;
    my $conn = shift;
    my $buf = shift;

    for my $ch (split(//, $buf)) {
        $self->_recv1($ch);
    }
}

package Intercept::send_text_check;
use warnings;
use strict;

sub new {
    my $class = shift;
    my $self = {};
    bless $self, $class;
    return $self;
}

sub start {
    my $self = shift;
    my $conn = shift;
    my $filename = shift;
    my $segsize = shift || 28;

    my $fh = FileHandle->new($filename, "r");
    if (!defined($fh)) {
        $conn->write_local("Could not open $filename\n");
        return 1;
    }
    $self->{conn} = $conn;
    $self->{fh} = $fh;
    $self->{buf} = '';
    $self->{segsize} = $segsize;

    $conn->copy_remote_rx($self);
    $conn->write_local("---sending---\n");
    $self->_send_segment();
}

sub _stop {
    my $self = shift;
    my $conn = $self->{conn};

    # Note that the done message will be output one buffer earlier than
    # expected in the local users display stream.
    # - the intercept is called before the $conn->write_local()
    #   (this ordering would in future allow the intercept to edit what
    #   the user can see - useful for a binary protocol, like xmodem)
    # TODO:
    # - see if we can think of a way around this ordering issue

    $conn->write_local("---done---\n");
    $conn->copy_remote_rx(undef);
}

sub _send_segment {
    my $self = shift;
    my $conn = $self->{conn};

    if (length($self->{buf}) == 0) {
        my $nextline = $self->{fh}->getline();

        # check for end of file
        if (!defined($nextline)) {
            $self->_stop();
            return;
        }

        # Assume file has standard end of lines
        chomp($nextline);

        $self->{buf} = $nextline;

        if (length($nextline) >80) {
            $conn->write_local("---WARN: line >80 chars---\n");
            # the far end performing echo may wordwrap, which will wierd us
        }
    }

    my $segment = substr($self->{buf}, 0, $self->{segsize}, '');
    $self->{expect} = $segment;

    if (length($self->{buf}) == 0) {
        # this is the last segment in this line
        # also send the remote end expected end of line char
        $segment .= "\r";
    }

    $conn->write_remote($segment);
}

sub remote_rx {
    my $self = shift;
    my $conn = shift;
    my $buf = shift;

    if (length($buf) == 0) {
        # eh?
        return;
    }

    my @chars = split(//, $buf);

    for my $ch (@chars) {
        next if ($ch eq "\x00"); # simply skip nulls

        if ($ch eq "\r" || $ch eq "\n") {
            # only valid if we are expecting nothimg more
            if (length($self->{expect}) != 0) {
                $conn->write_local("---line end but expect: ".$self->{expect}."---\n");
                $self->_stop();
                return;
            }

            next;
        }

        my $expect_ch = substr($self->{expect}, 0, 1);
        if ($ch ne $expect_ch) {
            $conn->write_local("---expect $expect_ch, got $ch---\n");
            $self->_stop();
            return;
        }

        substr($self->{expect}, 0, 1, '');
    }

    # TODO:
    # - if we did get a \r or a \n, confirm that we are at the end of a line
    # - if we are at the end of a line, confirm that we got a \r or a \n

    # if we have nothing more to expect, start sending the next segment
    if (length($self->{expect}) == 0) {
        $self->_send_segment();
    }
}

package main;
use warnings;
use strict;

use FileHandle;

sub ilist {
    my $menu = shift;
    my $conn = shift;

    my $buf = '';
    $buf .= "Intercepts:\n\n";

    no strict;
    for my $name (sort(keys(%{*{"Intercept\::"}}))) {
        $name =~ y/://d;
        $buf .= $name . "\n";
    }
    use strict;

    $conn->write_local($buf);
}

sub iclear {
    my $menu = shift;
    my $conn = shift;

    # Clear the intercept
    $conn->copy_remote_rx(undef);
}

sub iset {
    my $menu = shift;
    my $conn = shift;
    my $tail = shift;
    my $module = "Intercept::" . $tail;

    my $intercept = $module->new();
    $intercept->start($conn, @_);

    # FIXME:
    # - the menu maybe should not prompt after attaching an intercept
    # - the menu should be able to prompt after the intercept finishes..
}


sub main {
    my $host = shift @ARGV || die "Remote host not supplied";;
    my $port = shift @ARGV || 23;

    my $menu = Menu->new();
    $menu->register('ilist', \&ilist);
    $menu->register('iclear', \&iclear);
    $menu->register('iset', \&iset);

    my $conn = Telnet::Connection->new();
    $conn->menu($menu);
    $conn->hostname($host);
    $conn->port($port);
    $conn->connect();

    $conn->loop();
    exit(0);
}
unless(caller) { main(); }
