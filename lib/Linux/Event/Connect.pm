package Linux::Event::Connect;
use v5.36;
use strict;
use warnings;

our $VERSION = '0.001';

use Carp qw(croak);
use Fcntl qw(F_GETFL F_SETFL O_NONBLOCK);
use Socket qw(
  AF_INET AF_INET6 AF_UNIX
  SOCK_STREAM
  SOL_SOCKET SO_ERROR
  inet_pton
  pack_sockaddr_in
  pack_sockaddr_in6
  pack_sockaddr_un
  getaddrinfo
);
use Errno ();

use constant {
  S_NEW        => 0,
  S_CONNECTING => 1,
  S_DONE       => 2,
};

sub new ($class, %args) {
  my $loop = delete $args{loop};
  croak "loop is required" unless defined $loop && ref $loop;

  my $timeout_s = exists $args{timeout_s} ? delete $args{timeout_s} : undef;
  my $data      = delete $args{data};

  my $on_connect = exists $args{on_connect} ? delete $args{on_connect} : undef;
  my $on_error   = exists $args{on_error}   ? delete $args{on_error}   : undef;

  my $nonblocking = exists $args{nonblocking} ? delete $args{nonblocking} : 1;
  croak "nonblocking must be true" unless $nonblocking;

  croak "on_connect must be a coderef" if defined $on_connect && ref($on_connect) ne 'CODE';
  croak "on_error must be a coderef"   if defined $on_error   && ref($on_error)   ne 'CODE';

  if (defined $timeout_s) {
    croak "timeout_s must be a number >= 0"
      if $timeout_s !~ /\A(?:\d+(?:\.\d*)?|\.\d+)\z/ || $timeout_s < 0;
    $timeout_s = 0 + $timeout_s;
  }

  # Address mode selection (exactly one):
  my $have_hostport = (exists $args{host} || exists $args{port}) ? 1 : 0;
  my $have_unix     = exists $args{unix} ? 1 : 0;
  my $have_sockaddr = exists $args{sockaddr} ? 1 : 0;

  my $modes = ($have_hostport ? 1 : 0) + ($have_unix ? 1 : 0) + ($have_sockaddr ? 1 : 0);
  croak "exactly one address mode is required (host/port, unix, or sockaddr)" if $modes != 1;

  my ($host, $port, $unix, $sockaddr, $family);

  if ($have_hostport) {
    $host = delete $args{host};
    $port = delete $args{port};

    croak "host is required" unless defined $host;
    croak "host must be a non-empty string" if ref($host) || $host eq '';

    croak "port is required" unless defined $port;
    croak "port must be an integer" if ref($port) || $port !~ /\A\d+\z/;
    $port = 0 + $port;
    croak "port out of range" if $port < 0 || $port > 65535;

    croak "family is not allowed in host/port mode" if exists $args{family};
    croak "sockaddr is not allowed in host/port mode" if exists $args{sockaddr};
    croak "unix is not allowed in host/port mode" if exists $args{unix};
    croak "type is not allowed in host/port mode" if exists $args{type};
    croak "proto is not allowed in host/port mode" if exists $args{proto};
  }
  elsif ($have_unix) {
    $unix = delete $args{unix};
    croak "unix must be a non-empty string" if !defined($unix) || ref($unix) || $unix eq '';

    croak "host is not allowed in unix mode" if exists $args{host};
    croak "port is not allowed in unix mode" if exists $args{port};
    croak "sockaddr is not allowed in unix mode" if exists $args{sockaddr};
    croak "family is not allowed in unix mode" if exists $args{family};
    croak "type is not allowed in unix mode" if exists $args{type};
    croak "proto is not allowed in unix mode" if exists $args{proto};
  }
  else { # sockaddr mode
    $sockaddr = delete $args{sockaddr};
    croak "sockaddr must be a defined scalar" if !defined($sockaddr) || ref($sockaddr);

    $family = delete $args{family};
    croak "family is required in sockaddr mode" unless defined $family;
    croak "family must be a numeric AF_* constant" if ref($family) || $family !~ /\A\d+\z/;
    $family = 0 + $family;

    croak "host is not allowed in sockaddr mode" if exists $args{host};
    croak "port is not allowed in sockaddr mode" if exists $args{port};
    croak "unix is not allowed in sockaddr mode" if exists $args{unix};

    croak "type is not allowed in sockaddr mode (v0.001)" if exists $args{type};
    croak "proto is not allowed in sockaddr mode (v0.001)" if exists $args{proto};
  }

  if (%args) {
    my @k = sort keys %args;
    croak "unknown option(s): " . join(", ", @k);
  }

  my $self = bless {
    _loop      => $loop,
    _data      => $data,
    _timeout_s => $timeout_s,
    _cb_ok     => $on_connect,
    _cb_err    => $on_error,

    _state     => S_NEW,
    _done      => 0,
    _cancelled => 0,
    _errno     => undef,
    _gai_error => undef,

    _cand      => [],
    _idx       => 0,

    _fh        => undef,
    _watch     => undef,
    _timer_id  => undef,
  }, $class;

  # Normalize to candidate list
  if (defined $unix) {
    push @{ $self->{_cand} }, [ AF_UNIX, pack_sockaddr_un($unix) ];
  }
  elsif (defined $sockaddr) {
    push @{ $self->{_cand} }, [ $family, $sockaddr ];
  }
  else {
    # host/port mode: IP literal fast-path, else synchronous getaddrinfo
    my $h = $host;
    $h =~ s/\A[ \t\r\n]+//;
    $h =~ s/[ \t\r\n]+\z//;
    if ($h =~ /\A\[(.*)\]\z/) { $h = $1 }

    my $p4 = inet_pton(AF_INET, $h);
    if (defined $p4) {
      push @{ $self->{_cand} }, [ AF_INET, pack_sockaddr_in($port, $p4) ];
    }
    else {
      my $p6 = inet_pton(AF_INET6, $h);
      if (defined $p6) {
        push @{ $self->{_cand} }, [ AF_INET6, pack_sockaddr_in6($port, $p6) ];
      }
      else {
        my ($err, @res) = getaddrinfo($host, $port, { socktype => SOCK_STREAM });
        if ($err) {
          $self->{_gai_error} = "$err";
          my $mapped = ($err =~ /NONAME|NODATA|NO_DATA/i) ? Errno::ENOENT() : Errno::EIO();
          $self->_finalize_err($mapped);
          return $self;
        }

        for my $r (@res) {
          my $fam = $r->{family};
          my $sa  = $r->{addr};
          next unless defined $fam && defined $sa;
          push @{ $self->{_cand} }, [ $fam, $sa ];
        }

        if (!@{ $self->{_cand} }) {
          $self->_finalize_err(Errno::ENOENT());
          return $self;
        }
      }
    }
  }

  $self->{_state} = S_CONNECTING;
  $self->_arm_timeout if defined $timeout_s;
  $self->_attempt_next;
  return $self;
}

sub cancel ($self) {
  return if $self->{_done};
  $self->{_cancelled} = 1;
  $self->{_done}      = 1;
  $self->{_state}     = S_DONE;
  $self->_teardown;
  $self->{_cb_ok}  = undef;
  $self->{_cb_err} = undef;
  return;
}

sub is_pending ($self) { return !$self->{_done} }
sub is_done    ($self) { return  $self->{_done} }
sub fh         ($self) { return  $self->{_fh} }
sub errno      ($self) { return  $self->{_errno} }
sub gai_error  ($self) { return  $self->{_gai_error} }

sub _arm_timeout ($self) {
  my $id = $self->{_loop}->after($self->{_timeout_s}, sub ($loop) {
    return if $self->{_done} || $self->{_cancelled};
    $self->_finalize_err(Errno::ETIMEDOUT());
  });
  $self->{_timer_id} = $id;
  return;
}

sub _attempt_next ($self) {
  return if $self->{_done} || $self->{_cancelled};

  my $cand = $self->{_cand};
  my $n = @$cand;

  while ($self->{_idx} < $n) {
    my ($family, $sockaddr) = @{ $cand->[ $self->{_idx}++ ] };

    my $fh;
    if (!socket($fh, $family, SOCK_STREAM, 0)) {
      $self->{_errno} = 0 + $!;
      next;
    }

    my $flags = fcntl($fh, F_GETFL, 0);
    if (!defined $flags) {
      $self->{_errno} = 0 + $!;
      close $fh;
      next;
    }
    if (!fcntl($fh, F_SETFL, $flags | O_NONBLOCK)) {
      $self->{_errno} = 0 + $!;
      close $fh;
      next;
    }

    $self->{_fh} = $fh;

    if (connect($fh, $sockaddr)) {
      $self->_finalize_ok($fh);
      return;
    }

    my $e = 0 + $!;
    $self->{_errno} = $e;

    if ($e == Errno::EINPROGRESS()) {
      my $w = $self->{_loop}->watch($fh,
        write => sub ($loop, $fh2, $watcher) {
          return if $self->{_done} || $self->{_cancelled};

          my $raw = getsockopt($fh2, SOL_SOCKET, SO_ERROR);
          my $soerr = 0;
          $soerr = unpack("i", $raw) if defined($raw) && length($raw) >= 4;

          if ($soerr == 0) {
            $self->_finalize_ok($fh2);
            return;
          }

          $self->{_errno} = $soerr;
          eval { close $fh2; 1 };
          $self->{_fh} = undef;

          # Drop watcher before attempting next
          if (my $ww = delete $self->{_watch}) {
            eval { $ww->close; 1 };
          }

          $self->_attempt_next;
          return;
        },
        error => sub ($loop, $fh2, $watcher) {
          return if $self->{_done} || $self->{_cancelled};

          my $raw = getsockopt($fh2, SOL_SOCKET, SO_ERROR);
          my $soerr = 0;
          $soerr = unpack("i", $raw) if defined($raw) && length($raw) >= 4;
          $soerr ||= (0 + $!);

          $self->{_errno} = $soerr;
          eval { close $fh2; 1 };
          $self->{_fh} = undef;

          if (my $ww = delete $self->{_watch}) {
            eval { $ww->close; 1 };
          }

          $self->_attempt_next;
          return;
        },
      );

      $self->{_watch} = $w;
      return;
    }

    # Immediate failure, try next
    close $fh;
    $self->{_fh} = undef;
  }

  # exhausted candidates: report last errno if set, else EIO
  my $last = $self->{_errno};
  $last = Errno::EIO() if !defined $last;
  $self->_finalize_err($last);
  return;
}

sub _teardown ($self) {
  if (my $w = delete $self->{_watch}) {
    eval { $w->close; 1 } or do {
      # fallback if Watcher has no close
      if (my $fh = $self->{_fh}) {
        eval { $self->{_loop}->unwatch($fh); 1 };
      }
    };
  }

  if (defined(my $id = delete $self->{_timer_id})) {
    eval { $self->{_loop}->cancel($id); 1 };
  }

  if (my $fh = delete $self->{_fh}) {
    eval { close $fh; 1 };
  }

  return;
}

sub _finalize_ok ($self, $fh) {
  return if $self->{_done} || $self->{_cancelled};

  $self->{_done}  = 1;
  $self->{_state} = S_DONE;

  # Make inert before callbacks
  my $cb   = $self->{_cb_ok};
  my $data = $self->{_data};
  $self->{_cb_ok}  = undef;
  $self->{_cb_err} = undef;

  # Teardown watcher/timer, but do NOT close $fh on success
  if (my $w = delete $self->{_watch}) { eval { $w->close; 1 } }
  if (defined(my $id = delete $self->{_timer_id})) { eval { $self->{_loop}->cancel($id); 1 } }
  $self->{_fh} = undef;

  $cb->($self, $fh, $data) if $cb;
  return;
}

sub _finalize_err ($self, $errno) {
  return if $self->{_done} || $self->{_cancelled};

  $self->{_errno} = $errno;

  $self->{_done}  = 1;
  $self->{_state} = S_DONE;

  my $cb   = $self->{_cb_err};
  my $data = $self->{_data};
  $self->{_cb_ok}  = undef;
  $self->{_cb_err} = undef;

  $self->_teardown;

  $cb->($self, $errno, $data) if $cb;
  return;
}

1;

__END__

=head1 NAME

Linux::Event::Connect - Nonblocking outbound socket connect for Linux::Event

=head1 SYNOPSIS

  use v5.36;
  use Linux::Event;
  use Linux::Event::Connect;

  my $loop = Linux::Event->new;

  my $req = Linux::Event::Connect->new(
    loop => $loop,

    host => '127.0.0.1',
    port => 1234,

    timeout_s => 5,

    on_connect => sub ($req, $fh, $data) {
      # $fh is a connected nonblocking socket.
    },

    on_error => sub ($req, $errno, $data) {
      # Connect failed. $errno is numeric.
    },
  );

  $loop->run;

=head1 DESCRIPTION

Linux::Event::Connect provides a minimal nonblocking outbound connect primitive
for Linux::Event.

Host/port mode uses an IP literal fast-path (no getaddrinfo). Hostname
resolution uses getaddrinfo synchronously and may block. For strict nonblocking
behavior, use sockaddr mode.

=head1 CONSTRUCTOR

=head2 new(%args)

Creates and starts the connect request immediately. Unknown keys are fatal.

Exactly one address mode is required:

=over 4

=item * host/port mode

  host => $host, port => $port

C<port> must be an integer in 0..65535.

=item * unix mode

  unix => '/path/to.sock'

=item * sockaddr mode

  sockaddr => $packed, family => $AF_*

In sockaddr mode, C<family> is required and is not inferred.

=back

Optional:

=over 4

=item * timeout_s

If set, fails with ETIMEDOUT when the timeout expires.

=item * data

User data passed to callbacks.

=item * on_connect / on_error

Callbacks invoked as:

  on_connect($req, $fh, $data)
  on_error($req, $errno, $data)

=item * nonblocking

Must be true if provided.

=back

=head1 METHODS

=head2 cancel

Cancels a pending request. No callbacks are invoked.

=head2 is_pending, is_done, fh, errno, gai_error

=head1 PERFORMANCE NOTES

IP literals (IPv4 or IPv6) are detected via inet_pton and do not call
getaddrinfo.

Hostnames use synchronous getaddrinfo and may block.

For strictly nonblocking behavior in all cases, use sockaddr mode.

=cut

=head1 LICENSE

Same terms as Perl itself.

=cut
