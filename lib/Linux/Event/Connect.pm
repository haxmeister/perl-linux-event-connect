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
    if (index($h, '[') == 0 && substr($h, -1) eq ']') { $h = substr($h, 1, -1) }

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

Linux::Event::Connect - Nonblocking outbound connect for Linux::Event

=head1 SYNOPSIS

  use v5.36;
  use Linux::Event;
  use Linux::Event::Connect;
  use Linux::Event::Stream;

  my $loop = Linux::Event->new;

  my $req = Linux::Event::Connect->new(
    loop => $loop,

    host => '127.0.0.1',
    port => 1234,

    timeout_s => 5,

    on_connect => sub ($req, $fh, $data) {
      # You own $fh. Stream is the canonical next layer.
      Linux::Event::Stream->new(
        loop => $loop,
        fh   => $fh,

        codec      => 'line',
        on_message => sub ($stream, $line, $data) {
          $stream->write_message("client: $line");
        },

        on_error => sub ($stream, $errno, $data) {
          # fatal I/O error; stream will close
        },

        on_close => sub ($stream, $data) {
          # closed
        },
      );
    },

    on_error => sub ($req, $errno, $data) {
      # $errno is numeric; $! is not modified for you.
      # local $! = $errno; warn "connect failed: $!\n";
      warn "connect failed: $errno\n";
    },
  );

  $loop->run;

=head1 DESCRIPTION

B<Linux::Event::Connect> performs an outbound connect using a nonblocking socket
integrated with a L<Linux::Event> loop.

It is intentionally small and explicit:

=over 4

=item * One request object per connect attempt

The request manages the nonblocking socket, an internal watcher while the connect
is in progress, and an optional timeout.

=item * Nonblocking-only semantics

This module enforces nonblocking connect behavior and delivers completion via
callbacks.

=item * Composable

On success you receive a connected filehandle and can wrap it in
L<Linux::Event::Stream> or watch it directly with C<< $loop->watch(...) >>.

=back

=head1 LAYERING

This distribution is part of a composable socket stack:

=over 4

=item * B<Linux::Event::Connect>

Client-side socket acquisition: nonblocking outbound connect. Produces connected
nonblocking filehandles.

=item * B<Linux::Event::Listen>

Server-side socket acquisition: bind + listen + accept. Produces accepted
nonblocking filehandles.

=item * B<Linux::Event::Stream>

Buffered I/O + backpressure for an established filehandle (accepted or
connected). Stream owns the filehandle and handles read/write buffering.

=back

Canonical composition:

  Listen/Connect -> Stream -> (your protocol/codec/state)

=head1 CONSTRUCTOR

=head2 new

  my $req = Linux::Event::Connect->new(%args);

Creates and starts a connect request immediately. Unknown keys are fatal.

Required:

=over 4

=item * C<loop>

A L<Linux::Event::Loop> instance.

=back

Exactly one address mode is required (see L</ADDRESS MODES>).

Optional:

=over 4

=item * C<on_connect>

  on_connect => sub ($req, $fh, $data) { ... }

Called once on success.

=item * C<on_error>

  on_error => sub ($req, $errno, $data) { ... }

Called once on failure.

=item * C<timeout_s>

Seconds (integer or fractional). If set, the request fails with C<ETIMEDOUT> on
timeout.

=item * C<data>

Opaque user data passed to callbacks as the last argument.

=item * C<nonblocking>

If provided, must be true. This module only supports nonblocking connects.

=back

=head1 ADDRESS MODES

Exactly one address mode must be used.

=head2 host / port (TCP)

  host => $host,
  port => $port,

If C<host> is an IPv4/IPv6 literal, it is packed directly.

If C<host> is a hostname, this module calls C<getaddrinfo> synchronously to
produce candidate addresses. This may block; see L</PERFORMANCE NOTES>.

=head2 unix (AF_UNIX)

  unix => '/path/to.sock'

Connect to a Unix domain stream socket path.

=head2 sockaddr + explicit family

  sockaddr => $packed_sockaddr,
  family   => $AF_*

Use a caller-supplied sockaddr and an explicit address family.

=head1 CALLBACK CONTRACT

Callbacks are invoked at most once and have these signatures:

=head2 on_connect

  on_connect => sub ($req, $fh, $data) { ... }

Called once on success.

Ownership: you own C<$fh>. The request does not close it.

Nonblocking: C<$fh> is nonblocking.

After this callback runs, the request is complete and inert.

=head2 on_error

  on_error => sub ($req, $errno, $data) { ... }

Called once on failure with numeric C<$errno>.

The request has already torn down internal watchers/timers and closed any
in-progress socket before calling C<on_error>.

Note: C<$!> is not modified for you.

=head1 METHODS

=head2 cancel

  $req->cancel;

Cancel a pending request. No callbacks are invoked. After cancel, the request is
inert.

=head2 is_pending / is_done

  my $bool = $req->is_pending;
  my $bool = $req->is_done;

Convenience accessors for completion state.

=head2 fh

  my $fh = $req->fh;

Returns the in-progress filehandle while pending, or undef after completion.

=head2 errno

  my $errno = $req->errno;

Returns the last error number observed by the request.

=head2 gai_error

  my $str = $req->gai_error;

If hostname resolution via C<getaddrinfo> fails, this returns the stored resolver
failure string.

=head1 CALLBACK BEHAVIOR

Before invoking a callback, the request cancels its internal watcher and timeout.
This prevents double-callbacks and keeps re-entrant loop activity safe.

=head1 PERFORMANCE NOTES

=over 4

=item * IP literals avoid getaddrinfo

IPv4/IPv6 literals do not call C<getaddrinfo>.

=item * Hostnames may block

Hostname resolution is synchronous and may block. If you need strict nonblocking
behavior, use sockaddr mode with a pre-resolved address or provide an IP literal.

=item * Candidate fallback

When multiple candidates exist (for example IPv6 then IPv4), Connect tries them
in order until one succeeds or all fail.

=back

=head1 SEE ALSO

L<Linux::Event> - core event loop

L<Linux::Event::Listen> - server-side socket acquisition

L<Linux::Event::Connect> - client-side socket acquisition

L<Linux::Event::Fork> - asynchronous child processes

L<Linux::Event::Clock> - high resolution monotonic clock utilities

=head1 AUTHOR

Joshua S. Day

=head1 LICENSE

Same terms as Perl itself.

=cut
