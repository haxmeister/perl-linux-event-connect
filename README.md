# Linux::Event::Connect

[![CI](https://github.com/haxmeister/perl-linux-event-connect/actions/workflows/ci.yml/badge.svg)](https://github.com/haxmeister/perl-linux-event-connect/actions/workflows/ci.yml)

Nonblocking outbound connect for the Linux::Event ecosystem.
## Linux::Event Ecosystem

The Linux::Event modules are designed as a composable stack of small,
explicit components rather than a framework.

Each module has a narrow responsibility and can be combined with the others
to build event-driven applications.

Core layers:

Linux::Event
    The event loop. Linux-native readiness engine using epoll and related
    kernel facilities. Provides watchers and the dispatch loop.

Linux::Event::Listen
    Server-side socket acquisition (bind + listen + accept). Produces accepted
    nonblocking filehandles.

Linux::Event::Connect
    Client-side socket acquisition (nonblocking connect). Produces connected
    nonblocking filehandles.

Linux::Event::Stream
    Buffered I/O and backpressure management for an established filehandle.

Linux::Event::Fork
    Asynchronous child process management integrated with the event loop.

Linux::Event::Clock
    High resolution monotonic time utilities used for scheduling and deadlines.

Canonical network composition:

Listen / Connect
        ↓
      Stream
        ↓
  Application protocol

Example stack:

Linux::Event::Listen → Linux::Event::Stream → your protocol

or

Linux::Event::Connect → Linux::Event::Stream → your protocol

The core loop intentionally remains a primitive layer and does not grow
into a framework. Higher-level behavior is composed from small modules.

## Synopsis

use v5.36;
use Linux::Event;
use Linux::Event::Connect;

my $loop = Linux::Event->new;

Linux::Event::Connect->new(
  loop => $loop,

  host => '127.0.0.1',
  port => 1234,

  timeout_s => 5,

  on_connect => sub ($req, $fh, $data) {

    # You own $fh
    close $fh;

    $loop->stop;
  },

  on_error => sub ($req, $errno, $data) {

    local $! = $errno;
    warn "connect failed: $!\n";

    $loop->stop;
  },
);

$loop->run;

## Canonical integration with Stream

use Linux::Event::Stream;

Linux::Event::Connect->new(
  loop => $loop,
  host => '127.0.0.1',
  port => 1234,

  on_connect => sub ($req, $fh, $data) {

    Linux::Event::Stream->new(
      loop => $loop,
      fh   => $fh,

      codec => 'line',

      on_message => sub ($stream, $line, $data) {
        $stream->write_message("client saw: $line");
      },
    );
  },
);

$loop->run;

## Address modes

host + port (TCP)

unix => $path (Unix domain)

sockaddr + family (caller supplied address)

Hostname resolution uses synchronous getaddrinfo.

## License

Same terms as Perl itself.
