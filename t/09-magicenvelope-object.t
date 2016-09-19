#!/usr/bin/env perl
use Test::More;
use strict;
use Test::Output;
use warnings;
no strict 'refs';

use_ok('Crypt::MagicSignatures::Envelope');
use_ok('Crypt::MagicSignatures::Key');

stderr_like(
  sub {
    ok(!Crypt::MagicSignatures::Envelope->new(
      data => 'hihi',
      data_type => 'haha',
      'fail'
    ), 'Wrong argument number');
  },
  qr/wrong number/i,
  'Wrong number of arguments'
);

stderr_like(
  sub {
    ok(!Crypt::MagicSignatures::Envelope->new(
      data => 'hihi',
      data_type => 'haha',
      alg => 'dsa'
    ), 'algorithm not supported');
  },
  qr/algorithm is not supported/i,
  'DSA not supported'
);

stderr_like(
  sub {
    ok(!Crypt::MagicSignatures::Envelope->new(
      data => 'hihi',
      data_type => 'haha',
      encoding => 'base64'
    ), 'encoding not supported');
  },
  qr/encoding is not supported/i,
  'Encoding not supported'
);


stderr_like(
  sub {
    ok(!Crypt::MagicSignatures::Envelope->new(
      alg => 'rsa-sha256',
      encoding => 'Base64URL'
    ), 'No payload');
  },
  qr/no data payload/i,
  'No data payload'
);

ok(Crypt::MagicSignatures::Envelope->new, 'Create empty object');

stderr_like(
  sub {
    ok(!Crypt::MagicSignatures::Envelope->new('           '), 'Create empty object');
  },
  qr/invalid envelope/i,
  'Invalid envelope data passed'
);

stderr_like(
  sub {
    ok(!Crypt::MagicSignatures::Envelope->new('kghjghjghj'), 'Create empty object');
  },
  qr/invalid envelope/i,
  'Invalid envelope data passed'
);


done_testing;

1;
