#!/usr/bin/env perl
use strict;
use warnings;
use lib '../lib';
use Crypt::MagicSignatures::Envelope;
use Benchmark ':hireswallclock';
my $t0 = Benchmark->new;

# the code took:16.9309 wallclock secs (16.61 usr +  0.01 sys = 16.62 CPU)
# the code took:16.3691 wallclock secs (16.03 usr +  0.01 sys = 16.04 CPU)
# the code took:16.1347 wallclock secs (15.88 usr +  0.00 sys = 15.88 CPU)
# the code took:15.9587 wallclock secs (15.71 usr +  0.00 sys = 15.71 CPU)
foreach (1..5000) {
my $me = Crypt::MagicSignatures::Envelope->new(<<'MEXML');
  <?xml version="1.0" encoding="UTF-8"?>
  <me:env xmlns:me="http://salmon-protocol.org/ns/magic-env">
    <me:data type="text/plain">
      U29tZSBhcmJpdHJhcnkgc3RyaW5nLg==
    </me:data>
    <me:encoding>base64url</me:encoding>
    <me:alg>RSA-SHA256</me:alg>
    <me:sig key_id="my-01">
      S1VqYVlIWFpuRGVTX3l4S09CcWdjRVFDYVluZkI5Ulh4dmRFSnFhQW5XUmpB
      UEJqZUM0b0lReER4d0IwWGVQZDhzWHAxN3oybWhpTk1vNHViNGNVOVE9PQ==
    </me:sig>
  </me:env>
MEXML
};

my $t1 = Benchmark->new;
my $td = timediff($t1, $t0);
print "the code took:",timestr($td),"\n";

__END__

ok($me = Crypt::MagicSignatures::Envelope->new(
  data => 'Some arbitrary string.'
), 'Construct Envelope');

ok(my $mkey = Crypt::MagicSignatures::Key->new(
  n => '7559044843939663506259320537304075578393827653061512'.
    '8473782766607634893582870680024021118955399592377939320'.
    '97814477506511744331780532898089567876987800547',
  e => '65537',
  d => '4081886522529635038016957654686531802178274267083432'.
    '8649269452526728395927456718919822835972368706726172581'.
    '7490923395335201901856183147375494766403567873'
), 'Key constructor');


ok($me->sign(my_key => $mkey), 'Sign me');

ok($me->verify($mkey->to_string), 'Verify me');

ok($me->sign(my_second_key => $mkey, -data), 'Sign me data');

ok($me->verify([my_second_key => $mkey->to_string, -data]), 'Verify me data');

ok(!$me->verify([my_second_key => $mkey->to_string]), 'Verify me base (fail)');
