#!/usr/bin/env perl
use Test::More;
use strict;
use warnings;
no strict 'refs';

use lib '../lib';

BEGIN {
  use_ok('Crypt::MagicSignatures::Envelope');
  use_ok('Crypt::MagicSignatures::Key');
};


ok(my $me = Crypt::MagicSignatures::Envelope->new(
  data => 'Some arbitrary string.'
), 'Constructor (Attributes)');

is($me->data, 'Some arbitrary string.', 'Data');
is($me->data_type, 'text/plain', 'Data type');
is($me->alg, 'RSA-SHA256', 'Algorithm');
is($me->encoding, 'base64url', 'Encoding');


ok($me = Crypt::MagicSignatures::Envelope->new(<<'MEXML'), 'Constructor (XML)');
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

is($me->data, 'Some arbitrary string.', 'Data');
is($me->data_type, 'text/plain', 'Data type');
is($me->alg, 'RSA-SHA256', 'Algorithm');
is($me->encoding, 'base64url', 'Encoding');

ok($me = Crypt::MagicSignatures::Envelope->new(<<'MEJSON'), 'Constructor (JSON)');
{
  "data_type": "text\/plain",
  "data":"U29tZSBhcmJpdHJhcnkgc3RyaW5nLg==",
  "alg":"RSA-SHA256",
  "encoding":"base64url",
  "sigs": [
    { "key_id": "my-01",
      "value": "S1VqYVlIWFpuRGVTX3l4S09CcWdjRVFDYVluZkI5Ulh4dmRFSnFhQW5XUmpBUEJqZUM0b0lReER4d0IwWGVQZDhzWHAxN3oybWhpTk1vNHViNGNVOVE9PQ=="
    }
  ]
}
MEJSON

is($me->data, 'Some arbitrary string.', 'Data');
is($me->data_type, 'text/plain', 'Data type');
is($me->alg, 'RSA-SHA256', 'Algorithm');
is($me->encoding, 'base64url', 'Encoding');

ok($me = Crypt::MagicSignatures::Envelope->new(<<'MECOMPACT'), 'Constructor (Compact)');
    bXktMDE=.S1VqYVlIWFpuRGVTX3l4S09CcWdjRVFDYVlu
    ZkI5Ulh4dmRFSnFhQW5XUmpBUEJqZUM0b0lReER4d0IwW
    GVQZDhzWHAxN3oybWhpTk1vNHViNGNVOVE9PQ==.U29tZ
    SBhcmJpdHJhcnkgc3RyaW5nLg.dGV4dC9wbGFpbg.YmFz
    ZTY0dXJs.UlNBLVNIQTI1Ng
MECOMPACT

is($me->data, 'Some arbitrary string.', 'Data');
is($me->data_type, 'text/plain', 'Data type');
is($me->alg, 'RSA-SHA256', 'Algorithm');
is($me->encoding, 'base64url', 'Encoding');

ok(my $mkey = Crypt::MagicSignatures::Key->new(
  n => '7559044843939663506259320537304075578393827653061512847378276660763489358287068002402111895539959237793932097814477506511744331780532898089567876987800547',
  e => '65537',
  d => '408188652252963503801695765468653180217827426708343286492694525267283959274567189198228359723687067261725817490923395335201901856183147375494766403567873'
), 'Key constructor');



done_testing;
