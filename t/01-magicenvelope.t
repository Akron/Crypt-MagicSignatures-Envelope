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

ok(my $sig = $me->signature, 'Signature');
is($sig->{key_id}, 'my-01', 'Signature Key id');
is($sig->{value}, 'S1VqYVlIWFpuRGVTX3l4S09CcWdjRVFDYVluZkI5Ulh4dmRFSnFhQW5XUmpBUEJqZUM0b0lReER4d0IwWGVQZDhzWHAxN3oybWhpTk1vNHViNGNVOVE9PQ==', 'Signature value');

# Signing

ok($me = Crypt::MagicSignatures::Envelope->new(
  data => 'Some arbitrary string.'
), 'Construct Key');

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

ok($me->sign_data(my_second_key => $mkey), 'Sign me data');

ok($me->verify({
  key_id => 'my_second_key',
  value => $mkey->to_string,
  verify => 'data'
}), 'Verify me data');

ok(!$me->verify({
  key_id => 'my_second_key',
  value => $mkey->to_string}
	      ),
   'Verify me data (fail)');

# diag $me->to_xml;


# $mkey->to_string;

done_testing;
