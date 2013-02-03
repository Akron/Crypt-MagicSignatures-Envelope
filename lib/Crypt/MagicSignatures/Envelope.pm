package Crypt::MagicSignatures::Envelope;
use Crypt::MagicSignatures::Key qw/b64url_encode b64url_decode/;
use Carp qw/carp croak/;
use Mojo::Base -base;
use Mojo::DOM;
use Mojo::JSON;

our $VERSION = '0.01';

has 'data';
has alg       => 'RSA-SHA256';
has encoding  => 'base64url';
has data_type => 'text/plain';

# MagicEnvelope namespace
use constant ME_NS => 'http://salmon-protocol.org/ns/magic-env';


# Constructor
sub new {
  my $class = shift;

  my $self;

  # Bless object as parent class
  if (@_ > 1 && !(@_ % 2)) {
    $self = $class->SUPER::new(@_);
  }

  else {
    $self = $class->SUPER::new;

    # Message is me-xml
    if ($_[0] =~ /^[\s\t\n]*\</) {

      my $dom = Mojo::DOM->new(xml => 1);
      $dom->parse( shift );

      # Extract envelope from env or provenance
      my $env = $dom->at('env');
      $env = $dom->at('provenance') unless $env;
      return if !$env || $env->namespace ne ME_NS;

      # Retrieve and edit data
      my $data = $env->at('data');

      # Envelope empty
      return unless $data;

      $self->data_type( $data->attrs->{type} ) if $data->attrs->{type};
      $self->data( b64url_decode( $data->text ) );

      # Check algorithm
      if ($env->at('alg') &&
	    ($env->at('alg')->text ne 'RSA-SHA256')) {
	carp 'Algorithm currently not supported' and return;
      };

      # Check encoding
      if ($env->at('encoding') &&
	    ($env->at('encoding')->text ne 'base64url')) {
	carp 'Encoding currently not supported' and return;
      };

      # Find signatures
      $env->find('sig')->each(
	sub {
	  return unless $_->text;

	  my $sig_text = $_->text;
	  $sig_text =~ s/[\s\t]//g;

	  my %sig = ( value => $sig_text );

	  if (exists $_->attrs->{key_id}) {
	    $sig{key_id} = $_->attrs->{key_id};
	  };

	  # Add sig to array
	  push( @{ $self->{sigs} }, \%sig );

	  # Envelope is signed
	  $self->{signed} = 1;
	});
    }

    # Message is me-json
    elsif ($_[0] =~ /^[\s\t\n]*\{/ ) {
      my $env;

      # Parse json object
      my $json = Mojo::JSON->new;
      $env = $json->decode( shift );

      unless (defined $env) {
	carp $json->error and return;
      };

      # Clone datastructure
      foreach (qw/data data_type encoding alg sigs/) {
	$self->{$_} = delete $env->{$_} if exists $env->{$_};
      };

      # Envelope is signed
      $self->{signed} = 1 if $self->{sigs}->[0];

      $self->data( b64url_decode( $self->data ));


      # Unknown parameters
      carp 'Unknown parameters: ' . join(',', %$env)
	if keys %$env;
    }

    # Message is me as a compact string
    elsif (((my $me_c = _trim($_[0])) =~ /\.YmFzZTY0dXJs\./) > 0) {

      # Parse me compact string
      my $value = [];
      foreach (@$value = split(/\./, $me_c) ) {
	$_ = b64url_decode( $_ ) if $_;
      };

      # Store sig to data structure
      for ($self->{sigs}->[0]) {
	next unless $value->[1];
	$_->{key_id}    = $value->[0] if defined $value->[0];
	$_->{value}     = $value->[1];
	$self->{signed} = 1;
      };

      # Store values to data structure
      for ($value) {

	# ME is empty
	return unless $_->[2];

	$self->data( $_->[2] );
	if ($_->[3]) { $self->data_type( $_->[3] ) };
	if ($_->[4]) { $self->encoding( $_->[4] ) };
	if ($_->[5]) { $self->alg( $_->[5] ) };
      };
    };
  };

  # Message has unknown format
  unless ($self->data) {
    carp 'Envelope has unknown format' and return;
  };

  $self->{sigs}     //= [];
  $self->{sig_base} //= '';

  return $self;
};


# Sign magic envelope instance following the spec
sub sign {
  my $self = shift;
  return $self->_sign($self->sig_base, @_);
};


# Sign the data of the magic envelope
sub sign_data {
  my $self = shift;
  return $self->_sign(b64url_encode($self->data), @_);
};


# Sign magic envelope instance
sub _sign {
  my $self = shift;
  my $data = shift;
  my $key  = pop;
  my $key_id = shift;

  # Todo: Regarding key id:
  # "If the signer does not maintain individual key_ids,
  #  it SHOULD output the base64url encoded representation
  #  of the SHA-256 hash of public key's application/magic-key
  #  representation."

  # A valid key is given
  if ($key) {

    # Create MagicKey from parameter
    my $mkey = Crypt::MagicSignatures::Key->new(
      ( ref $key && $key eq 'HASH' ? %{ $key } : $key )
    );

    # No valid private key
    return undef unless ($mkey && $mkey->d);

    # Compute signature for base string
    my $msig = $mkey->sign( $data );

    # No valid signature
    return undef unless $msig;

    # Sign envelope
    my %msig = ( value => $msig );
    $msig{key_id} = $key_id if defined $key_id;

    # Push signature
    push( @{ $self->{sigs} }, \%msig );

    # Declare envelope as signed
    $self->{signed} = 1;

    # Return envelope for piping
    return $self;
  };

  return;
};


# Verify Signature
sub verify {
  my $self = shift;

  # Regarding key id:
  # "If the signer does not maintain individual key_ids,
  #  it SHOULD output the base64url encoded representation
  #  of the SHA-256 hash of public key's application/magic-key
  #  representation."

  # No sig base - MagicEnvelope is invalid
  return unless $self->sig_base;

  my $verified = 0;

  foreach my $key (@_) {

    my $verify = 'sig_base';
    my $key_id = undef;

    if (ref $key) {
      if (ref $key eq 'HASH') {
	$key_id = delete $key->{key_id};
	$verify = delete $key->{verify};
	$key = delete $key->{value};
	next unless $key;
      };
    };

    my $mkey = Crypt::MagicSignatures::Key->new($key);

    next unless $mkey;

    # Get without key id
    my $sig = $self->signature($key_id);

    # Found key/sig pair
    if ($sig) {

      if ($verified ne 'data') {
	$verified = $mkey->verify($self->sig_base => $sig->{value});
	last if $verified;
      };

      if ($verified eq 'data' || $verified eq 'compatible') {

	# Verify with b64url data
	$verified = $mkey->verify(b64url_encode($self->data) => $sig->{value});
	last if $verified;

	# Verify with b64url data
	$verified = $mkey->verify(b64url_encode($self->data, 0) => $sig->{value});
	last if $verified;
      };
    };
  };

  return $verified;
};


# Retrieve MagicEnvelope signatures
# Todo: Better sig?
sub signature {
  my $self = shift;
  my $key_id = shift;

  # MagicEnvelope has no signature
  return unless $self->signed;

  my @sigs = @{ $self->{sigs} };

  # No key_id given
  unless ($key_id) {

    # Search sigs for necessary default key
    foreach (@sigs) {
      unless (exists $_->{key_id}) {
	return $_;
      };
    };

    # Return first sig
    return $sigs[0];
  }

  # Key is given
  else {
    my $default;

    # Search sigs for necessary specific key
    foreach (@sigs) {

      # sig specifies key
      if (defined $_->{key_id}) {

	# Found wanted key
	if ($_->{key_id} eq $key_id) {
	  return $_;
	};
      }

      # sig needs default key
      else {
	$default = $_;
      };
    };

    # Return sig for default key
    return $default;
  };

  # No matching sig found
  return;
};


# Is the MagicEnvelope signed?
sub signed {

  # There is no specific key_id requested
  return $_[0]->{signed} unless defined $_[1];

  # Check for specific key_id
  foreach my $sig (@{ $_[0]->{sigs} }) {
    return 1 if $sig->{key_id} eq $_[1];
  };

  # Envelope is not signed
  return 0;
};


# Generate and return signature base
sub sig_base {
  my $self = shift;

  # Already computed
  return $self->{sig_base} if $self->{sig_base};

  $self->{sig_base} = join('.',
			   b64url_encode( $self->data, 0 ),
			   b64url_encode( $self->data_type ),
			   b64url_encode( $self->encoding ),
			   b64url_encode( $self->alg )
			 );

  unless ($self->{sig_base}) {
    carp 'Unable to construct sig_base.';
  };

  return $self->{sig_base};
};


# Return the data as a Mojo::DOM if it is xml
sub dom {
  my $self = shift;

  # Already computed
  return $self->{dom} if $self->{dom};

  # Create new DOM instantiation
  my $dom = Mojo::DOM->new;
  if (index($self->{data_type}, 'xml') >= 0) {
    $dom->parse( $self->{data} );
  };

  # Return DOM instantiation (Maybe empty)
  return ($self->{dom} = $dom);
};


# Return em-xml string
sub to_xml {
  my $self = shift;

  my $xml;

  my $me;

  my $start_tag = 'env';
  if ($self->{embed}) {
    $start_tag = 'provenance';
  }

  else {
    $xml = qq{<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n};
  };

  $xml .= qq{<me:$start_tag xmlns:me="http://salmon-protocol.org/ns/magic-env">\n};

  $xml .= '  <me:data';
  $xml .= ' type="' . $me->{data_type} . '"' if exists $me->{data_type};
  $xml .= ">" . b4url_encode($me->data, 0) . "</me:data>\n";

  $xml .= '  <me:encoding>' . $me->encoding . "</me:encoding>\n";
  $xml .= '  <me:alg>' . $me->alg . "</me:alg>\n";

  foreach my $sig (@{$me->{sigs}}) {
    $xml .= '  <me:sig';
    $xml .= ' key_id="' . $sig->{key_id} . '"' if $sig->{key_id};
    $xml .= '>' . b64url_encode($sig->{value}) . "</me:sig>\n"
  };

  $xml .= "</me:$start_tag>";

  return $xml;
};


# Return em-compact string
sub to_compact {
  my $self = shift;

  # The me has to be signed
  return unless $self->signed;

  # Use default signature for serialization
  my $sig = $self->signature;

  return join( '.',
	       b64url_encode( $sig->{key_id} ) || '',
	       b64url_encode( $sig->{value} ),
	       $self->sig_base );
};


# Return em-json string
sub to_json {
  my $self = shift;

  # Empty envelope
  return '{}' unless $self->data;

  # Create new datastructure
  my %new_em = (
    alg       => $self->alg,
    encoding  => $self->encoding,
    data_type => $self->data_type,
    data      => b64url_encode( $self->data ),
    sigs      => []
  );

  # loop through signatures
  foreach my $sig ( @{ $self->{sigs} } ) {
    my %msig = ( value => b64url_encode( $sig->{value} ) );
    $msig{key_id} = $sig->{key_id} if defined $sig->{key_id};
    push( @{ $new_em{sigs} }, \%msig );
  };

  # Return json-string
  return Mojo::JSON->new->encode( \%new_em );
};


# Delete all whitespaces
sub _trim {
  my $string = shift;
  $string =~ tr{\t-\x0d }{}d;
  $string;
};

1;


__END__

=pod

=head1 NAME

Crypt::MagicSignatures - Sign and verify MagicSignatures

=head1 SYNOPSIS

  use Crypt::MagicSignatures;

  my $me = Crypt::MagicSignatures::Envelope->new({
    data => 'Some arbitrary string.',
    data_type => 'text/plain'
  });

  $me->sign('key-01' => 'RSA.vsd...');


=head1 DESCRIPTION

L<Crypt::MagicSignatures> helps to verify and sign MagicEnvelopes
with MagicSignatures as described in the
L<MagicSignature Specification|http://salmon-protocol.googlecode.com/svn/trunk/draft-panzer-magicsig-01.html>.


=head1 ATTRIBUTES

=head2 C<alg>

  my $alg = $me->alg;
  $me->alg('RSA-SHA256');

The algorithm used for the folding of the MagicEnvelope.
Defaults to C<RSA-SHA256>, which is the only supported algorithm.


=head2 C<data>

  my $data = $me->data;
  $me->data('Hello world!');

The decoded data folded in the MagicEnvelope.


=head2 C<data_type>

  my $data_type = $me->data_type;
  $me->data_type('text/plain');

The mime type of the data folded in the MagicEnvelope.
Defaults to C<text/plain>.


=head2 C<dom>

  my $dom = $me->dom;

The L<Mojo::DOM> object of the decoded data,
if the magic envelope contains XML.

B<This attribute is experimental and can change without warning!>


=head2 C<encoding>

  my $encoding = $me->encoding;
  $me->encoding('base64url');

The encoding of the MagicEnvelope.
Defaults to C<base64url>, which is the only encoding supported.


=head2 C<sig_base>

  my $base = $me->sig_base;

The signature base of the MagicEnvelope.


=head2 <signature>

  my $sig = $me->signature('key-01');
  my $sig = $me->signature;

A signature of the MagicEnvelope.
For retrieving a specific signature, pass a key id,
otherwise a default signature will be returned.

If a matching signature is found, the signature
is returned as a hashref, containing data for C<value>
and possibly C<key_id>.
If no matching signature is found, false is returned.

B<This attribute is experimental and can change without warning!>


=head2 C<signed>

  # With key id
  if ($me->signed('key-01')) {
    print "Magic Envelope is signed with key-01.\n";
  }

  # Without key id
  elsif ($me->signed) {
    print "Magic Envelope is signed.\n";
  };

Returns a C<true> value in case the MagicEnvelope is signed at least once.
Accepts optionally a C<key_id> and returns true, if the
MagicEnvelope was signed with this specific key.

B<This attribute is experimental and can change without warning!>


=head1 METHODS


=head2 C<new>

The L<Crypt::MagicSignatures::Envelope> constructor accepts
MagicEnvelope data in various formats.

It accepts MagicEnvelopes in the XML format or an
XML document including an MagicEnvelope C<provenance> element.

  $me = Crypt::MagicSignatures::Envelope->new(<<'MEXML');
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

Additionally it accepts MagicEnvelopes in the JSON notation.

  $me = Crypt::MagicSignatures::Envelope->new(<<'MEJSON');
  {
    "data_type": "text\/plain",
    "data":"U29tZSBhcmJpdHJhcnkgc3RyaW5nLg==",
    "alg":"RSA-SHA256",
    "encoding":"base64url",
    "sigs": [
      { "key_id": "my-01",
        "value":"S1VqYVlIWFpuRGVTX3l4S09CcWdjRV..."
      }
    ]
  }
  MEJSON

The constructor also accepts MagicEnvelopes by defined
attributes (the same as described in the JSON notation),
with the data not encoded.
This is the common way to fold new envelopes.

  $me = Crypt::MagicSignatures::Envelope->new(
    data      => 'Some arbitrary string.',
    data_type => 'plain_text',
    alg       => 'RSA-SHA256',
    encoding  => 'base64url',
    sigs => [
      {
        key_id => 'my-01',
        value  => 'S1VqYVlIWFpuRGVTX3l4S09CcWdjRVFDYVluZkI5U
                   lh4dmRFSnFhQW5XUmpBUEJqZUM0b0lReER4d0IwWG
                   VQZDhzWHAxN3oybWhpTk1vNHViNGNVOVE9PQ=='
      }
    ]
  );

Finally the constructor accepts MagicEnvelopes in the compact
MagicEnvelope notation as described in the
L<MagicSignature Specification|http://salmon-protocol.googlecode.com/svn/trunk/draft-panzer-magicsig-01.html>.

  $me = Crypt::MagicSignatures::Envelope->new(<<'MECOMPACT');
    bXktMDE=.S1VqYVlIWFpuRGVTX3l4S09CcWdjRVFDYVlu
    ZkI5Ulh4dmRFSnFhQW5XUmpBUEJqZUM0b0lReER4d0IwW
    GVQZDhzWHAxN3oybWhpTk1vNHViNGNVOVE9PQ==.U29tZ
    SBhcmJpdHJhcnkgc3RyaW5nLg.dGV4dC9wbGFpbg.YmFz
    ZTY0dXJs.UlNBLVNIQTI1Ng
  MECOMPACT


=head2 C<sign>

  $me->sign( 'key-01' => 'RSA.hgfrhvb ...' )
     ->sign( 'RSA.hgfrhvb ...' );

  my $mkey = Crypt::MagicSignatures::Key->new( 'RSA.hgfrhvb ...' )
  $me->sign( $mkey );

Adds a signature to the MagicEnvelope.

For adding a signature, the private key with an optional
key id has to be given.
The private key can be a
L<Crypt::MagicSignatures::Key> object,
a MagicKey string as described in the
L<Specification|http://salmon-protocol.googlecode.com/svn/trunk/draft-panzer-magicsig-01.html#rfc.section.8.1> or a hashref
containing the parameters accepted by
L<Crypt::MagicSignatures::Key> C<new>.

On success, the method returns the MagicEnvelope,
otherwise it returns a false value.

A MagicEnvelope can be signed multiple times.

B<This method is experimental and can change without warning!>


=head2 C<sign_data>

  $me->sign_data( 'key-01' => 'RSA.hgfrhvb ...' )
     ->sign_data( 'RSA.hgfrhvb ...' );

  my $mkey = Crypt::MagicSignatures::Key->new( 'RSA.hgfrhvb ...' )
  $me->sign_data( $mkey );

Adds a signature to the MagicEnvelope.
Other than C<sign>, this will sign the data instead of the
base string as defined in the
L<Specification|http://salmon-protocol.googlecode.com/svn/trunk/draft-panzer-magicsig-01.html#rfc.section.3.2>.

This is implemented for compatibility with non-standard implementations.


=head2 C<verify>

  $me->verify(
    'RSA...',
    {
      key_id => 'key-01',
      value => 'RSA...',
      verify => 'data'
    },
    'RSA...'
  );

Verifies a signed envelope against a bunch of given public MagicKeys.
Returns true on success. In other case false.

If one key succeeds, the envelope is verified.

An element can be the MagicKey as a string or a
L<Crypt::MagicSignatures::Key> object, or a hash reference,
giving the MagicKey as a C<value>, referring to a certain C<key_id>
and defining the data to C<verify>, either C<sig_base>, C<data> or C<compatible>.
The default is C<sig_base>.
C<sig_base> will verify the sign by the base string as defined in the
L<Specification|http://salmon-protocol.googlecode.com/svn/trunk/draft-panzer-magicsig-01.html#rfc.section.3.2>.
C<data> will verify the sig using the data string, C<compatible> will try both.

B<This method is experimental and can change without warning!>


=head2 C<to_xml>

  $me->to_xml;

Returns the MagicEnvelope as a stringified xml representation.


=head2 C<to_json>

  $me->to_json;

Returns the MagicEnvelope as a stringified json representation.


=head2 C<to_compact>

  $me->to_compact;

Returns the MagicEnvelope as a compact representation.


=head1 DEPENDENCIES

L<Crypt::MagicSignatures::Key>,
L<Mojolicious>.


=head1 KNOWN BUGS AND LIMITATIONS

The signature is currently not working correctly!


=head1 AVAILABILITY

  https://github.com/Akron/Crypt-MagicSignatures


=head1 COPYRIGHT AND LICENSE

Copyright (C) 2011-2013, Nils Diewald.

This program is free software, you can redistribute it and/or modify it under
the same terms as Perl.

=cut
