use strict;
use warnings;
use Module::Build;

Module::Build->new(
  module_name          => 'Crypt::ScryptKDF',
  dist_abstract        => 'Scrypt password based key derivation function',
  dist_author          => 'Karel Miko',
  dist_version_from    => 'lib/Crypt/ScryptKDF.pm',
  license              => 'perl',
  create_readme        => 1,
  requires             => {
    'MIME::Base64' => 0,
  },
  build_requires       => {
    'MIME::Base64' => 0,
    'Test::More'   => 0,
  },
  c_source             => 'src',
)->create_build_script;
