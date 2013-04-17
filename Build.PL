use strict;
use warnings;
use Module::Build;

Module::Build->new(
  module_name          => 'Crypt::ScryptKDF',
  dist_abstract        => 'Scrypt password based key derivation function',
  dist_author          => 'Karel Miko',
  dist_version_from    => 'lib/Crypt/ScryptKDF.pm',
  license              => 'perl',
  c_source             => 'src',
  requires             => {
    'MIME::Base64'  => 0,
    'parent'        => 0,
  },
  build_requires       => {
    'MIME::Base64'  => 0,
    'parent'        => 0,
    'Module::Build' => 0,
    'Test::More'    => 0,
  },
  configure_requires   => {
    'Module::Build' => 0,
  },
)->create_build_script;
