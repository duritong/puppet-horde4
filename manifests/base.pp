class horde4::base(
  $manage_sieve = hiera('horde4_manage_sieve',true)
){

  include php::extensions::common
  include php::extensions::crypt_blowfish
  include php::extensions::pgsql
  include php::extensions::xml
  include php::packages::geoip
  include php::packages::lzf
  include php::packages::services_weather
  include php::packages::cache
  include php::packages::intl
  include php::packages::gettext
  include aspell

  include php::packages::idn
  include php::packages::mail_mimedecode
  include gpg

  if $horde4::base::manage_sieve {
    include php::packages::net_sieve
  }

  if hiera('use_shorewall',false) {
    include shorewall::rules::out::keyserver
    include shorewall::rules::out::imap
    include shorewall::rules::out::pop3
    if $horde4::base::manage_sieve {
      include shorewall::rules::out::managesieve
    }
  }
}
