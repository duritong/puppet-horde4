class horde4::base {

  include php::extensions::bcmath
  include php::extensions::common
  include php::extensions::crypt_blowfish
  include php::extensions::pgsql
  include php::extensions::xml
  include php::extensions::ldap
  include php::packages::geoip
  include php::packages::lzf
  include php::packages::services_weather
  include php::packages::cache
  # include php::packages::intl
  include php::packages::gettext
  include aspell

  include php::packages::idn
  include php::packages::mail_mimedecode
  include gpg

}
