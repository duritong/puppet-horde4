class horde4::base{

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

}
