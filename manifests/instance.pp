# an instance of horde
# creates a complete horde installation
define horde4::instance(
  $run_uid,
  $run_gid,
  $ensure           = 'present',
  $domainalias      = 'absent',
  $wwwmail          = false,
  $alarm_cron       = true,
  $upgrade_mode     = false,
  $install_libs     = {
    'webdav_server' => true,
    'date_holidays' => true,
    'imagick'       => true
  },
  $manage_sieve     = true,
  $manage_shorewall = false,
  $manage_nagios    = false,
  $additional_vhost_options = ''
){

  $user_shell = $::operatingsystem ? {
    debian  => '/usr/sbin/nologin',
    ubuntu  => '/usr/sbin/nologin',
    default => '/sbin/nologin'
  }
  $user_homedir = $::operatingsystem ? {
    openbsd => "/var/www/htdocs/${name}",
    default => "/var/www/vhosts/${name}"
  }
  user::managed{$name:
    ensure      => $ensure,
    uid         => $run_uid,
    gid         => $run_gid,
    shell       => $user_shell,
    managehome  => false,
    homedir     => $user_homedir,
    before      => Apache::Vhost::Php::Standard[$name],
  }

  user::groups::manage_user{"apache_in_${name}":
    ensure  => $ensure,
    group   => $name,
    user    => 'apache'
  }

  if $wwwmail {
    user::groups::manage_user{"${name}_in_wwwmailers":
      ensure  => $ensure,
      group   => 'wwwmailers',
      user    => $name
    }
    if ($ensure == 'present') {
      require webhosting::wwwmailers
      User::Groups::Manage_user["${name}_in_wwwmailers"]{
        require => User::Managed[$name],
      }
    }
  }
  apache::vhost::php::standard{$name:
    ensure              => $ensure,
    domainalias         => $domainalias,
    run_mode            => 'fcgid',
    owner               => root,
    group               => $name,
    documentroot_owner  => root,
    documentroot_group  => $name,
    manage_docroot      => false,
    run_uid             => $name,
    run_gid             => $name,
    ssl_mode            => 'force',
    allow_override      => 'FileInfo Limit',
    php_settings        => {
      php_tmp_dir             => "/var/www/vhosts/${name}/tmp/",
      'apc.shm_size'          => '512M',
      safe_mode               => 'Off',
      register_globals        => 'Off',
      magic_quotes_runtime    => 'Off',
      'session.use_trans_sid' => 'Off',
      'session.auto_start'    => 'Off',
      'session.gc_divisor'    => 10000,
      file_uploads            => 'On',
      display_errors          => 'Off',
      include_path            => "/var/www/vhosts/${name}/pear/php",
      open_basedir            => "/var/www/vhosts/${name}/www/:/var/www/vhosts/${name}/pear:/var/www/upload_tmp_dir/${name}/:/var/www/session.save_path/${name}/:/var/www/vhosts/${name}/logs/:/var/www/vhosts/${name}/tmp/:/etc/resolv.conf:/.pearrc:/etc/pki/tls/certs/ca-bundle.crt",
    },
    php_options         => {
      use_pear                => true,
    },
    additional_options  => "${additional_vhost_options}

  ExpiresActive On
  ExpiresByType image/png 'now plus 1 week'
  ExpiresByType image/gif 'now plus 1 week'
  ExpiresByType text/javascript 'now plus 1 week'
  ExpiresByType application/x-javascript 'now plus 1 week'
  ExpiresByType text/css 'now plus 1 week'

  RewriteEngine On
  RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]
  RewriteRule ^/Microsoft-Server-ActiveSync /rpc.php [PT,QSA]

  Alias /autodiscover/autodiscover.xml /var/www/vhosts/${name}/www/rpc.php
  RedirectPermanent /.well-known/carddav /horde/rpc.php

  SetEnv PHP_PEAR_SYSCONF_DIR /var/www/vhosts/${name}
  SetEnv TMPDIR /var/www/vhosts/${name}/tmp

  <DirectoryMatch \"^/var/www/vhosts/${name}/www/(.*/)?(config|lib|locale|po|scripts|templates)/(.*)?\">
    Order deny,allow
    Deny  from all
  </DirectoryMatch>

  <LocationMatch \"^/(.*/)?test.php\">
   Order deny,allow
   Deny  from all
   Allow from localhost
  </LocationMatch>",
    mod_security        => false,
  }

  file{
    "/etc/cron.d/${name}_horde_alarm":;
    "/etc/cron.d/${name}_horde_tmp_cleanup":
      ensure => $ensure;
    "/etc/cron.d/${name}_horde_session_cleanup":
      ensure => $ensure;
  }
  if (!$alarm_cron and $ensure == 'present') or ($ensure != 'present') {
    File["/etc/cron.d/${name}_horde_alarm"]{
      ensure => absent,
    }
  }

  if $ensure == 'present' {

    include horde4::base

    if $manage_sieve {
      include php::packages::net_sieve
      include php::packages::pecl_http
    }

    if $manage_shorewall {
      include shorewall::rules::out::keyserver
      include shorewall::rules::out::imap
      include shorewall::rules::out::pop3
      if $manage_sieve {
        include shorewall::rules::out::managesieve
      }
    }

    require git
    Class['horde4::base'] -> Class['git']
    file{
      "/var/www/vhosts/${name}/pear":
        ensure  => directory,
        seltype => 'httpd_sys_rw_content_t',
        owner   => root,
        group   => $name,
        mode    => '0640';
      "/var/www/vhosts/${name}/tmp":
        ensure  => directory,
        seltype => 'httpd_sys_rw_content_t',
        owner   => $name,
        group   => $name,
        mode    => '0640';
      "/var/www/vhosts/${name}/pear.conf":
        replace => false,
        content => template('horde4/pear.conf.erb'),
        seltype => 'httpd_sys_rw_content_t',
        owner   => root,
        group   => $name,
        mode    => '0640';
      "/var/www/vhosts/${name}/www/static":
        ensure  => directory,
        seltype => 'httpd_sys_rw_content_t',
        owner   => $name,
        group   => $name,
        mode    => '0640';
    }

    exec{
      "install_pear_for_${name}":
        command     => "pear -c /var/www/vhosts/${name}/pear.conf install pear",
        group       => $name,
        creates     => "/var/www/vhosts/${name}/pear/pear",
        require     => File["/var/www/vhosts/${name}/pear.conf"];
      "discover_pear_channel_horde_for_${name}":
        command     => "/var/www/vhosts/${name}/pear/pear -c /var/www/vhosts/${name}/pear.conf channel-discover pear.horde.org",
        timeout     => 1000,
        creates     => "/var/www/vhosts/${name}/pear/php/.channels/pear.horde.org.reg",
        notify      => Exec["fix_horde_perms_for_${name}"],
        group       => $name,
        require     => Exec["install_pear_for_${name}"];
      "install_horde_for_${name}_step_1":
        command     => "/var/www/vhosts/${name}/pear/pear -c /var/www/vhosts/${name}/pear.conf install horde/horde_role",
        timeout     => 1000,
        creates     => "/var/www/vhosts/${name}/pear/php/PEAR/Installer/Role/Horde.xml",
        notify      => Exec["fix_horde_perms_for_${name}"],
        group       => $name,
        require     => Exec["discover_pear_channel_horde_for_${name}"];
      "install_horde_for_${name}_step_2":
        command     => "/var/www/vhosts/${name}/pear/pear -c /var/www/vhosts/${name}/pear.conf install -a -B horde/horde",
        timeout     => 0,
        creates     => "/var/www/vhosts/${name}/www/index.php",
        notify      => Exec["fix_horde_perms_for_${name}"],
        group       => $name,
        require     => Exec["install_horde_for_${name}_step_1"];
      "install_webmail_for_${name}":
        command     => "/var/www/vhosts/${name}/pear/pear -c /var/www/vhosts/${name}/pear.conf install -a -B horde/webmail",
        timeout     => 0,
        creates     => "/var/www/vhosts/${name}/www/imp/index.php",
        group       => $name,
        notify      => Exec["fix_horde_perms_for_${name}"],
        require     => Exec["install_horde_for_${name}_step_2"];
      "install_menmo_for_${name}":
        command     => "/var/www/vhosts/${name}/pear/pear -c /var/www/vhosts/${name}/pear.conf install -a -B horde/mnemo",
        timeout     => 0,
        creates     => "/var/www/vhosts/${name}/www/mnemo/index.php",
        group       => $name,
        notify      => Exec["fix_horde_perms_for_${name}"],
        require     => Exec["install_webmail_for_${name}"];
      "install_passwd_for_${name}":
        command     => "/var/www/vhosts/${name}/pear/pear -c /var/www/vhosts/${name}/pear.conf install -a -B horde/passwd",
        creates     => "/var/www/vhosts/${name}/www/passwd/index.php",
        group       => $name,
        notify      => Exec["install_autoloader_for_${name}"],
        require     => Exec["install_webmail_for_${name}"];
      "install_autoloader_for_${name}":
        command     => "/var/www/vhosts/${name}/pear/pear -c /var/www/vhosts/${name}/pear.conf install -a -B horde/horde_autoloader_cache",
        creates     => "/var/www/vhosts/${name}/pear/horde-autoloader-cache-prune",
        group       => $name,
        notify      => Exec["fix_horde_perms_for_${name}"],
        require     => Exec["install_passwd_for_${name}"];
      "fix_horde_perms_for_${name}":
        command     => "chown root:${name} /var/www/vhosts/${name}/www/* /var/www/vhosts/${name}/pear/* -R",
        before      => File["/var/www/vhosts/${name}/www/static","/var/www/vhosts/${name}/tmp"],
        refreshonly => true;
    }

    if $upgrade_mode {
      file{"/var/www/vhosts/${name}/www/config/conf.php":
        source  => ["puppet:///modules/site_horde4/upgrade-${name}-conf.php",
                    'puppet:///modules/site_horde4/upgrade-conf.php'],
        owner   => 'root',
        group   => $name,
        mode    => '0440',
        require => Exec["install_passwd_for_${name}"];
      }
    } else {
      file{"/var/www/vhosts/${name}/www":
        ensure  => directory,
        source  => "puppet:///modules/site_horde4/${name}/config",
        owner   => 'root',
        group   => $name,
        mode    => '0440',
        recurse => remote,
        force   => true,
        require => Exec["install_passwd_for_${name}"];
      }
    }

    $upgrade_ensure = $upgrade_mode ? {
      true => present,
      false => absent
    }
    file{"/var/www/vhosts/${name}/www/config/registry.d/upgrade-mode.php":
      ensure  => $upgrade_ensure,
      source  => ['puppet:///modules/site_horde4/upgrade-registry.phpr',
                  'puppet:///modules/horde4/upgrade-registry.php'],
      owner   => 'root',
      group   => $name,
      mode    => '0440';
    }

    File["/etc/cron.d/${name}_horde_tmp_cleanup"]{
      content => "1 * * * * ${name} tmpwatch -d 12h /var/www/vhosts/${name}/tmp; tmpwatch 12h /var/www/upload_tmp_dir/${name}\n",
      require => Exec["install_autoloader_for_${name}"],
    }

    # Poor mans session timeout
    File["/etc/cron.d/${name}_horde_session_cleanup"]{
      content => "*/15 * * * * ${name} tmpwatch 40m /var/www/session.save_path/${name}\n",
      require => Exec["install_autoloader_for_${name}"],
    }

    if $alarm_cron {
      File["/etc/cron.d/${name}_horde_alarm"]{
        content => "*/5 * * * * ${name} PHP_PEAR_SYSCONF_DIR=/var/www/vhosts/${name}/ php -d include_path='/var/www/vhosts/${name}/pear/php:/var/www/vhosts/${name}/www' -d error_log='/var/www/vhosts/${name}/logs/php_error_log' -d safe_mode='off' -d error_reporting='E_ALL & ~E_DEPRECATED' /var/www/vhosts/${name}/pear/horde-alarms\n",
        require => Exec["install_webmail_for_${name}"]
      }
    }
  }

  # install additional libs
  $std_install_libs = {
    'webdav_server' => true,
    'date_holidays' => true,
    'imagick'       => true
  }
  $real_install_libs = merge($std_install_libs,$install_libs)

  if $real_install_libs['webdav_server'] {
    exec{
      "install_webdav_server_${name}":
        command => "pear -c /var/www/vhosts/${name}/pear.conf install HTTP_WebDAV_Server-beta",
        creates => "/var/www/vhosts/${name}/pear/php/HTTP/WebDAV/Server.php",
        require => Exec["install_webmail_for_${name}"],
        notify  => Exec["fix_horde_perms_for_${name}"];
    }
  }
  if $real_install_libs['date_holidays'] {
    exec{
      "install_date_holiday_${name}":
        command => "pear -c /var/www/vhosts/${name}/pear.conf install Date_Holidays-alpha#all",
        creates => "/var/www/vhosts/${name}/pear/php/Date/Holidays.php",
        require => Exec["install_webmail_for_${name}"],
        notify  => Exec["fix_horde_perms_for_${name}"];
    }
  }
  if $real_install_libs['imagick'] {
    include php::packages::imagick
  }

# if $manage_nagios {
#   $real_monitor_url = $monitor_url ? {
#     'absent' => $name,
#     default => $monitor_url,
#   }
#   nagios::service::http{$real_monitor_url:
#     ensure => $ensure,
#     check_url => '/imp/login.php',
#     ssl_mode => $ssl_mode,
#     check_code => '301',
#     }
#   }
# }
}
