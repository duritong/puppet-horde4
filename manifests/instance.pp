# an instance of horde
# creates a complete horde installation
define horde4::instance (
  $run_uid,
  $run_gid,
  $ensure                   = 'present',
  $domainalias              = 'absent',
  $wwwmail                  = false,
  $alarm_cron               = true,
  $upgrade_mode             = false,
  $install_libs             = {
    'webdav_server' => true,
    'date_holidays' => true,
    'imagick'       => true,
  },
  $manage_sieve             = true,
  $manage_firewall          = false,
  $manage_nagios            = false,
  $additional_vhost_options = '',
  $additional_php_options   = '',
  $php_installation         = 'scl56',
  $php_run_mode             = 'fcgid',
  $php_options              = {},
  $php_settings             = {},
  $configuration            = {},
) {
  $user_shell = $facts['os']['name'] ? {
    'debian' => '/usr/sbin/nologin',
    'ubuntu' => '/usr/sbin/nologin',
    default  => '/sbin/nologin'
  }
  $user_homedir = $facts['os']['name'] ? {
    'openbsd' => "/var/www/htdocs/${name}",
    default   => "/var/www/vhosts/${name}"
  }
  user::managed { $name:
    ensure     => $ensure,
    uid        => $run_uid,
    gid        => $run_gid,
    shell      => $user_shell,
    managehome => false,
    homedir    => $user_homedir,
    before     => Apache::Vhost::Php::Standard[$name],
  }

  user::groups::manage_user { "apache_in_${name}":
    ensure => $ensure,
    group  => $name,
    user   => 'apache',
  }

  if $wwwmail {
    user::groups::manage_user { "${name}_in_wwwmailers":
      ensure => $ensure,
      group  => 'wwwmailers',
      user   => $name,
    }
    if ($ensure == 'present') {
      require webhosting::wwwmailers
      User::Groups::Manage_user["${name}_in_wwwmailers"] {
        require => User::Managed[$name],
      }
    }
  }
  if versioncmp(guess_apache_version(),'2.4.') >= 0 {
    $deny_statement = 'Require all denied'
  } else {
    $deny_statement = "Order allow,deny\n    Deny From All"
  }
  apache::vhost::php::standard { $name:
    ensure             => $ensure,
    configuration      => $configuration,
    domainalias        => $domainalias,
    run_mode           => $php_run_mode,
    owner              => root,
    group              => $name,
    documentroot_owner => root,
    documentroot_group => $name,
    manage_docroot     => false,
    run_uid            => $name,
    run_gid            => $name,
    php_installation   => $php_installation,
    ssl_mode           => 'force',
    allow_override     => 'All',
    php_options        => {
      additional_open_basedir => "/var/www/vhosts/${name}/pear/:/var/www/vhosts/${name}/logs/:/etc/resolv.conf:/.pearrc:/etc/pki/tls/certs/ca-bundle.crt",
      additional_envs         => {
        'PHP_PEAR_SYSCONF_DIR' => "/var/www/vhosts/${name}",
      },
    } + $php_options,
    php_settings       => {
      safe_mode               => 'Off',
      register_globals        => 'Off',
      magic_quotes_runtime    => 'Off',
      'session.use_trans_sid' => 'Off',
      'session.auto_start'    => 'Off',
      'session.gc_divisor'    => 10000,
      file_uploads            => 'On',
      display_errors          => 'Off',
      include_path            => "/var/www/vhosts/${name}/pear/php",
    } + $php_settings,
    additional_options => "${additional_vhost_options}

  ExpiresActive On
  ExpiresByType image/png 'now plus 1 week'
  ExpiresByType image/gif 'now plus 1 week'
  ExpiresByType text/javascript 'now plus 1 week'
  ExpiresByType application/x-javascript 'now plus 1 week'
  ExpiresByType text/css 'now plus 1 week'

  RewriteEngine On
  RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]
  RewriteRule ^/Microsoft-Server-ActiveSync /rpc.php [PT,QSA]
  RewriteRule ^/autodiscover/autodiscover.xml /rpc.php [PT,QSA]

  RedirectPermanent /.well-known/carddav /rpc.php
  RedirectPermanent /.well-known/caldav /rpc.php

  <DirectoryMatch \"^/var/www/vhosts/${name}/www/(.*/)?(config|lib|locale|po|scripts|templates)/(.*)?\">
    ${deny_statement}
  </DirectoryMatch>

  <LocationMatch \"^/(.*/)?test.php\">
    ${deny_statement}
  </LocationMatch>",
    mod_security       => false,
  }

  file {
    "/etc/cron.d/${name}_horde_alarm":;
    "/etc/cron.d/${name}_horde_tmp_cleanup":
      ensure => $ensure;
    "/etc/cron.d/${name}_horde_session_cleanup":
      ensure => $ensure;
  }
  if (!$alarm_cron and $ensure == 'present') or ($ensure != 'present') {
    File["/etc/cron.d/${name}_horde_alarm"] {
      ensure => absent,
    }
  }

  if $ensure == 'present' {
    include horde4::base

    if $manage_firewall {
      include firewall::rules::out::keyserver
      include firewall::rules::out::imap
      include firewall::rules::out::pop3
      if $manage_sieve {
        include firewall::rules::out::managesieve
      }
    }

    if $php_installation =~ /^scl/ {
      $php_inst = regsubst($php_installation,'^scl','php')
      require "::php::scl::${php_inst}"
      $scl_name = getvar("php::scl::${php_inst}::scl_name")
    } else {
      # TODO: install cmds in the next sections need to be adapted
      fail('This module currently only supports installation with SCLs')
    }

    $data_dir = "/var/www/vhosts/${name}/data"
    file {
      ["/var/www/vhosts/${name}/pear", "/var/www/vhosts/${name}/scripts"]:
        ensure => directory,
        owner  => root,
        group  => $name,
        mode   => '0640';
      ["${data_dir}/token", "${data_dir}/cache", "${data_dir}/vfs"]:
        ensure  => directory,
        seltype => 'httpd_sys_rw_content_t',
        owner   => $name,
        group   => $name,
        mode    => '0640';
      "/var/www/vhosts/${name}/pear.conf":
        replace => false,
        content => template('horde4/pear.conf.erb'),
        owner   => root,
        group   => $name,
        mode    => '0640';
      "/var/www/vhosts/${name}/www/static":
        ensure  => directory,
        seltype => 'httpd_sys_rw_content_t',
        owner   => $name,
        group   => $name,
        mode    => '0640';
      "/var/www/vhosts/${name}/scripts/horde_cleanup_user.php":
        ensure => absent;
      "/var/www/vhosts/${name}/scripts/horde_cleanup_user.sh":
        content => "#!/bin/bash\nscl enable ${scl_name} \"PHP_PEAR_SYSCONF_DIR=/var/www/vhosts/${name}/ php -d include_path='/var/www/vhosts/${name}/pear/php:/var/www/vhosts/${name}/www' -d error_log='/var/www/vhosts/${name}/logs/php_error_log' -d safe_mode='off' -d error_reporting='E_ALL' /var/www/vhosts/${name}/pear/horde-remove-user-data $@\"\n",
        owner   => root,
        group   => $name,
        mode    => '0550';
    }

    exec {
      "install_pear_for_${name}":
        command => "scl enable ${scl_name} 'pear -c /var/www/vhosts/${name}/pear.conf install --force pear'",
        group   => $name,
        creates => "/var/www/vhosts/${name}/pear/pear",
        require => File["/var/www/vhosts/${name}/pear.conf"];
      "discover_pear_channel_horde_for_${name}":
        command => "scl enable ${scl_name} '/var/www/vhosts/${name}/pear/pear -c /var/www/vhosts/${name}/pear.conf channel-discover pear.horde.org'",
        timeout => 1000,
        creates => "/var/www/vhosts/${name}/pear/php/.channels/pear.horde.org.reg",
        group   => $name,
        require => File["/var/www/vhosts/${name}/pear.conf"];
      "install_horde_for_${name}_step_1":
        command => "scl enable ${scl_name} '/var/www/vhosts/${name}/pear/pear -c /var/www/vhosts/${name}/pear.conf install horde/horde_role'",
        timeout => 1000,
        creates => "/var/www/vhosts/${name}/pear/php/PEAR/Installer/Role/Horde.xml",
        notify  => Exec["fix_horde_perms_for_${name}"],
        group   => $name,
        require => Exec["discover_pear_channel_horde_for_${name}"];
      "install_horde_for_${name}_step_2":
        command => "scl enable ${scl_name} '/var/www/vhosts/${name}/pear/pear -c /var/www/vhosts/${name}/pear.conf install -a -B horde/horde'",
        timeout => 0,
        creates => "/var/www/vhosts/${name}/www/index.php",
        notify  => Exec["fix_horde_perms_for_${name}"],
        group   => $name,
        require => Exec["install_horde_for_${name}_step_1"];
      "install_webmail_for_${name}":
        command => "scl enable ${scl_name} '/var/www/vhosts/${name}/pear/pear -c /var/www/vhosts/${name}/pear.conf install -a -B horde/webmail'",
        timeout => 0,
        creates => "/var/www/vhosts/${name}/www/imp/index.php",
        group   => $name,
        notify  => Exec["fix_horde_perms_for_${name}"],
        require => Exec["install_horde_for_${name}_step_2"];
      "install_passwd_for_${name}":
        command => "scl enable ${scl_name} '/var/www/vhosts/${name}/pear/pear -c /var/www/vhosts/${name}/pear.conf install -a -B horde/passwd'",
        creates => "/var/www/vhosts/${name}/www/passwd/index.php",
        group   => $name,
        notify  => Exec["install_autoloader_for_${name}"],
        require => Exec["install_webmail_for_${name}"];
      "install_autoloader_for_${name}":
        command => "scl enable ${scl_name} '/var/www/vhosts/${name}/pear/pear -c /var/www/vhosts/${name}/pear.conf install -a -B horde/horde_autoloader_cache'",
        creates => "/var/www/vhosts/${name}/pear/horde-autoloader-cache-prune",
        group   => $name,
        notify  => Exec["fix_horde_perms_for_${name}"],
        require => Exec["install_passwd_for_${name}"];
      "fix_horde_perms_for_${name}":
        command     => "chown -R root:${name} /var/www/vhosts/${name}/www/* /var/www/vhosts/${name}/pear/*",
        before      => File["/var/www/vhosts/${name}/www/static","/var/www/vhosts/${name}/data"],
        refreshonly => true;
      "initial_db_seed_for_${name}":
        command     => "scl enable ${scl_name} \"PHP_PEAR_SYSCONF_DIR=/var/www/vhosts/${name} php -d include_path='/var/www/vhosts/${name}/pear/php:/var/www/vhosts/${name}/www' -d error_log='/var/www/vhosts/${name}/logs/php_error_log' -d safe_mode='off' /var/www/vhosts/${name}/pear/horde-db-migrate\"",
        user        => $name,
        group       => $name,
        subscribe   => Exec["fix_horde_perms_for_${name}"],
        require     => Service['apache'],
        refreshonly => true;
      # somehow we need to run it twice
      "initial_db_seed_for_${name}_2":
        command     => "scl enable ${scl_name} \"PHP_PEAR_SYSCONF_DIR=/var/www/vhosts/${name} php -d include_path='/var/www/vhosts/${name}/pear/php:/var/www/vhosts/${name}/www' -d error_log='/var/www/vhosts/${name}/logs/php_error_log' -d safe_mode='off' /var/www/vhosts/${name}/pear/horde-db-migrate\"",
        user        => $name,
        group       => $name,
        subscribe   => Exec["initial_db_seed_for_${name}"],
        require     => Service['apache'],
        refreshonly => true;
      "fix_horde_perms_for_${name}_2":
        command     => "chown -R ${name} /var/www/vhosts/${name}/data/cache/* /var/www/vhosts/${name}/logs/horde* && restorecon -R /var/www/vhosts/${name}",
        subscribe   => Exec["initial_db_seed_for_${name}_2"],
        refreshonly => true;
    }

    if $upgrade_mode {
      file { "/var/www/vhosts/${name}/www/config/conf.php":
        source  => ["puppet:///modules/site_horde4/upgrade-${name}-conf.php",
        'puppet:///modules/site_horde4/upgrade-conf.php'],
        seltype => 'httpd_sys_rw_content_t',
        owner   => 'root',
        group   => $name,
        mode    => '0440',
        require => Exec["install_passwd_for_${name}"];
      }
    } else {
      file { "/var/www/vhosts/${name}/www":
        ensure       => directory,
        source       => ["puppet:///modules/site_horde4/${name}/config",
          'puppet:///modules/site_horde4/config',
          "puppet:///modules/ib_horde/${name}/config",
          'puppet:///modules/ib_horde/config',
        ],
        seltype      => 'httpd_sys_rw_content_t',
        sourceselect => 'all',
        owner        => 'root',
        group        => $name,
        mode         => '0440',
        recurse      => remote,
        force        => true,
        before       => Service['apache'],
        require      => Exec["install_passwd_for_${name}"];
      }
    }

    $upgrade_ensure = $upgrade_mode ? {
      true  => present,
      false => absent
    }
    file { "/var/www/vhosts/${name}/www/config/registry.d/upgrade-mode.php":
      ensure  => $upgrade_ensure,
      source  => ['puppet:///modules/site_horde4/upgrade-registry.php',
      'puppet:///modules/horde4/upgrade-registry.php'],
      owner   => 'root',
      group   => $name,
      seltype => 'httpd_sys_rw_content_t',
      mode    => '0440';
    }

    require tmpwatch
    File["/etc/cron.d/${name}_horde_tmp_cleanup"] {
      content => "1 * * * * ${name} tmpwatch -q -d 12h /var/www/vhosts/${name}/data/ /var/www/vhosts/${name}/tmp/uploads/ /var/www/vhosts/${name}/tmp/tmp\n",
      require => [Exec["install_autoloader_for_${name}"],Package['tmpwatch']],
    }

    # Poor mans session timeout
    File["/etc/cron.d/${name}_horde_session_cleanup"] {
      content => "*/15 * * * * ${name} tmpwatch 40m /var/www/vhosts/${name}/tmp/sessions/\n",
      require => [Exec["install_autoloader_for_${name}"],Package['tmpwatch']],
    }

    if $alarm_cron {
      File["/etc/cron.d/${name}_horde_alarm"] {
        content => "*/5 * * * * ${name} scl enable ${scl_name} \"PHP_PEAR_SYSCONF_DIR=/var/www/vhosts/${name}/ php -d include_path='/var/www/vhosts/${name}/pear/php:/var/www/vhosts/${name}/www' -d error_log='/var/www/vhosts/${name}/logs/php_error_log' -d safe_mode='off' -d error_reporting='E_ALL & ~E_DEPRECATED' -d apc.enable_cli=1 /var/www/vhosts/${name}/pear/horde-alarms\"\n",
        require => Exec["install_webmail_for_${name}"]
      }
    }
  }

  # install additional libs
  $std_install_libs = {
    'webdav_server' => true,
    'date_holidays' => true,
    'imagick'       => true,
  }
  $real_install_libs = merge($std_install_libs,$install_libs)

  if $real_install_libs['webdav_server'] {
    exec {
      "install_webdav_server_${name}":
        command => "scl enable ${scl_name} '/var/www/vhosts/${name}/pear/pear -c /var/www/vhosts/${name}/pear.conf install HTTP_WebDAV_Server-beta'",
        creates => "/var/www/vhosts/${name}/pear/php/HTTP/WebDAV/Server.php",
        require => Exec["install_webmail_for_${name}"],
        notify  => Exec["fix_horde_perms_for_${name}"];
    }
  }
  if $real_install_libs['date_holidays'] {
    exec {
      "install_date_holiday_${name}":
        command => "scl enable ${scl_name} '/var/www/vhosts/${name}/pear/pear -c /var/www/vhosts/${name}/pear.conf install --force Date_Holidays-alpha#all'",
        creates => "/var/www/vhosts/${name}/pear/php/Date/Holidays.php",
        require => Exec["install_webmail_for_${name}"],
        notify  => Exec["fix_horde_perms_for_${name}"];
    }
  }
}
