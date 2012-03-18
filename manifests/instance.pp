define horde4::instance(
  $ensure = 'present',
  $domainalias = 'absent',
  $run_uid,
  $run_gid,
  $wwwmail = false,
  $alarm_cron = true
){

  user::managed{$name:
    ensure => $ensure,
    uid => $run_uid,
    gid => $run_gid,
    shell => $::operatingsystem ? {
      debian => '/usr/sbin/nologin',
      ubuntu => '/usr/sbin/nologin',
      default => '/sbin/nologin'
    },
    managehome => false,
    homedir => $::operatingsystem ? {
      openbsd => "/var/www/htdocs/${name}",
      default => "/var/www/vhosts/${name}"
    },
    before => Apache::Vhost::Php::Standard[$name],
  }

  user::groups::manage_user{"apache_in_${name}":
    ensure => $ensure,
    group => $name,
    user => 'apache'
  }

  if $wwwmail {
    user::groups::manage_user{"${name}_in_wwwmailers":
      ensure => $ensure,
      group => 'wwwmailers',
      user => $name
    }
    if ($ensure == 'present') {
      require webhosting::wwwmailers
      User::Groups::Manage_user["${name}_in_wwwmailers"]{
        require => User::Managed[$name],
      }
    }
  }
  apache::vhost::php::standard{$name:
    ensure => $ensure,
    domainalias => $domainalias,
    run_mode => 'fcgid',
    owner => root,
    group => $name,
    documentroot_owner => root,
    documentroot_group => $name,
    run_uid => $name,
    run_gid => $name,
    ssl_mode => 'force',
    allow_override => 'FileInfo Limit',
    php_settings => {
      disable_functions       => 'sys_get_temp_dir',
      'apc.shm_size'          => '512M',
      safe_mode               => 'Off',
      register_globals        => 'Off',
      magic_quotes_runtime    => 'Off',
      'session.use_trans_sid' => 'Off',
      'session.auto_start'    => 'Off',
      file_uploads            => 'On',
      display_errors          => 'Off',
      register_globals        => 'Off',
      include_path            => "/var/www/vhosts/${name}/pear/php",
      open_basedir            => "/var/www/vhosts/${name}/www/:/var/www/vhosts/${name}/pear:/var/www/upload_tmp_dir/${name}/:/var/www/session.save_path/${name}/:/var/www/vhosts/${name}/logs/:/var/www/vhosts/${name}/tmp/:/etc/resolv.conf:/.pearrc",
    },
    php_options => { use_pear => true },
    additional_options => "

  ExpiresActive On
  ExpiresByType image/png 'now plus 1 week'
  ExpiresByType image/gif 'now plus 1 week'
  ExpiresByType text/javascript 'now plus 1 week'
  ExpiresByType application/x-javascript 'now plus 1 week'
  ExpiresByType text/css 'now plus 1 week'

  RewriteEngine On
  RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization},L]
  RewriteRule ^/Microsoft-Server-ActiveSync /rpc.php [PT,L,QSA]

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
    mod_security => false,
  }

  file{
    "/etc/cron.d/${name}_horde_alarm":;
    "/etc/cron.d/${name}_horde_tmp_cleanup":
      ensure => $ensure;
  }
  if (!$alarm_cron and $ensure == 'present') or ($ensure != 'present') {
    File["/etc/cron.d/${name}_horde_alarm"]{
      ensure => absent,
    }
  }

  if $ensure == 'present' {
    require horde4::base
    require git
    file{
      "/var/www/vhosts/${name}/pear":
        ensure => directory,
        seltype => 'httpd_sys_rw_content_t',
        owner => root, group => $name, mode => 0640;
      "/var/www/vhosts/${name}/tmp":
        ensure => directory,
        seltype => 'httpd_sys_rw_content_t',
        owner => $name, group => $name, mode => 0640;
      "/var/www/vhosts/${name}/pear.conf":
        replace => false,
        content => template('horde4/pear.conf.erb'),
        seltype => 'httpd_sys_rw_content_t',
        owner => root, group => $name, mode => 0640;
       "/var/www/vhosts/${name}/www/static":
        ensure => directory,
        seltype => 'httpd_sys_rw_content_t',
        owner => $name, group => $name, mode => 0640;
    }

    exec{
      "instal_pear_for_${name}":
        command => "pear -c /var/www/vhosts/${name}/pear.conf install pear",
        group => $name,
        creates => "/var/www/vhosts/${name}/pear/pear";
      "install_horde_for_${name}":
        command => "/var/www/vhosts/${name}/pear/pear -c /var/www/vhosts/${name}/pear.conf install -a -B horde/horde",
        creates => "/var/www/vhosts/${name}/www/index.php",
        notify => Exec["fix_horde_perms_for_${name}"],
        group => $name,
        require => Exec["instal_pear_for_${name}"];
      "install_webmail_for_${name}":
        command => "/var/www/vhosts/${name}/pear/pear -c /var/www/vhosts/${name}/pear.conf install -a -B horde/webmail",
        creates => "/var/www/vhosts/${name}/www/index.php",
        group => $name,
        notify => Exec["fix_horde_perms_for_${name}"],
        require => Exec["install_horde_for_${name}"];
      "install_menmo_for_${name}":
        command => "/var/www/vhosts/${name}/pear/pear -c /var/www/vhosts/${name}/pear.conf install -a -B horde/mnemo",
        creates => "/var/www/vhosts/${name}/www/mnemo/index.php",
        group => $name,
        notify => Exec["fix_horde_perms_for_${name}"],
        require => Exec["install_webmail_for_${name}"];
      "install_passwd_for_${name}":
        command => "/var/www/vhosts/${name}/pear/pear -c /var/www/vhosts/${name}/pear.conf install -a -B horde/passwd",
        creates => "/var/www/vhosts/${name}/www/passwd/index.php",
        group => $name,
        notify => Exec["fix_horde_perms_for_${name}"],
        require => Exec["install_webmail_for_${name}"];
      "fix_horde_perms_for_${name}":
        command => "chown root:${name} /var/www/vhosts/${name}/www/* /var/www/vhosts/${name}/pear/* -R",
        refreshonly => true;
      "init_git_repo_for_horde_${name}":
        command => "git init",
        creates => "/var/www/vhosts/${name}/www/.git",
        cwd => "/var/www/vhosts/${name}/www",
        require => Exec["fix_horde_perms_for_${name}"];
    }

    file{"/var/www/vhosts/${name}/www/.gitignore":
      content => "*
!config/
!config/*
config/.htaccess
!*/
!*/config/
!*/config/*
*/config/.htaccess
",
      replace => false,
      seltype => 'httpd_sys_rw_content_t',
      require => Exec["init_git_repo_for_horde_${name}"],
      owner => root, group => root, mode => 0640;
    }

    File["/etc/cron.d/${name}_horde_tmp_cleanup"]{
      content => "1 * * * * ${name} tmpwatch 12h /var/www/vhosts/${name}/tmp\n",
    }

    if $alarm_cron {
      File["/etc/cron.d/${name}_horde_alarm"]{
        content => "*/5 * * * * ${name} /var/www/vhosts/${name}/pear/horde-alarms\n",
        require => Exec["install_webmail_for_${name}"]
      }
    }
  }


/*
  if hiera('use_nagios',false) {
    $real_monitor_url = $monitor_url ? {
      'absent' => $name,
      default => $monitor_url,
    }
    nagios::service::http{"${real_monitor_url}":
      ensure => $ensure,
      check_url => '/imp/login.php',
      ssl_mode => $ssl_mode,
      check_code => $horde::install_type ? {
        'git4' => '301',
        default => 'OK',
      }
    }
  }
*/

}
