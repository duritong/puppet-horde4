define horde4::instance(
  $ensure = 'present',
  $domainalias = 'absent',
  $run_uid,
  $run_gid,
  $wwwmail = false
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
  $additional_fcgi_options = '    RewriteEngine On
  RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization},L]
'
  apache::vhost::php::standard{$name:
    ensure => $ensure,
    domainalias => $domainalias,
    run_mode => 'fcgid',
    owner => root,
    group => $name,
    run_uid => $name,
    run_gid => $name,
    ssl_mode => 'force',
    options => 'FileInfo',
    php_settings => {
      safe_mode               => 'Off',
      register_globals        => 'Off',
      magic_quotes_runtime    => 'Off',
      'session.use_trans_sid' => 'Off',
      'session.auto_start'    => 'Off',
      file_uploads            => 'On',
      display_errors          => 'Off',
      register_globals        => 'Off',
      include_path            => "/var/www/vhosts/${name}/pear/php",
      open_basedir            => "/var/www/vhosts/${name}/www/:/var/www/vhosts/${name}/pear:/var/www/upload_tmp_dir/${name}/:/var/www/session.save_path/${name}/:/var/www/vhosts/${name}/logs/:/var/www/vhosts/${name}/tmp/",
    },
    php_options => { use_pear => true },
    additional_options => "
  RewriteEngine On
  RewriteRule ^/Microsoft-Server-ActiveSync /horde/rpc.php [PT,L,QSA]
  SetEnv PHP_PEAR_SYSCONF_DIR /var/www/vhosts/${name}
  <DirectoryMatch \"^/var/www/vhosts/${name}/www/(.*/)?(config|lib|locale|po|scripts|templates)/(.*)?\">
    Order deny,allow
    Deny  from all
  </DirectoryMatch>

  <LocationMatch \"^/(.*/)?test.php\">
   Order deny,allow
   Deny  from all
   Allow from localhost
  </LocationMatch>
  ${additional_fcgi_options}",
    mod_security => false,
  }

  if $ensure == 'present' {
    require horde4::base
    require git

    file{
      "/var/www/vhosts/${name}/pear":
        ensure => directory,
        owner => root, group => $name, mode => 0640;
      "/var/www/vhosts/${name}/tmp":
        ensure => directory,
        owner => $name, group => $name, mode => 0640;
      "/var/www/vhosts/${name}/pear.conf":
        replace => false,
        content => template('horde4/pear.conf.erb'),
        owner => root, group => $name, mode => 0640;
       "/var/www/vhosts/${name}/www/static":
        ensure => directory,
        owner => $name, group => $name, mode => 0640;
    }

    exec{
      "instal_pear_for_${name}":
        command => "pear -c /var/www/vhosts/${name}/pear.conf install pear",
        user => $name,
        creates => "/var/www/vhosts/${name}/pear/pear";
      "install_horde_for_${name}":
        command => "/var/www/vhosts/${name}/pear/pear -c /var/www/vhosts/${name}/pear.conf install -a -B horde/horde",
        creates => "/var/www/vhosts/${name}/www/index.php",
        notify => Exec["fix_horde_perms_for_${name}"],
        user => $name,
        require => Exec["instal_pear_for_${name}"];
      "install_horde_for_${name}":
        command => "/var/www/vhosts/${name}/pear/pear -c /var/www/vhosts/${name}/pear.conf install -a -B horde/webmail",
        creates => "/var/www/vhosts/${name}/www/index.php",
        user => $name,
        notify => Exec["fix_horde_perms_for_${name}"],
        require => Exec["instal_horde_for_${name}"];
      "install_menmo_for_${name}":
        command => "/var/www/vhosts/${name}/pear/pear -c /var/www/vhosts/${name}/pear.conf install -a -B horde/mnemo",
        creates => "/var/www/vhosts/${name}/www/mnemo/index.php",
        user => $name,
        notify => Exec["fix_horde_perms_for_${name}"],
        require => Exec["instal_horde_for_${name}"];
      "install_htpasswd_for_${name}":
        command => "/var/www/vhosts/${name}/pear/pear -c /var/www/vhosts/${name}/pear.conf install -a -B horde/passwd",
        creates => "/var/www/vhosts/${name}/www/passwd/index.php",
        user => $name,
        notify => Exec["fix_horde_perms_for_${name}"],
        require => Exec["instal_horde_for_${name}"];
      "fix_horde_perms_for_${name}":
        command => "chown root:${name} /var/www/vhosts/${name}/www/* -R",
        refreshonly => true;
      "init_git_repo_for_horde_${name}":
        command => "git init",
        creates => "/var/www/vhosts/${name}/www/.git",
        cwd => "/var/www/vhosts/${name}/www",
        require => Exec["fix_horde_perms_for_${name}"];
    }

    file{"/var/www/vhosts/${name}/www/.gitignore":
      content => "*\n!config/*\n!*!*/config/\n",
      replace => false,
      require => Exec["init_git_repo_for_horde_${name}"],
      owner => root, group => root, mode => 0640;
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
