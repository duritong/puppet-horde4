#!/usr/bin/env php
<?php

function verbose($msg, $type = 'cli.message')
{
  if (!$GLOBALS['verbose'])
    return false;
  $prefix = (!empty($GLOBALS['vprefix'])) ? $GLOBALS['vprefix'] . ' ' : '';
  return $GLOBALS['cli']->message($prefix . $msg, $type);
}

# initialize horde
require_once 'PEAR/Config.php';
$baseDir = PEAR_Config::singleton()->get('horde_dir', null, 'pear.horde.org');

# initialize kronolith instead of horde as we need the tagger instance
require_once $baseDir . '/kronolith/lib/Application.php';
Horde_Registry::appInit('kronolith', array(
  'cli' => true,
  'authentication' => 'none',
  'user_admin' => true
));

require_once $baseDir . '/content/lib/Application.php';
Horde_Registry::appInit('content', array(
  'cli' => true,
  'user_admin' => true
));
require CONTENT_BASE . '/lib/Tags/Tag.php';
require CONTENT_BASE . '/lib/Tags/TagMapper.php';
require CONTENT_BASE . '/lib/Objects/ObjectMapper.php';

# parse commandline options
$c = new Console_Getopt();
$argv = $c->readPHPArgv();
array_shift($argv);
if (empty($argv) || empty($argv[0]))
{
  $cli->writeln(
    $cli->bold('Syntax: ') .
    $cli->blue($_SERVER['argv'][0]) .
    $cli->green(' [-vf]') .
    $cli->red(' <user>')
  );
  exit(1);
}
$options = $c->getopt2($argv, 'fv');
if (PEAR::isError($options))
  $cli->fatal($options->getMessage());
$user      = $options[1][0];
$regexp    = '^'.$user.'$';
$doremove  = false;
$GLOBALS['verbose'] = false;
foreach ($options[0] as $val)
{
  switch($val[0])
  {
    case 'f':
      $doremove = true;
      break;
    case 'v':
      $GLOBALS['verbose'] = true;
      break;
  }
}

if (!$doremove)
{
  $cli->message('DO_NOT_REMOVE-flag is set!', 'cli.warning');
  if (!$GLOBALS['verbose'])
  {
    $cli->message('Enabling verbose mode...');
    $GLOBALS['verbose'] = true;
  }
}

# connect to database
try
{
  $db = $GLOBALS['injector']->getInstance('Horde_Core_Factory_Db')->create('horde', 'removeUser');
}
catch(Horde_Db_Exception $e)
{
  $cli->fatal('Unable to connect to the database: ' . $e);
}

# fetch users from horde_prefs
try
{
  $result = $db->selectValues(
    'SELECT ' . $db->distinct('pref_uid') . ' ' .
    'FROM horde_prefs');
  $users = array();
  foreach($result as $u)
  {
    if (preg_match('/'.$regexp.'/', $u))
      $users[] = $u;
  }
}
catch (Horde_Db_Exception $e)
{
  $cli->fatal('Unable to select from table \'horde_prefs\': ' . $e);
}

if (empty($users))
{
  verbose('No users with syntax "' . $regexp . '" found (no prefs exist)', 'cli.error');
  exit(0);
}

# fetch and check active sessions
try
{
  $sessionHandler = $GLOBALS['injector']->createInstance('Horde_SessionHandler');
  $sessions = $sessionHandler->getSessionsInfo();
  $loggedin = array();
  foreach ($sessions as $sid => $data)
  {
    if (preg_match('/'.$regexp.'/', $data['userid']))
    {
      # we're unable to delete sessions from phps builtin sessionhandler
      #$session->sessionHandler->destroy($sid);
      $loggedin[$data['userid']] = true;
    }
  }
}
catch(Horde_SessionHandler_Exception $e)
{
  $cli->fatal('Session counting is not supported with the current session handler.');
}
if (!empty($loggedin))
  $cli->fatal('The following users cannot be removed as they are currently logged in: ' . join(' ', array_keys($loggedin)));

# list users which will be removed
verbose('I\'ll delete the following users:');
foreach($users as $u)
  verbose('  ' . $u);

# get tagger
$tagger = $GLOBALS['injector']->getInstance('Content_Tagger');

# finally remove the data
# NOTE: we're unable to remove every object references especially in rampage
# thus we take care of that in a separate cron: cleanup_rampage.php
if ($doremove)
{
  foreach($users as $user)
  {
    $cli->message(str_repeat('-', 30), 'cli.success');
    $cli->message('Processing ' . $user . '...', 'cli.success');

    # remove tags
    try
    {
      $GLOBALS['vprefix'] = $cli->yellow('[ Content ]');
      $tUserId = current($GLOBALS['injector']->getInstance('Content_Users_Manager')->ensureUsers($user));
      $tTags = $tagger->getTags(array('userId' => $tUserId));
      foreach($tTags as $tTagId => $tTag)
      {
        $tObjects = $tagger->getObjects(array('tagId' => $tTagId, 'userId' => $tUserId));
        foreach($tObjects as $tObjectId => $tObject)
        {
          verbose(sprintf('Removing tag "%s/%d" from object "%s/#%d"...', $tTag, $tTagId, $tObject, $tObjectId), 'cli.none');
          $tagger->untag($tUserId, $tObjectId, $tTagId);

          # housekeeping: check if objects are used anymore
          verbose(sprintf('Removing object "%s/#%d"...', $tObject, $tObjectId), 'cli.none');
          $mapper = new Content_ObjectMapper($injector->getInstance('Horde_Db_Adapter'));
          $mapper->delete($tObjectId);
        }

        # housekeeping: check if tags are used anymore
        $tObjects = $tagger->getObjects(array('tagId' => $tTagId));
        if (empty($tObjects))
        {
          verbose(sprintf('Removing tag "%s/#%d" as it isn\'t used any more...', $tTag, $tTagId), 'cli.none');
          $mapper = new Content_TagMapper($injector->getInstance('Horde_Db_Adapter'));
          $mapper->delete($tTagId);
        }
      }
    }
    catch(Horde_Db_Exception $e)
    {
      # fatal/exit is safe here as we don't care much
      # about a consistent content database
      $cli->fatal('Error while removing tags: ' . $e);
    }

    # remove SyncML anchors and maps
    try
    {
      $GLOBALS['vprefix'] = $cli->yellow('[ SyncML  ]');
      $syncml = Horde_SyncMl_Backend::factory('Horde');
      $devices = $syncml->getUserAnchors($user);
      if (!empty($devices))
      {
        verbose('Removing session...', 'cli.none');
        $syncml->removeAnchor($user);
        $syncml->removeMaps($user);
      }
    }
    catch(Horde_Exception $e)
    {
      # fatal/exit is safe here as we don't care much
      # about a consistent syncml database
      $cli->fatal('Error while removing SyncML session: ' . $e);
    }

    # remove ActiveSync devices
    try
    {
      $GLOBALS['vprefix'] = $cli->yellow('[ ActSync ]');
      $activesync = $GLOBALS['injector']->getInstance('Horde_ActiveSyncState');
      $activesync->setLogger($GLOBALS['injector']->getInstance('Horde_Log_Logger'));
      $devices = $activesync->listDevices($user);
      if (!empty($devices))
        verbose('Removing devices...', 'cli.none');
      foreach ($devices as $device)
        $activesync->removeState(null, $device['device_id'], $user);
    }
    catch(Horde_ActiveSync_Exception $e)
    {
      # fatal/exit is safe here as we don't care much
      # about a consistent activesync database
      $cli->fatal('Error while removing ActiveSync devices: ' . $e);
    }

    # remove history
    try
    {
      $GLOBALS['vprefix'] = $cli->yellow('[ History ]');
      verbose('Removing data...', 'cli.none');
      $db->delete('DELETE FROM horde_histories WHERE history_who = ?', array($user));
    }
    catch(Horde_Db_Exception $e)
    {
      # fatal/exit is safe here as we don't care much
      # about a consistent history database
      $cli->fatal('Error while removing history: ' . $e);
    }

    # remove user data
    # NOTE: this will leave/add an delete-entry in horde_histories
    # belonging to/referencing the admin user
    try
    {
      $GLOBALS['vprefix'] = $cli->yellow('[ Data ]');
      verbose('Removing user data...', 'cli.none');
      $GLOBALS['registry']->removeUserData($user);
    }
    catch(Horde_Exception $e)
    {
      $cli->message('  Error while removing ' . $user . ': ' . $e, 'cli.error');
      continue;
    }

    # remove history
    try
    {
      $GLOBALS['vprefix'] = $cli->yellow('[ History ]');
      verbose('Removing data...', 'cli.none');
      $db->delete('DELETE FROM horde_histories WHERE history_who = ?', array($user));
    }
    catch(Horde_Db_Exception $e)
    {
      # fatal/exit is safe here as we don't care much
      # about a consistent history database
      $cli->fatal('Error while removing history: ' . $e);
    }

    # clear horde prefs cache
    # otherwise the shutdown function will store the default value of all dirty
    # cache entries (= everything removed during removeUserData($user)) again
    try
    {
      $GLOBALS['vprefix'] = $cli->yellow('[ Prefs ]');
      verbose('Clear prefs cache...', 'cli.none');
      $prefs_ob = $GLOBALS['injector']
        ->getInstance('Horde_Core_Factory_Prefs')
        ->create('horde', array(
          'user' => $user
        ));
    }
    catch(Horde_Exception $e)
    {
      $cli->message('  Error while clearing prefs cache: ' . $e, 'cli.error');
      continue;
    }

    # finally remove the user from rampage
    try
    {
      # this should be the last as we might recreate the user during deletion
      $GLOBALS['vprefix'] = $cli->yellow('[ Content ]');
      verbose(sprintf('Removing user "%s/#%d"...', $user, $tUserId), 'cli.none');
      $usermanager = $GLOBALS['injector']->getInstance('Content_Users_Manager');
      $meth = new ReflectionMethod(get_class($usermanager), '_t');
      $meth->setAccessible(true);
      $db->delete('DELETE FROM ' . $meth->invoke($usermanager, 'users') . ' WHERE user_id = ?', array($tUserId));
    }
    catch(Horde_Db_Exception $e)
    {
      $cli->message('Error while removing user: ' . $e, 'cli.error');
      continue;
    }

    $cli->message('  ' . $user . ' removed', 'cli.success');
  }
}

$db->disconnect();

?>
