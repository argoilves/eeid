<?php
// This file is part of Moodle - http://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <http://www.gnu.org/licenses/>.

/**
 * @package   auth_eeid
 * @author    Argo Ilves <argoilves@gmail.com>
 * @license   http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

defined('MOODLE_INTERNAL') || die();

$string['pluginname'] = 'eeID Authentication';
$string['client_id'] = 'Client ID';
$string['client_id_desc'] = 'Enter your eeID Client ID';
$string['client_secret'] = 'Client Secret';
$string['client_secret_desc'] = 'Enter your eeID Client Secret';
$string['not_allowed_roles'] = 'Not Allowed Roles';
$string['not_allowed_roles_desc'] = 'Comma-separated list of roles not allowed to login via eeID';
$string['allow_user_creation'] = 'Allow User Creation';
$string['allow_user_creation_desc'] = 'Allow creating new users if they do not exist';
$string['invalidstate'] = 'Invalid state';
$string['auth_error'] = 'Authentication error: {$a}';
$string['auth_failed'] = 'Authentication failed: {$a}';
$string['missinguserfields'] = 'Missing required user fields from eeID response';
$string['not_allowed_roles'] = 'Role not allowed';
$string['not_allowed_roles_desc'] = 'Role not allowed to login via eeID';
$string['login_button'] = 'ID-card mID SmartID';
$string['nosuchidnumber'] = 'No such personal ID';

