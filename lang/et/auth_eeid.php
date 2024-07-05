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

$string['pluginname'] = 'eeID Autentimine';
$string['client_id'] = 'Kliendi ID';
$string['client_id_desc'] = 'Sisesta oma eeID Kliendi ID';
$string['client_secret'] = 'Kliendi Salajane Võti';
$string['client_secret_desc'] = 'Sisesta oma eeID Kliendi Salajane Võti';
$string['not_allowed_roles'] = 'Keelatud Rollid';
$string['not_allowed_roles_desc'] = 'Komadega eraldatud nimekiri rollidest, kellel pole lubatud eeID kaudu sisse logida';
$string['allow_user_creation'] = 'Luba Kasutajate Loomine';
$string['allow_user_creation_desc'] = 'Luba uute kasutajate loomine, kui nad ei eksisteeri';
$string['invalidstate'] = 'Vigane olek';
$string['auth_error'] = 'Autentimisviga: {$a}';
$string['auth_failed'] = 'Autentimine ebaõnnestus: {$a}';
$string['missinguserfields'] = 'Puuduvad vajalikud kasutajaväljad eeID päringu vastuses';
$string['not_allowed_roles'] = 'Roll ei ole lubatud';
$string['not_allowed_roles_desc'] = 'Rollil ei ole lubatud eeID kaudu sisse logida';
$string['login_button'] = 'ID-kaart mID SmartID';
$string['nosuchidnumber'] = 'Isikukoodi ei leitud!';
