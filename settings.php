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

if ($ADMIN->fulltree) {
    $settings->add(new admin_setting_configtext(
        'auth_eeid/client_id',
        get_string('client_id', 'auth_eeid'),
        get_string('client_id_desc', 'auth_eeid'),
        '',
        PARAM_TEXT
    ));

    $settings->add(new admin_setting_configtext(
        'auth_eeid/client_secret',
        get_string('client_secret', 'auth_eeid'),
        get_string('client_secret_desc', 'auth_eeid'),
        '',
        PARAM_TEXT
    ));

    $settings->add(new admin_setting_configtext(
        'auth_eeid/not_allowed_roles',
        get_string('not_allowed_roles', 'auth_eeid'),
        get_string('not_allowed_roles_desc', 'auth_eeid'),
        '',
        PARAM_TEXT
    ));

    $settings->add(new admin_setting_configcheckbox(
        'auth_eeid/allow_user_creation',
        get_string('allow_user_creation', 'auth_eeid'),
        get_string('allow_user_creation_desc', 'auth_eeid'),
        false // Changed 0 to false for consistency
    ));

}

