# Moodle eeID Authentication Plugin

This Moodle plugin integrates the eeID authentication service into Moodle.

## Installation

1. Clone this repository into your Moodle installation's `auth` directory or download as .zip and upload via `Site administration -> Plugins -> Install plugins` and follow the instructions.
2. Navigate to `Site administration -> Notifications` to install the plugin.
3. Activate the plugin in `Site administration -> Plugins -> Authentication`.

## Configuration

1. Configure the plugin in `Site administration -> Plugins -> Authentication -> Manage authentication`.
   - `client_id`: Your eeID client ID or TEST data.
   - `client_secret`: Your eeID client secret or TEST data.
   - `not_allowed_roles`: Comma-separated list of role IDs that are not allowed to use this authentication method.
   - `allow_user_creation`: Allow new user creation during authentication.

## Testing

1. When testing the plugin, use test credentials according to the documentation [eeID](https://docs.eeid.ee/guide/test-environment.html).
2. Create test users for mID and smartID testing according to the documentation (ID numbers and phone number for mID) or allow user creation upon signing in.
3. Test settings must be added to the configuration file in the Moodle installation root directory.

    ```php
    $CFG->eeid_auth_url = 'https://test-auth.eeid.ee/hydra-public/oauth2/auth'; // TEST servers
    $CFG->eeid_token_url = 'https://test-auth.eeid.ee/hydra-public/oauth2/token';
    $CFG->eeid_user_data_url = 'https://test-auth.eeid.ee/hydra-public/userinfo';
    $CFG->eeid_client_id = ''; // test data from documentation
    $CFG->eeid_client_secret = ''; // test data from documentation
    $CFG->eeid_not_allowed_roles = ''; // Comma-separated role IDs
    $CFG->eeid_allow_user_creation = false;
    ```

## Usage

1. After testing, obtain live credentials (client ID and secret) from eeid.ee, follow the configuration instructions, and update settings for live usage in settings.
2. LIVE settings must be added both to the plugin settings page in moodle plugin administration page and to the configuration file in the Moodle installation root directory.

    ```php
    $CFG->eeid_auth_url = 'https://auth.eeid.ee/hydra-public/oauth2/auth'; // LIVE servers
    $CFG->eeid_token_url = 'https://auth.eeid.ee/hydra-public/oauth2/token'; 
    $CFG->eeid_user_data_url = 'https://auth.eeid.ee/hydra-public/userinfo';
    $CFG->eeid_client_id = ''; // LIVE id from eeid.ee
    $CFG->eeid_client_secret = ''; // LIVE secret from eeid.ee
    $CFG->eeid_not_allowed_roles = ''; // Comma-separated role IDs
    $CFG->eeid_allow_user_creation = false; //set to true if users can be created during authentication
    ```

3. Users will be redirected to eeID for authentication when they attempt to log in.
4. Upon successful authentication via ID-card, Mobile-ID or SmartID, they will be redirectbac and logged in to the Moodle.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
