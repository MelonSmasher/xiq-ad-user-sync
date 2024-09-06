#!/usr/bin/env python3

import logging
import json
import tempfile
from base64 import b64decode
from typing import Tuple, List
from lib.qrcodeserver import push_qr_code_data
from lib.ldap import LDAP
from lib.xiq import XIQ, XIQUser
from lib.mail import Mail, MailImage
from lib.util import init_logger, read_config_file, get_mail_logo, Status, StatusValue
from copy import deepcopy
from WiFiQRGen import WifiNetworkSettings, WifiSecurity


def pull_networks(
        role_pcg_mapping: dict,
        xiq: XIQ,
        current_status: Status = Status()
) -> Tuple[dict[str, List[dict]], Status]:
    """
    Pull the networks from the XIQ API for each role in the role PCG mapping
    :param role_pcg_mapping: The mapping of roles to PCGs
    :type role_pcg_mapping: dict
    :param xiq: The XIQ client to use to connect to the XIQ API server
    :type xiq: XIQ
    :param current_status: The current status of the sync process
    :type current_status: Status
    :return: The networks for each role in the role PCG mapping
    :rtype: Tuple[dict[str, List[dict]], Status]
    """
    networks = {}
    logger = logging.getLogger('xiq-ppsk-ldap-sync.pull_networks')
    for role_id, pcg in role_pcg_mapping.items():
        logger.info(f"Pulling networks for role: {pcg['policy_id']} / {pcg['policy_name']}")
        results = xiq.get_network_policy_ssids(pcg['policy_id'])
        if not results:
            logger.error(f'Failed to retrieve networks for role: {pcg['policy_id']} / {pcg['policy_name']}')
            current_status.set_status(StatusValue.ERROR)
            continue
        logger.debug(f'Networks: {results}')
        logger.info(f"Networks pulled for role: {pcg['policy_id']} / {pcg['policy_name']}")
        network_index = 0
        for network in results:
            logger.info(f"Pulling advanced settings for SSID: {network['id']} / {network['name']} "
                        f"with advanced settings ID: {network['advanced_settings_id']}")
            advanced_settings = xiq.get_ssid_advanced_settings(network['advanced_settings_id'])
            if not advanced_settings:
                logger.error(f'Failed to retrieve advanced settings for SSID: {network['id']} / {network["name"]}')
                network_index += 1
                current_status.set_status(StatusValue.ERROR)
                continue
            logger.debug(f'Advanced settings: {advanced_settings}')
            results[network_index]['advanced_settings'] = advanced_settings
            network_index += 1
            logger.info(f"Advanced settings pulled for SSID: {network['id']} / {network['name']}")
        networks[role_id] = results
    return networks, current_status


def run_sync(
        xiq_client: XIQ,
        ldap_client: LDAP,
        config: dict,
        xiq_networks: dict,
        current_status: Status = Status()
) -> tuple[list[XIQUser | bool], Status]:
    """
    Run the sync process between the AD groups and the XIQ roles
    :param xiq_client: The XIQ client to use to connect to the XIQ API server
    :type xiq_client: XIQ
    :param ldap_client: The LDAP client to use to connect to the AD server
    :type ldap_client: LDAP
    :param config: The configuration dictionary
    :type config: dict
    :param xiq_networks: The networks for each role in the role PCG mapping
    :type xiq_networks: dict[str: list[dict]]
    :param current_status: The current status of the sync process
    :type current_status: Status
    :return: A list of users as XIQUser objects to mail the PPSK credentials and the status of the sync process
    :rtype: tuple[list[XIQUser | bool], Status]
    """
    logger = logging.getLogger('xiq-ppsk-ldap-sync.run_sync')
    users_to_mail = []

    for ad_group_xiq_mapping in config['mapping']['ad_group_to_xiq_role']:
        # Create a list to store the created users
        created_users = []
        # Get the AD group and XIQ role from the mapping... Split the tuple into two variables
        ad_group_dn, xiq_role = ad_group_xiq_mapping
        logger.debug(f'Processing AD group: {ad_group_dn}')
        # Get the users in the AD group
        ad_group_users = ldap_client.retrieve_users_from_group(ad_group_dn)
        logger.debug(f'Users in AD group: {ad_group_users}')
        logger.info(f'Retrieved {len(ad_group_users)} users from AD group: {ad_group_dn}')

        # Get the users in the XIQ role
        xiq_role_users, xiq_request_status = xiq_client.get_ppsk_users(page_size=100, user_group_id=xiq_role)
        if not xiq_request_status:
            logger.error(f'Failed to retrieve users in XIQ role: {xiq_role}')
            current_status.set_status(StatusValue.ERROR)
            continue
        logger.debug(f'Users in XIQ role: {xiq_role_users}')
        logger.info(f'Retrieved {len(xiq_role_users)} users from XIQ role: {xiq_role}')

        # build a list of emails from the AD group,
        # filtering out users who are disabled, and who don't have email addresses
        ad_group_hash = {
            user.email_address: user for user in ad_group_users if
            user.user_account_control not in config['ldap']['disable_codes'] and
            (user.email_address is not None or user.email_address != '')
        }
        # build a list of emails from the XIQ role
        xiq_role_hash = {user.email_address: user for user in xiq_role_users}
        # Find the users that need to be added to the XIQ role
        users_to_add = []
        for user in ad_group_users:
            if (
                    user.email_address not in xiq_role_hash.keys() and
                    user.email_address is not None and
                    user.email_address != '' and
                    len(user.email_address) > 1
            ):
                users_to_add.append(user)

        logger.debug(f'Users to add: {users_to_add}')
        logger.info(f'Found {len(users_to_add)} users to add to XIQ role: {xiq_role}')
        # Find the users that need to be removed from the XIQ role
        users_to_remove = [user for user in xiq_role_users if user.email_address not in ad_group_hash.keys()]
        logger.debug(f'Users to remove: {users_to_remove}')
        logger.info(f'Found {len(users_to_remove)} users to remove from XIQ role: {xiq_role}')

        # Add the users to the XIQ role
        for user in users_to_add:
            if not user.email_address or user.email_address == '' or len(user.email_address) < 1:
                logger.error(f'User {user.display_name} does not have an email address, skipping')
                current_status.set_status(StatusValue.ERROR)
                continue
            # Create the user in the XIQ role
            logger.debug(f'Adding user: {user.email_address} to XIQ role: {xiq_role}')
            created_xiq_user = xiq_client.create_ppsk_user(XIQUser({
                'email_address': user.email_address,
                'name': user.display_name,
                'user_group_id': xiq_role,
                'description': user.employee_id,
                'user_name': user.username
            }))
            # If the user could not be created, log the error and continue to the next user
            if not created_xiq_user:
                logger.error(f'Failed to add user: {user.email_address} to XIQ role: {xiq_role}')
                current_status.set_status(StatusValue.ERROR)
                continue

            created_xiq_user.wifi_settings = []

            for xiq_network in xiq_networks[xiq_role]:
                logger.info(f'Processing network: {xiq_network["name"]}')
                logger.debug(f'Network: {xiq_network}')
                # Determine the security type of the Wi-Fi network
                # default to WPA2
                security = WifiSecurity.NONE

                if xiq_network['access_security']['security_type'].startswith('OPEN'):
                    security = WifiSecurity.NONE
                else:
                    if xiq_network['access_security']['key_management'].startswith('WEP'):
                        security = WifiSecurity.WEP
                    if xiq_network['access_security']['key_management'].startswith('WPA_'):
                        security = WifiSecurity.WPA
                    if xiq_network['access_security']['key_management'].startswith('WPA3_'):
                        security = WifiSecurity.WPA3
                    if xiq_network['access_security']['key_management'].startswith('WPA2_'):
                        security = WifiSecurity.WPA2

                logger.info(f'Creating Wi-Fi network settings for SSID: {xiq_network["name"]}')
                # Create the Wi-Fi network settings
                wifi_settings = WifiNetworkSettings(
                    ssid=xiq_network['broadcast_name'],
                    password=created_xiq_user.password,
                    security=security
                )
                logger.debug(f'Wi-Fi network settings: {wifi_settings.get_qrcode_data_string()}')
                # Add the Wi-Fi network settings to the user with the QR code
                qr_logo_path = config['qr']['logo_path']
                qr_logo = None
                if qr_logo_path is not None:
                    logger.info(
                        f'Using QR code logo located at: {qr_logo_path}'
                    ) if not qr_logo_path.lower().startswith(
                        'data:image/'
                    ) else \
                        logger.info(
                            f'Using base64 encoded QR code logo: {qr_logo_path[:50]}...'
                        )
                    qr_logo = get_mail_logo(qr_logo_path) if qr_logo_path is not None else None
                    qr_logo = MailImage(
                        filename=f'qr_logo.png',
                        base64_image=qr_logo
                    )
                    logger.debug(f'QR code logo: {qr_logo.base64_image}')
                    # Write the base64 encoded image to a temporary file
                    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                        temp_file.write(b64decode(qr_logo.base64_image))
                        qr_logo = temp_file.name
                        logger.info(f'Temporary file created for QR code logo: {qr_logo}')

                created_xiq_user.wifi_settings.append({
                    'settings': wifi_settings,
                    'qrcode': f"data:image/png;base64,"
                              f"{wifi_settings.generate_base64_qrcode_png(embeded_image_path=qr_logo)}"
                    if config['qr']['enabled'] and qr_logo_path else None
                })
                if qr_logo is not None:
                    # Remove the temporary file
                    temp_file.close()
                    logger.info(f'Temporary file {qr_logo} removed')

                logger.info(
                    f'Wi-Fi network settings created for SSID: {xiq_network["name"]} and '
                    f'added to user {created_xiq_user.email_address}'
                )
                logger.debug(f'User: {created_xiq_user}')

            # Add the created user to the list of created users
            created_users.append(created_xiq_user)
            logger.info(f'Added user: {user.email_address} to XIQ role: {xiq_role}')

            # If PCG is enabled and the XIQ role is in the PCG mapping, add the user to the PCG
            # @todo see long comment below
            """
            this might be able to be moved outside of the loop and only run once per XIQ role by collecting all 
            users per XIQ role that wer created then send all users to the PCG endpoint in the users array parameter.
            Doing this would reduce the number of API calls to the PCG endpoint and reduce the time it takes to complete
            the sync process and reduce the surface area for potential network related issues.
            """
            if config['xiq']['pcg_enabled'] and xiq_role in dict(config['mapping']['pcg']).keys():
                logger.debug('PCG is enabled and the XIQ role is in the PCG mapping')
                mapping = config['mapping']['pcg'][xiq_role]
                logger.info(f'Adding user: {created_xiq_user.email_address} to PCG: {mapping["policy_name"]}')
                # Define the PCG user
                pcg_user = created_xiq_user.to_pcg_user(
                    user_group_name=mapping['UserGroupName']
                )
                logger.debug(f'PCG User: {pcg_user}')
                # Add the user to the PCG through the API
                result = xiq_client.add_user_to_pcg(
                    policy_id=mapping['policy_id'],
                    users=[pcg_user]
                )
                if not result:
                    logger.error(
                        f'Failed to add user: {created_xiq_user.email_address} to PCG: {mapping["policy_name"]}'
                    )
                    current_status.set_status(StatusValue.ERROR)
                    continue
                logger.info(
                    f'Added user: {created_xiq_user.email_address} to PCG: {mapping["policy_name"]}'
                )
            # Add the user to the list of users to mail the PPSK credentials
            if created_xiq_user.email_address and created_xiq_user.email_address != '':
                users_to_mail.append(created_xiq_user)

        # Remove the users from the XIQ role
        for user in users_to_remove:
            logger.debug(f'Removing user: {user.email_address} from XIQ role: {xiq_role}')
            # Remove the user from the XIQ role
            if not xiq_client.delete_ppsk_user(user.id):
                # If the user could not be removed, log the error and continue to the next user
                logger.error(f'Failed to remove user: {user.email_address} from XIQ role: {xiq_role}')
                current_status.set_status(StatusValue.ERROR)
                continue
            logger.info(f'Removed user: {user.email_address} from XIQ role: {xiq_role}')

    # Return the list of users to mail the PPSK credentials
    return users_to_mail, current_status


def main():
    """
    Main function to run the XIQ-AD-PPSK-Sync application
    """
    current_status = Status()
    # Read the configuration file
    config = read_config_file()
    # Initialize the logger
    init_logger(
        log_level=config['log']['level'],
        log_to_file=config['log']['to_file']
    )
    logger = logging.getLogger('xiq-ppsk-ldap-sync.main')
    logger.info('Starting the XIQ-AD-PPSK-Sync application')
    logger.debug('Logger initialized successfully')
    logger.debug('Configuration loaded successfully')

    # Log the configuration if the log level is DEBUG and mask the passwords and dump the configuration to the log
    if config['log']['level'] == 'DEBUG':
        debug_config = deepcopy(config)
        if debug_config['ldap']['password'] is not None:
            debug_config['ldap']['password'] = '*' * len(debug_config['ldap']['password'])
        if debug_config['xiq']['password'] is not None:
            debug_config['xiq']['password'] = '*' * len(debug_config['xiq']['password'])
        logger.debug('Configuration:')
        logger.debug(f'{json.dumps(debug_config, indent=4)}')

    logger.debug('Creating the LDAP client...')
    # Create the LDAP client
    ldap = LDAP(
        hosts=config['ldap']['hosts'].split(','),
        domain=config['ldap']['domain'],
        username=config['ldap']['username'],
        password=config['ldap']['password'],
        auth_method=config['ldap']['auth_method'],
        sasl_mechanism=config['ldap']['sasl_mechanism'],
        auto_bind=config['ldap']['auto_bind']
    )
    logger.info('LDAP client created successfully')

    logger.debug('Initializing the LDAP server pool...')
    # Initialize the LDAP server pool and bind to the LDAP server
    if not ldap.build_connection():
        logger.error('Failed to initialize the LDAP server pool')
        current_status.set_status(StatusValue.ERROR)
        raise Exception('Failed to initialize the LDAP server pool')

    if ldap.current_status.get_status() == StatusValue.SUCCESS:
        logger.info('LDAP server pool initialized successfully')
    if ldap.current_status.get_status() == StatusValue.WARNING:
        logger.warning('LDAP server pool initialized with warnings')
    if ldap.current_status.get_status() == StatusValue.ERROR:
        logger.error('LDAP server pool initialized with errors')

    current_status.set_status(ldap.current_status.get_status())

    logger.debug('Creating the XIQ client...')
    # Create the XIQ client
    xiq = XIQ(
        url=config['xiq']['url'],
        username=config['xiq']['username'],
        password=config['xiq']['password'],
        verify_ssl=config['xiq']['verify_ssl'],
        check_password_against_pwned=config['xiq']['check_password_against_pwned'],
        strict_password_check=config['xiq']['strict_password_check'],
        password_generator_use_words=config['xiq']['password_generator_use_words'],
        password_word_count=config['xiq']['password_word_count']
    )
    if not xiq.current_status.get_status() == StatusValue.SUCCESS:
        logger.info('XIQ client initialized successfully')
    if xiq.current_status.get_status() == StatusValue.WARNING:
        logger.warning('XIQ client initialized with warnings')
    if xiq.current_status.get_status() == StatusValue.ERROR:
        logger.error('XIQ client initialized with errors')
    current_status.set_status(xiq.current_status.get_status())

    mail = None
    if (
            config['mail']['enabled'] and
            config['mailgun']['api_key'] is not None and
            config['mailgun']['domain'] is not None
    ):
        logger.info('Initializing the Mail client...')
        # Initialize the Mail client
        mail = Mail(
            api_key=config['mailgun']['api_key'],
            domain=config['mailgun']['domain']
        )
        if not mail.current_status.get_status() == StatusValue.SUCCESS:
            logger.info('Mail client initialized successfully')
        if mail.current_status.get_status() == StatusValue.WARNING:
            logger.warning('Mail client initialized with warnings')
        if mail.current_status.get_status() == StatusValue.ERROR:
            logger.error('Mail client initialized with errors')
        current_status.set_status(mail.current_status.get_status())

    logger.debug('Obtaining XIQ auth token...')
    # Get the XIQ auth token
    if not xiq.get_auth_token():
        logger.error('Failed to obtain XIQ auth token')
        current_status.set_status(StatusValue.ERROR)
        raise Exception('Failed to obtain XIQ auth token')
    logger.info('XIQ auth token obtained successfully')

    logger.debug('Pulling networks from XIQ...')
    # Pull the networks from XIQ for each role in the role PCG mapping
    networks, network_status = pull_networks(
        role_pcg_mapping=config['mapping']['pcg'],
        xiq=xiq
    )
    if network_status.get_status() == StatusValue.SUCCESS:
        logger.info('Networks pulled from XIQ successfully')
    if network_status.get_status() == StatusValue.WARNING:
        logger.warning('Networks pulled from XIQ with warnings')
    if network_status.get_status() == StatusValue.ERROR:
        logger.error('Failed to pull networks from XIQ')
        current_status.set_status(StatusValue.ERROR)
        raise Exception('Failed to pull networks from XIQ')
    current_status.set_status(network_status.get_status())
    logger.debug(f'Networks: {networks}')

    logger.info('Running the sync process...')
    # Run the sync process and get the users to mail the PPSK credentials
    users_to_mail, sync_status = run_sync(
        xiq_client=xiq,
        ldap_client=ldap,
        config=config,
        xiq_networks=networks
    )
    if sync_status.get_status() == StatusValue.SUCCESS:
        logger.info('Sync process completed successfully')
    if sync_status.get_status() == StatusValue.WARNING:
        logger.warning('Sync process completed with warnings')
    if sync_status.get_status() == StatusValue.ERROR:
        logger.error('Sync process completed with errors')
        current_status.set_status(StatusValue.ERROR)
    current_status.set_status(sync_status.get_status())

    logger.debug(f'Users to mail: {users_to_mail}')
    if len(users_to_mail) < 1:
        logger.info('No users to mail, skipping mail process')
    if (
            config['mail']['enabled'] and
            config['mailgun']['api_key'] is not None and
            config['mailgun']['domain'] is not None and
            mail is not None and
            len(users_to_mail) > 0
    ):
        # Get the mail logo
        mail_logo_base64 = get_mail_logo(config['mail']['logo']) if config['mail']['logo'] is not None else None

        logger.info('Mailing the PPSK credentials...')
        # Mail the PPSK credentials to the users
        for user in users_to_mail:
            mailed_ssids = []
            for wifi_settings in user.wifi_settings:
                if wifi_settings['settings'].ssid not in config['xiq']['mail_for_ssids']:
                    logger.info(f'Skipping SSID: {wifi_settings["settings"].ssid} due to it not being in the SSID list')
                    continue
                if wifi_settings['settings'].ssid in mailed_ssids:
                    logger.info(f'Skipping SSID: {wifi_settings["settings"].ssid} due to it already being mailed')
                    continue
                logger.info(
                    f'Rendering HTML body for user: {user.email_address} / SSID: {wifi_settings["settings"].ssid}'
                )
                qr_mail_image = None
                logo_mail_image = None
                # Send the mail to the user
                if wifi_settings['qrcode'] is not None:
                    qr_mail_image = MailImage(
                        filename=f'qr.png',
                        base64_image=str(wifi_settings['qrcode'])
                    )
                if mail_logo_base64 is not None:
                    logo_mail_image = MailImage(
                        filename=f'logo.png',
                        base64_image=str(mail_logo_base64)
                    )
                mail.current_status.set_status(StatusValue.SUCCESS)
                html_body = mail.render_html_body(
                    name=user.name,
                    ssid=wifi_settings['settings'].ssid,
                    logo_image=logo_mail_image,
                    company_name=config['mail']['company_name'],
                    passphrase=wifi_settings['settings'].password,
                    qrcode_image=qr_mail_image,
                    extra_message=config['mail']['extra_message'],
                    kb_article_url=config['mail']['kb_article_url'],
                    support_email=config['mail']['support_email'],
                    support_page_url=config['mail']['support_page_url']
                )
                if mail.current_status.get_status() == StatusValue.SUCCESS:
                    logger.info(f'Rendered HTML body for user: {user.email_address}')
                if mail.current_status.get_status() == StatusValue.ERROR:
                    logger.error(f'Failed to render HTML body for user: {user.email_address}')
                    current_status.set_status(StatusValue.ERROR)
                    continue
                if mail.current_status.get_status() == StatusValue.WARNING:
                    logger.warning(f'HTML body rendered with warnings for user: {user.email_address}')
                    current_status.set_status(StatusValue.WARNING)
                current_status.set_status(mail.current_status.get_status())
                logger.debug(f'HTML body: {html_body}')
                logger.info(
                    f'HTML body rendered for user: {user.email_address} / SSID: {wifi_settings["settings"].ssid}'
                )
                logger.info(f'Sending mail to user: {user.email_address}')
                mail.current_status.set_status(StatusValue.SUCCESS)
                mail.send(
                    to_address=user.email_address,
                    from_address=config['mailgun']['from'],
                    subject=f'Wi-Fi Network Credentials for {wifi_settings["settings"].ssid}',
                    html_body=html_body,
                    qrcode=qr_mail_image,
                    logo=logo_mail_image
                )
                if mail.current_status.get_status() == StatusValue.SUCCESS:
                    logger.info(f'Mailed PPSK credentials to user: {user.email_address}')
                if mail.current_status.get_status() == StatusValue.WARNING:
                    logger.warning(f'Mailed PPSK credentials to user: {user.email_address} with warnings')
                if mail.current_status.get_status() == StatusValue.ERROR:
                    logger.error(f'Failed to mail PPSK credentials to user: {user.email_address}')
                mailed_ssids.append(wifi_settings['settings'].ssid)
                current_status.set_status(mail.current_status.get_status())
        logger.info('PPSK credentials mailed successfully')

    if len(users_to_mail) > 0:
        logger.info('Hitting webhooks...')
        webhooks_status = Status()
        for user in users_to_mail:
            notified = []
            for wifi_settings in user.wifi_settings:
                for email, notify_settings in config['mapping']['notify_qrcode_servers'].items():
                    # Check if the email address is in the notify list
                    if user.email_address.lower() != email.lower():
                        continue
                    found = False
                    # Check if the SSID is in the SSID list
                    if wifi_settings['settings'].ssid.lower() == notify_settings['ssid'].lower():
                        found = True
                    # If the SSID is not in the SSID list, log and continue to the next SSID
                    if not found:
                        logger.info(
                            f'Skipping SSID: {wifi_settings["settings"].ssid} due to it not being in the SSID list'
                        )
                        continue
                    # Check if the URL has already been notified
                    if notify_settings["url"] in notified:
                        logger.info(
                            f'Skipping {wifi_settings["settings"].ssid} --> {notify_settings["url"]} '
                            f'due to it already being notified'
                        )
                        continue
                    logger.info(f'Pushing QR code data to: {notify_settings["url"]}')
                    logger.debug(wifi_settings['qrcode'])
                    # Push the QR code data to the QR code server
                    if (push_qr_code_data(
                            url=notify_settings["url"],
                            created_for=f'{user.name} <{user.email_address.lower()}>',
                            settings=wifi_settings['settings'],
                            qr_code_base64=str(wifi_settings['qrcode'])
                    )):
                        logger.info(f'QR code data pushed to: {notify_settings["url"]}')
                        notified.append(notify_settings["url"])
                        webhooks_status.set_status(StatusValue.SUCCESS)
                    else:
                        logger.error(f'Failed to push QR code data to: {notify_settings["url"]}')
                        webhooks_status.set_status(StatusValue.ERROR)
        if webhooks_status.get_status() == StatusValue.SUCCESS:
            logger.info('Webhooks hit successfully')
        if webhooks_status.get_status() == StatusValue.WARNING:
            logger.warning('Webhooks hit with warnings')
        if webhooks_status.get_status() == StatusValue.ERROR:
            logger.error('Failed to hit webhooks')
        current_status.set_status(webhooks_status.get_status())

    logger.debug('Destroying the LDAP connection and server pool...')
    # Destroy the LDAP connection and server pool
    if not ldap.destroy_connection():
        logger.error('Failed to destroy the LDAP connection and server pool')
        current_status.set_status(StatusValue.ERROR)
        raise Exception('Failed to destroy the LDAP connection and server pool')
    logger.info('LDAP connection and server pool destroyed successfully')

    logger.debug('Logging out of XIQ...')
    # Log out of XIQ
    if not xiq.revoke_access_token():
        logger.warning('Failed to log out of XIQ')
        current_status.set_status(StatusValue.WARNING)
    else:
        logger.info('Logged out of XIQ successfully')

    if current_status.get_status() == StatusValue.ERROR:
        logger.error('XIQ-AD-PPSK-Sync application completed with errors')

    if current_status.get_status() == StatusValue.WARNING:
        logger.warning('XIQ-AD-PPSK-Sync application completed with warnings')

    if current_status.get_status() == StatusValue.SUCCESS:
        logger.info('XIQ-AD-PPSK-Sync application completed successfully')

    print(
        f'XIQ-AD-PPSK-Sync application completed with status: {current_status.get_status().name} and '
        f'exit code: {current_status.get_status().value}'
    )
    exit(current_status.get_status().value)


# Run the main function if the script is executed
if __name__ == '__main__':
    main()
