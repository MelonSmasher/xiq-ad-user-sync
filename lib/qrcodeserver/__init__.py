import requests
from logging import getLogger
from WiFiQRGen import WifiNetworkSettings, WifiSecurity, WifiEapMethod, WifiPhase2Auth


def get_qr_code_data(url: str) -> WifiNetworkSettings | None:
    """
    Get the QR code data from the specified URL
    :param url: The webhook URL to get the QR code data from
    :type url: str
    :return: The Wi-Fi network settings from the QR code data
    :rtype: WifiNetworkSettings | None
    """
    logger = getLogger('qrcodeserver.get_qr_code_data')
    logger.info(f'Getting QR code data from {url}')
    response = requests.request(
        method='GET',
        url=url,
        headers={
            'Accept': 'application/json'
        }
    )
    if response.status_code != 200:
        logger.error(f'Failed to get QR code data from {url}')
        return None
    qr_code_data = response.json()
    logger.info(f'QR code data received from {url}')
    logger.debug(f'QR code data: {qr_code_data}')
    eap = WifiEapMethod[qr_code_data['settings']['eap_method']] if qr_code_data['settings']['eap_method'] else None
    p2 = WifiPhase2Auth[qr_code_data['settings']['phase_two_auth']] if qr_code_data['settings'][
        'phase_two_auth'] else None
    return WifiNetworkSettings(
        ssid=qr_code_data['settings']['ssid'],
        password=qr_code_data['settings']['passphrase'],
        security=WifiSecurity[qr_code_data['settings']['security']],
        hidden=bool(qr_code_data['settings']['hidden']),
        identity=qr_code_data['settings']['identity'],
        eap_method=eap,
        phase_2_auth=p2,
        anon_outer_identity=bool(qr_code_data['settings']['anon_outer_identity'])
    )


def push_qr_code_data(url: str, created_for: str, settings: WifiNetworkSettings, qr_code_base64: str):
    """
    Push the QR code data to the specified URL
    :param url: The webhook URL to push the QR code data to
    :type created_for: str
    :param created_for: The email or name of the person the QR code is created for
    :type settings: WifiNetworkSettings
    :param settings: The Wi-Fi network settings to push
    :type created_for: str
    :param qr_code_base64: The base64 encoded QR code image
    :type url: str
    :return: Success or failure of the push
    :rtype: bool
    """
    logger = getLogger('qrcodeserver.push_qr_code_data')
    logger.info(f'Pushing QR code data to {url}')
    response = requests.request(
        method='POST',
        url=url,
        headers={
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        },
        json={
            'created_for': created_for,
            'ssid': settings.ssid,
            'passphrase': settings.password,
            'security': str(settings.security.value),
            'hidden': settings.hidden,
            'identity': settings.identity,
            'eap_method': str(settings.eap_method.value) if settings.eap_method else None,
            'phase_two_auth': str(settings.phase_2_auth.value) if settings.phase_2_auth else None,
            'anon_outer_identity': settings.anon_outer_identity,
            'base64_image': qr_code_base64
        }
    )
    if response is None:
        logger.error(
            f'Failed to push QR code data to {url} '
            f'No response received'
        )
        return False
    if response.status_code != 200:
        logger.error(
            f'Failed to push QR code data to {url} '
            f'Status code: {response.status_code} '
            f'Reason: {response.reason} '
        )
        logger.debug(response.text)
        return False
    logger.info(f'QR code data pushed to {url}')
    logger.debug(f'QR code data: {response.json()}')
    return True
