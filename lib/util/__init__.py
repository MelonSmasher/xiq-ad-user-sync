from dotenv import load_dotenv
from os import getenv
import logging
from io import BytesIO
from PIL import Image
import base64
from pathlib import Path
import requests
import enum
import random


class StatusValue(enum.Enum):
    SUCCESS = 0
    WARNING = 1
    ERROR = 2


class Status:
    def __init__(self):
        self.status = StatusValue.SUCCESS

    def set_status(self, status: StatusValue):
        if self.status.value < status.value:
            self.status = status

    def get_status(self):
        return self.status


def calc_exponential_backoff(retry: int, base_delay: float = 0.5, max_delay: float = 60):
    """
    Function to calculate the exponential backoff delay
    :param retry: The current retry count
    :type retry: int
    :param base_delay: The base delay in seconds
    :type base_delay: float
    :param max_delay: The maximum delay in seconds
    :type max_delay: float
    :return:
    :rtype: float
    """
    # Exponential backoff formula: min(base_delay * 2^retry + jitter, max_delay)
    sleep_time = min(base_delay * (2 ** retry) + random.uniform(0, 1), max_delay)
    return sleep_time


def init_logger(log_level: str = 'INFO', log_to_file: bool = False, log_path: str = 'log/'):
    """
    Function to initialize the logger
    :param log_level: The log level
    :type log_level: str
    :param log_to_file: Whether to log to a file
    :type log_to_file: bool
    :param log_path: Path to store the log file
    :type log_path: str
    :return: Logger object
    :rtype: logging.Logger
    """
    if log_to_file:
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s: %(name)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S',
            filemode='a',
            handlers=[
                logging.FileHandler(f'{log_path}xiq_ldap.log'),
                logging.StreamHandler()
            ]
        )
    else:
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s: %(name)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S',
            handlers=[
                logging.StreamHandler()
            ]
        )
    return logging.getLogger('xiq-ppsk-ldap-sync')


def get_mail_logo(img_path: str) -> str | None:
    """
    Function to get the logo for the email
    :param img_path: Path to the logo
    :type img_path: str
    :return: Base64 encoded logo
    :rtype: str
    """
    logger = logging.getLogger('xiq-ppsk-ldap-sync.util.get_mail_logo')
    base64_logo = None
    # If the path is a URL
    if img_path.lower().startswith('data:image/'):
        base64_logo = img_path
        logger.info("Using the provided base64 encoded logo")
    elif img_path.lower().startswith('http://') or img_path.lower().startswith('https://'):
        try:
            logger.info(f"Downloading the logo from {img_path}")
            # download the logo and save it to an io.BytesIO object
            response = requests.get(img_path)
            # Guard clause to check if the request was successful
            if response.status_code != 200:
                logger.error(f"Failed to download the logo from {img_path}")
                return None
            image = Image.open(BytesIO(response.content))
            buffered = BytesIO()
            image.save(buffered, format=image.format)
            # convert the image to base64 string for embedding in the email html
            base64_logo = f"data:image/{image.format.lower()};base64,{base64.b64encode(buffered.getvalue()).decode('utf-8')}"
        except Exception as e:
            logger.error(f"Failed to download the logo from {img_path}: {e}")
            return None
        logger.info(f"Successfully downloaded the logo from {img_path}")
    # If it's a local file test if it exists
    elif Path(img_path).is_file():
        logger.info(f"Reading the logo from {img_path}")
        try:
            with open(img_path, 'rb') as image_file:
                image = Image.open(image_file)
                buffered = BytesIO()
                image.save(buffered, format=image.format)
                # convert the image to base64 string for embedding in the email html
                base64_logo = f"data:image/{image.format.lower()};base64,{base64.b64encode(buffered.getvalue()).decode('utf-8')}"
        except Exception as e:
            logger.error(f"Failed to read the logo from {img_path}: {e}")
            return None
        logger.info(f"Successfully read the logo from {img_path}")
    else:
        logger.error(
            f"Unable to determine the logo type from {img_path}, "
            f"please provide a valid URL, "
            f"local file path or base64 encoded image that starts with 'data:image/'"
            f" (e.g. data:image/png;base64,<base64_encoded_image_data>)"
        )
        # base64_logo is None at this point, so we return it outside the if-elif-else block
    return base64_logo


def read_config_file(config_file: str = '.env') -> dict:
    """
    Function to read the configuration file
    :param config_file: Path to the configuration environment file
    :type config_file: str
    :return: A dictionary containing the configuration
    :rtype: dict
    """
    if getenv('IN_DOCKER') is None or getenv('IN_DOCKER') == 'False':
        # if not running in Docker, use the .env file in the root directory
        # otherwise, we expect environment variables to be set by Docker
        load_dotenv(dotenv_path=config_file)

    log_to_file = getenv('LOG_TO_FILE', False)
    if log_to_file is not False:
        log_to_file = log_to_file.lower().startswith('t')

    pcg_enabled = getenv('XIQ_PCG_ENABLED', False)
    if pcg_enabled is not False:
        pcg_enabled = pcg_enabled.lower().startswith('t')

    xiq_verify_ssl = getenv('XIQ_VERIFY_SSL', True)
    if xiq_verify_ssl is not True:
        if xiq_verify_ssl.lower().startswith('f'):
            xiq_verify_ssl = False
        else:
            xiq_verify_ssl = True

    ldap_auth_method = getenv('LDAP_AUTH_METHOD', 'NTLM').upper()
    if ldap_auth_method not in ['NTLM', 'ANONYMOUS', 'SIMPLE', 'SASL']:
        ldap_auth_method = 'NTLM'

    ldap_sasl_mechanism = None
    if ldap_auth_method == 'SASL':
        ldap_sasl_mechanism = getenv('LDAP_SASL_MECHANISM', 'GSSAPI').upper()
        if ldap_sasl_mechanism not in ['EXTERNAL', 'DIGEST-MD5', 'GSSAPI', 'PLAIN']:
            ldap_sasl_mechanism = 'GSSAPI'

    auto_bind = getenv('LDAP_AUTO_BIND', 'NO_TLS').upper()
    if auto_bind not in ['DEFAULT', 'NONE', 'NO_TLS', 'TLS_BEFORE_BIND', 'TLS_AFTER_BIND']:
        auto_bind = 'DEFAULT'

    ad_group_to_xiq_role_mapping = []
    for mapping in getenv('MAPPING_AD_GROUP_TO_XIQ_ROLE', '').split('|'):
        ad_group, xiq_role = mapping.split(':')
        ad_group_to_xiq_role_mapping.append((ad_group, xiq_role))

    check_password_against_pwned = getenv('XIQ_CHECK_PASSWORD_AGAINST_PWNED', False)
    if check_password_against_pwned is not False:
        if check_password_against_pwned.lower().startswith('t'):
            check_password_against_pwned = True
        else:
            check_password_against_pwned = False

    strict_password_check = getenv('XIQ_STRICT_PASSWORD_CHECK', True)
    if strict_password_check is not True:
        if strict_password_check.lower().startswith('f'):
            strict_password_check = False
        else:
            strict_password_check = True

    pcg_mapping = {}
    for mapping in getenv('MAPPING_PCG', '').split(','):
        pcg_items = mapping.split(':')
        pcg_mapping[pcg_items[0]] = {
            'UserGroupName': pcg_items[1],
            'policy_id': pcg_items[2],
            'policy_name': pcg_items[3]
        }

    xiq_password_generator_use_words = getenv('XIQ_PASSWORD_GENERATOR_USE_WORDS', False)
    if xiq_password_generator_use_words is not False:
        if xiq_password_generator_use_words.lower().startswith('t'):
            xiq_password_generator_use_words = True
        else:
            xiq_password_generator_use_words = False

    qr_code_enabled = getenv('QR_CODE_ENABLED', False)
    if qr_code_enabled is not False:
        qr_code_enabled = qr_code_enabled.lower().startswith('t')

    mail_enabled = getenv('MAIL_ENABLED', False)
    if mail_enabled is not False:
        mail_enabled = mail_enabled.lower().startswith('t')

    # Get the number of words to use in the password generator
    try:
        password_word_count = int(getenv('XIQ_PASSWORD_GENERATOR_WORD_COUNT', 4))
    except ValueError:
        password_word_count = 4

    xiq_mail_for_ssids = []
    for ssid in getenv('XIQ_MAIL_FOR_SSIDS', '').split(','):
        xiq_mail_for_ssids.append(ssid)

    notify_qrcode_servers = {}
    for server in getenv('WEBOOK_MAPPING', '').split(','):
        if server is None or server == '' or not server or '|' not in server:
            continue
        email, ssid, server_url = server.split('|')
        notify_qrcode_servers[email] = {
            'ssid': ssid,
            'url': server_url,
            'email': email
        }

    return {
        'log': {
            'level': getenv('LOG_LEVEL', 'INFO'),
            'to_file': log_to_file,
        },
        'ldap': {
            # comma separated list of LDAP servers in the format server:port:use_ssl
            # e.g. ldap.example.com:389:False,ldap2.example.com:636:True
            'hosts': getenv('LDAP_HOSTS'),
            'domain': getenv('LDAP_DOMAIN'),
            'username': getenv('LDAP_USERNAME'),
            'password': getenv('LDAP_PASSWORD'),
            'search_filter': getenv('LDAP_SEARCH_FILTER', ''),
            'auth_method': ldap_auth_method,
            'sasl_mechanism': ldap_sasl_mechanism,
            'auto_bind': auto_bind,
            'disable_codes': getenv('LDAP_DISABLE_CODES', '').split(',') if getenv('LDAP_DISABLE_CODES') else [
                '514',
                '642',
                '66050',
                '66178',
            ],
        },
        'xiq': {
            'url': getenv('XIQ_URL', 'https://api.extremecloudiq.com'),
            'username': getenv('XIQ_USERNAME'),
            'password': getenv('XIQ_PASSWORD'),
            'verify_ssl': xiq_verify_ssl,
            'pcg_enabled': pcg_enabled,
            'check_password_against_pwned': check_password_against_pwned,
            'strict_password_check': strict_password_check,
            'password_generator_use_words': xiq_password_generator_use_words,
            'password_word_count': password_word_count,
            'mail_for_ssids': xiq_mail_for_ssids,
        },
        'mapping': {
            'ad_group_to_xiq_role': ad_group_to_xiq_role_mapping,
            'pcg': pcg_mapping,
            'notify_qrcode_servers': notify_qrcode_servers,
        },
        'qr': {
            'enabled': qr_code_enabled,
            'logo_path': getenv('QR_CODE_LOGO_PATH', None),
        },
        'mailgun': {
            'api_key': getenv('MAILGUN_API_KEY'),
            'domain': getenv('MAILGUN_DOMAIN'),
            'from': getenv('MAILGUN_FROM'),
        },
        'mail': {
            'enabled': mail_enabled,
            'logo': getenv('MAIL_LOGO', None),
            'company_name': getenv('MAIL_COMPANY_NAME', None),
            'extra_message': getenv('MAIL_EXTRA_MESSAGE', None),
            'kb_article_url': getenv('MAIL_KB_ARTICLE_URL', None),
            'support_email': getenv('MAIL_SUPPORT_EMAIL', None),
            'support_page_url': getenv('MAIL_SUPPORT_PAGE_URL', None),
        }
    }
