from jinja2 import Environment, FileSystemLoader
from datetime import datetime
import requests
import logging
import re
from base64 import b64decode
from lib.util import Status, StatusValue


class MailImage:
    def __init__(self, filename: str, base64_image: str):
        # extract the file extension from the base64 image string
        file_ext = re.search(r'^data:image/(.+);base64,', base64_image).group(1)
        self.file_ext = file_ext
        # replace the file extension in the filename with the extracted file extension
        self.filename = re.sub(r'\.[a-z]+$', f'.{file_ext}', filename)
        # remove the data URL prefix from the base64 image string
        self.base64_image = re.sub('^data:image/.+;base64,', '', base64_image)


class Mail:
    def __init__(self, api_key: str, domain: str, current_status: Status = Status()):
        self.api_key = api_key
        self.domain = domain
        self.current_status = current_status
        self.logger = logging.getLogger('xiq-ppsk-ldap-sync.mail.Mail')

    @staticmethod
    def render_html_body(
            name: str,
            ssid: str,
            logo_image: MailImage = None,
            company_name: str = None,
            passphrase: str = None,
            username: str = None,
            qrcode_image: MailImage = None,
            extra_message: str = None,
            kb_article_url: str = None,
            support_email: str = None,
            support_page_url: str = None
    ):
        """
        Function to render the HTML body of the email
        :param name: The name of the recipient
        :type name: str
        :param ssid: The SSID of the network
        :type ssid: str
        :param logo_image: The logo image to embed in the email
        :type logo_image: MailImage | None
        :param company_name: The name of the company
        :type company_name: str | None
        :param passphrase: The passphrase for the network
        :type passphrase: str | None
        :param username: The username for the network
        :type username: str | None
        :param qrcode_image: The QR code image to embed in the email
        :type qrcode_image: MailImage | None
        :param extra_message: An extra message to include in the email
        :type extra_message: str | None
        :param kb_article_url: URL to a knowledge base article
        :type kb_article_url: str | None
        :param support_email: The support email address
        :type support_email: str | None
        :param support_page_url: The URL to the support page
        :type support_page_url: str | None
        :return: The rendered HTML body
        :rtype: str
        """
        environment = Environment(loader=FileSystemLoader("templates/"))
        template = environment.get_template("email_message.html.j2")
        return template.render(
            name=name,
            logo_url=logo_image.filename if logo_image else None,
            company_name=company_name,
            ssid=ssid,
            passphrase=passphrase,
            username=username,
            qr_code_url=qrcode_image.filename if qrcode_image else None,
            extra_message=extra_message,
            kb_article_url=kb_article_url,
            support_email=support_email,
            support_page_url=support_page_url,
            current_year=str(datetime.now().year)
        )

    def send(
            self,
            to_address: str,
            from_address: str,
            subject: str,
            html_body: str,
            logo: MailImage = None,
            qrcode: MailImage = None
    ) -> bool:
        """
        Function to send an email using the Mailgun API
        :param to_address: The recipient's email address
        :type to_address: str
        :param from_address: The sender's email address
        :type from_address: str
        :param subject: The subject of the email
        :type subject: str
        :param html_body: The HTML body of the email
        :type html_body: str
        :param logo: The logo image to embed in the email
        :type logo: MailImage | None
        :param qrcode: The QR code image to embed in the email
        :type qrcode: MailImage | None
        :return: Success or failure of the email sending
        :rtype: bool
        """
        files = []
        if logo:
            files.append(('inline', (logo.filename, b64decode(logo.base64_image))))
        if qrcode:
            files.append(('inline', (qrcode.filename, b64decode(qrcode.base64_image))))
        response = requests.post(
            f"https://api.mailgun.net/v3/{self.domain}/messages",
            files=files,
            auth=('api', self.api_key),
            data={
                'from': from_address,
                'to': to_address,
                'subject': subject,
                'html': html_body
            }
        )
        if response.status_code == 200:
            self.logger.info(f"Email sent successfully to {to_address}")
            return True
        self.logger.error(f"Failed to send email to {to_address}")
        self.logger.error(f"Response: {response.text}")
        self.logger.error(f"Status Code: {response.status_code}")
        self.current_status.set_status(StatusValue.ERROR)
        return False
