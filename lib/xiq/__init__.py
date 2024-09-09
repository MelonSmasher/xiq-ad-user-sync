import requests
import logging
from faker import Faker
import hashlib
from copy import deepcopy
from lib.util import Status, StatusValue, calc_exponential_backoff
import time

class PcgUser:
    def __init__(self, name: str, email: str, user_group_name: str):
        self.name = name
        self.email = email
        self.user_group_name = user_group_name

    def __repr__(self):
        return self.__str__()

    def __dict__(self):
        return {
            "name": self.name,
            "email": self.email,
            "user_group_name": self.user_group_name
        }

    def __str__(self):
        return f"{self.__dict__()}"


class XIQUser:
    def __init__(self, xiq_entry: dict):
        self.id = xiq_entry['id'] if 'id' in xiq_entry else None
        self.create_time = xiq_entry['create_time'] if 'create_time' in xiq_entry else None
        self.update_time = xiq_entry['update_time'] if 'update_time' in xiq_entry else None
        self.org_id = xiq_entry['org_id'] if 'org_id' in xiq_entry else None
        self.name = xiq_entry['name'] if 'name' in xiq_entry else None
        self.description = xiq_entry['description'] if 'description' in xiq_entry else None
        self.email_address = xiq_entry['email_address'] if 'email_address' in xiq_entry else None
        self.phone_number = xiq_entry['phone_number'] if 'phone_number' in xiq_entry else None
        self.password = xiq_entry['password'] if 'password' in xiq_entry else None
        self.user_name = xiq_entry['user_name'] if 'user_name' in xiq_entry else None
        self.visit_purpose = xiq_entry['visit_purpose'] if 'visit_purpose' in xiq_entry else None
        self.email_password_delivery = xiq_entry[
            'email_password_delivery'] if 'email_password_delivery' in xiq_entry else None
        self.sms_password_delivery = xiq_entry[
            'sms_password_delivery'] if 'sms_password_delivery' in xiq_entry else None
        self.user_group_id = xiq_entry['user_group_id'] if 'user_group_id' in xiq_entry else None
        self.user_group_name = xiq_entry['user_group_name'] if 'user_group_name' in xiq_entry else None
        self.approval_type = xiq_entry['approval_type'] if 'approval_type' in xiq_entry else None
        self.expired_time = xiq_entry['expired_time'] if 'expired_time' in xiq_entry else None
        self.wifi_settings = xiq_entry['wifi_settings'] if 'wifi_settings' in xiq_entry else []

    def __repr__(self):
        return self.__str__()

    # def __dict__(self):
    #     return {
    #         'id': self.id,
    #         'create_time': self.create_time,
    #         'update_time': self.update_time,
    #         'org_id': self.org_id,
    #         'name': self.name,
    #         'description': self.description,
    #         'email_address': self.email_address,
    #         'phone_number': self.phone_number,
    #         'password': self.password,
    #         'user_name': self.user_name,
    #         'visit_purpose': self.visit_purpose,
    #         'email_password_delivery': self.email_password_delivery,
    #         'sms_password_delivery': self.sms_password_delivery,
    #         'user_group_id': self.user_group_id,
    #         'user_group_name': self.user_group_name,
    #         'approval_type': self.approval_type,
    #         'expired_time': self.expired_time
    #     }

    def __str__(self):
        return f"{self.__dict__}"

    def to_pcg_user(self, user_group_name: str) -> PcgUser:
        self.user_group_name = user_group_name
        return PcgUser(
            name=self.name,
            email=self.email_address,
            user_group_name=user_group_name
        )


class XIQ:
    def __init__(
            self,
            url: str,
            username: str,
            password: str,
            current_status: Status = Status(),
            verify_ssl: bool = True,
            check_password_against_pwned: bool = False,
            strict_password_check: bool = True,
            password_generator_use_words=False,
            password_word_count: int = 5,
            max_request_retries: int = 7,
            request_retry_on_code: list = None
    ):
        if request_retry_on_code is None:
            request_retry_on_code = [400, 429, 500, 502, 503, 504]
        self.url = url.rstrip("/")
        self.current_status = current_status
        self.username = username
        self.password = password
        self.logger = logging.getLogger('xiq-ppsk-ldap-sync.lib.XIQ')
        self.verify_ssl = verify_ssl
        self.check_password_against_pwned = check_password_against_pwned
        self.strict_password_check = strict_password_check
        self.password_generator_use_words = password_generator_use_words
        self.password_word_count = password_word_count
        self.token = None
        self.default_headers = {
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        self.session = requests.Session()
        self.session.verify = self.verify_ssl
        self.session.headers.update(self.default_headers)
        self.faker = Faker()
        self.http_success_codes = [200, 201, 202, 204]
        self.max_request_retries = max_request_retries
        self.request_retry_on_code = request_retry_on_code

    def get_auth_token(self) -> str | bool:
        """
        Get an auth token and login to XIQ, update the session headers with the auth token
        :return: Auth token string or False
        :rtype: str | bool
        """
        response = self.session.post(
            url=f"{self.url}/login",
            json={
                "username": self.username,
                "password": self.password
            }
        )

        if response is None:
            self.logger.error("Failed to get auth token: No response")
            self.current_status.set_status(StatusValue.ERROR)
            return False

        if response.status_code != 200:
            self.logger.error(
                f"Failed to get auth token: HTTP/{response.status_code} - {response.reason}"
            )
            self.logger.debug(f"Response Body: \t\t{response.text}")
            self.current_status.set_status(StatusValue.ERROR)
            return False

        if "access_token" in response.json():
            self.token = response.json()["access_token"]
            self.session.headers.update({"Authorization": f"Bearer {self.token}"})
            self.logger.info("Successfully authenticated, session updated with auth token")
            self.logger.debug(f"Auth token: {self.token}")
            return self.token

        self.logger.error(
            f"Failed to get auth token: access_token not found in response - {response.text}"
        )
        self.current_status.set_status(StatusValue.ERROR)
        return False

    def revoke_access_token(self):
        """
        Revoke the current access token and log out of XIQ
        :return: True or False
        :rtype: bool
        """
        if self.token is None:
            self.logger.error("Failed to revoke access token: No access token found")
            self.current_status.set_status(StatusValue.ERROR)
            return False

        response = self.session.post(
            url=f"{self.url}/logout"
        )

        if response is None:
            self.logger.error("Failed to revoke access token: No response")
            self.current_status.set_status(StatusValue.ERROR)
            return False

        if response.status_code != 200:
            self.logger.error(
                f"Failed to revoke access token: HTTP/{response.status_code} - {response.reason}"
            )
            self.logger.debug(f"Response Body: \t\t{response.text}")
            self.current_status.set_status(StatusValue.ERROR)
            return False

        self.token = None
        self.session.headers.pop("Authorization")

        self.logger.info("Successfully revoked access token")
        return True

    def __base_request(
            self,
            method: str,
            url: str,
            json: dict = None,
            params: dict = None,
            retry_auth_on_fail: bool = True,
            retry: int = 0
    ) -> tuple[bool, requests.Response] | tuple[bool, None]:
        """
        Base request method to send requests to the XIQ API
        :param method: The HTTP method to use
        :type method: str
        :param url: The URL to send the request to
        :type url: str
        :param json: The JSON data to send with the request
        :type json: dict
        :param params: The URL parameters to send with the request
        :type params: dict
        :param retry_auth_on_fail: Whether to retry authentication if the request fails due to unauthorized
        :type retry_auth_on_fail: bool
        :param retry: The current retry count
        :type retry: int
        :return: The result of the operation as a boolean and the response object
        :rtype: tuple[bool, requests.Response] | tuple[bool, None]
        """
        response = self.session.request(
            method=method,
            url=url,
            json=json,
            params=params
        )
        if response is None:
            self.logger.error(f"Failed to send request: No response")
            self.current_status.set_status(StatusValue.ERROR)
            return False, response
        if response.status_code == 401 and retry_auth_on_fail:
            self.logger.warning("Failed to send request: Unauthorized, attempting to re-authenticate...")
            self.current_status.set_status(StatusValue.WARNING)
            if self.get_auth_token():
                self.logger.info("Re-authentication successful, retrying request...")
                return self.__base_request(
                    method=method,
                    url=url,
                    json=json,
                    params=params,
                    retry_auth_on_fail=False
                )
            self.logger.error("Re-authentication failed, request failed")
            self.current_status.set_status(StatusValue.ERROR)
            return False, response
        if response.status_code not in self.http_success_codes:
            # If the request failed and the status code is in the retry list
            if retry < self.max_request_retries and response.status_code in self.request_retry_on_code:
                self.logger.warning(
                    f"Failed to send request: HTTP/{response.status_code} - {response.reason}, retrying...")
                self.logger.debug(f"Response Body: \t\t{response.text}")
                self.current_status.set_status(StatusValue.WARNING)
                retry += 1
                mx_delay = 60
                sleep = calc_exponential_backoff(retry, max_delay=mx_delay)
                if sleep == mx_delay:
                    self.logger.warning(f"Max sleep time reached at {mx_delay} seconds")
                self.logger.info(
                    f"Retry count: {retry}, Max retries: {self.max_request_retries}, Sleeping for {sleep} seconds..."
                )
                time.sleep(sleep)
                return self.__base_request(
                    method=method,
                    url=url,
                    json=json,
                    params=params,
                    retry_auth_on_fail=retry_auth_on_fail,
                    retry=retry
                )
            self.logger.error(
                f"Failed to send request: HTTP/{response.status_code} - {response.reason}"
            )
            self.logger.debug(f"Response Body: \t\t{response.text}")
            self.current_status.set_status(StatusValue.ERROR)
            return False, response
        return True, response

    def has_password_leaked(self, password: str, strict: bool = True) -> bool:
        """
        Check if the password has been leaked using the pwnedpasswords API
        :param password: Password to check
        :type password: str
        :param strict: If True, if there is a communication error with the API, function will return True as if the password is leaked. If False, function will return False if there is a communication error with the API.
        :type strict: bool
        :return: True if the password is leaked, False if not
        :rtype: bool
        """
        # hash the password using sha1 and convert to uppercase
        hash_string = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        # get the first 5 characters of the hash
        prefix = hash_string[0:5]
        self.logger.debug(f"Checking password hash prefix: {prefix}")
        # Send the has prefix to the pwnedpasswords API to get a list of related hashes
        result = requests.get(
            url=f"https://api.pwnedpasswords.com/range/{prefix}",
            verify=self.verify_ssl
        )
        self.logger.info('API request to pwnedpasswords.com sent')
        # If the request was not successful and empty
        if result is None:
            self.logger.error('Failed to check password hash: No response')
            if strict:
                self.current_status.set_status(StatusValue.WARNING)
                self.logger.warning(f'Strict mode enabled, will assume that the password is leaked.')
                self.current_status.set_status(StatusValue.WARNING)
                return True
            self.current_status.set_status(StatusValue.ERROR)
            self.logger.warning(f'Strict mode disabled, will assume that the has not been leaked.')
            self.current_status.set_status(StatusValue.WARNING)
            return False
        # If the request was not successful
        if result.status_code != 200:
            self.logger.error(f"Failed to check password hash: HTTP/{result.status_code} - {result.reason}")
            self.logger.debug(f"Response Body: \t\t{result.text}")
            # If strict mode is enabled, return True
            if strict:
                self.logger.warning(f'Strict mode enabled, will assume that the password is leaked.')
                self.current_status.set_status(StatusValue.WARNING)
                return True
            # If strict mode is disabled, return False
            self.logger.warning(f'Strict mode disabled, will assume that the has not been leaked.')
            self.current_status.set_status(StatusValue.ERROR)
            return False
        self.logger.info('API request to pwnedpasswords.com successful')
        self.logger.info('Checking if the password hash is in the response...')
        # If the request was successful, get the response content
        response_content = result.content.decode('utf-8')
        # split the result twice - each line into key, value pairs of hash-postfixes and the usage count.
        hashes = dict(t.split(":") for t in response_content.split('\r\n'))
        # add the prefix to the key values (hashes) of the hashes dictionary
        hashes = dict((prefix + key, value) for (key, value) in hashes.items())
        # Iterate over the hashes dictionary
        for item_hash in hashes:
            # check if the password hash is in the dictionary
            if item_hash == hash_string:
                # if the hash is found in the hashes dictionary the password is leaked
                self.logger.warning('Password is leaked')
                self.current_status.set_status(StatusValue.WARNING)
                return True
        self.logger.info('Password is not leaked')
        # If we get here the password is not leaked
        return False

    def __generate_words_list__(self, word_count: int) -> list[str]:
        """
        Generate a list of random words
        :param word_count: The number of words to generate
        :type word_count: int
        :return: A list of random words
        :rtype: list[str]
        """
        words = []
        while len(words) < word_count:
            # generate a random sentence with 10 words
            opts = self.faker.sentence(nb_words=10).replace(".", "").lower().split(" ")
            # pick a random word from the sentence and capitalize it
            words.append(opts[self.faker.random_int(min=0, max=len(opts) - 1)].capitalize())
        return words

    @staticmethod
    def __generate_special_characters_list__() -> list[str]:
        """
        Generate a list of special characters
        :return: A list of special characters
        :rtype: list[str]
        """
        return [chr(x) for x in range(33, 48)] + [chr(x) for x in range(58, 65)] + [chr(x) for x in range(91, 96)]

    @staticmethod
    def __generate_numbers_list__() -> list[str]:
        """
        Generate a list of numbers as strings. This is a list of numbers from 0 to 9
        :return: A list of numbers as strings
        :rtype: list[str]
        """
        return [str(x) for x in list(range(0, 9))]

    @staticmethod
    def __generate_upper_and_lower_letters_list__() -> list[str]:
        """
        Generate a list of upper and lower case letters
        :return: A list of upper and lower case letters
        :rtype: list[str]
        """
        # return a list of upper case letters and lower case letters using the ASCII values
        return [chr(x) for x in range(65, 91)] + [chr(x) for x in range(97, 123)]

    def generate_user_password(
            self,
            enable_letters: bool,
            enable_numbers: bool,
            enable_special_characters: bool,
            password_min_length: int = 16,
            word_based: bool = True,
            word_count: int = 4,
            check_password_against_pwned: bool = False,
            strict_password_check: bool = True
    ) -> str:
        """
        Generate a random password for the user
        :param enable_letters: Enable letters in the password
        :type enable_letters: bool
        :param enable_numbers: Enable numbers in the password
        :type enable_numbers: bool
        :param enable_special_characters: Enable special characters in the password
        :type enable_special_characters: bool
        :param password_min_length: The minimum length of the password
        :type password_min_length: int
        :param word_based: If True, generate a password based on words, if False, generate a random password with random letters
        :type word_based: bool
        :param word_count: The number of words to use in the password
        :type word_count: int
        :param check_password_against_pwned: Whether to check the password against the pwnedpasswords API
        :type check_password_against_pwned: bool
        :param strict_password_check: If True, if there is a communication error with the API, function will return True as if the password is leaked. If False, function will return False if there is a communication error with the API. This parameter only has an effect if check_password_against_pwned is True
        :type strict_password_check: bool
        :return: Random password
        :rtype: str
        """
        # Guard clauses to check and validate parameters
        if not enable_letters and not enable_numbers and not enable_special_characters:
            self.logger.error("Cannot generate password: No character set enabled")
            self.current_status.set_status(StatusValue.ERROR)
            raise ValueError("At least one character set must be enabled when generating a password")
        if word_based and word_count < 1 and enable_letters:
            self.logger.error("Cannot generate password: Word count must be greater than 0")
            self.current_status.set_status(StatusValue.ERROR)
            raise ValueError("Word count must be greater than 0 when generating a word-based password")
        if not word_based and enable_letters and password_min_length < 8:
            self.logger.error("Cannot generate password: Password length must be greater than 7")
            self.current_status.set_status(StatusValue.ERROR)
            raise ValueError("Password length must be greater than 7 when generating a random password")
        if not word_based and enable_letters and password_min_length < 16:
            self.logger.warning("Password length is less than 16 characters, this is not recommended")
            self.current_status.set_status(StatusValue.WARNING)
        if not enable_special_characters and not enable_numbers:
            self.logger.warning("Password does not contain special characters or numbers, this is not recommended")
            self.current_status.set_status(StatusValue.WARNING)
        if word_based and not enable_letters:
            self.logger.warning(
                "Word based passwords is enabled but letters are not, the password will be generated without words"
            )
            self.current_status.set_status(StatusValue.WARNING)

        self.logger.info("Generating random password...")

        # Generate the character sets
        words = self.__generate_words_list__(word_count)
        special_chars = self.__generate_special_characters_list__()
        numbers = self.__generate_numbers_list__()
        upper_and_lower_letters = self.__generate_upper_and_lower_letters_list__()
        password_parts = []
        unused_words = deepcopy(words)
        used_words = []
        char_types = []

        if enable_letters:
            char_types.append(0)
        if enable_numbers:
            char_types.append(1)
        if enable_special_characters:
            char_types.append(2)

        # While the password is less than the minimum length
        # and the word count is less than the required word count if the password is word based
        # Check for this is done in the loop
        while True:
            # Check if the password is word based
            if word_based and enable_letters:
                # Check if there are any unused words
                if len(unused_words) != 0:
                    # Pick a random word from the pool of unused words or the only word if there is only one
                    word = unused_words[0] if len(unused_words) == 1 else unused_words[
                        self.faker.random_int(min=0, max=len(unused_words) - 1)
                    ]
                    # add a random word to the password parts list
                    password_parts.append(word)
                    # remove the word from the unused words list
                    unused_words.remove(word)
                    # add the word to the used words list
                    used_words.append(word)
            # Create a new list to store characters for the password
            chosen_chars = []
            while len(chosen_chars) < 2:
                # pick a random character type from the char_types list
                if len(char_types) == 1:
                    char_type = char_types[0]
                else:
                    char_type = char_types[self.faker.random_int(min=0, max=len(char_types) - 1)]

                if char_type == 0:
                    self.logger.debug("Character type is 0 - letters")
                if char_type == 1:
                    self.logger.debug("Character type is 1 - numbers")
                if char_type == 2:
                    self.logger.debug("Character type is 2 - special character")

                # If the character type is 0 and letters are enabled
                if char_type == 0 and enable_letters and not word_based:
                    # pick a random upper or lower case letter from the upper_and_lower_letters list
                    chosen_chars.append(
                        upper_and_lower_letters[self.faker.random_int(min=0, max=len(upper_and_lower_letters) - 1)]
                    )
                # If the character type is 1 and numbers are enabled
                if char_type == 1 and enable_numbers:
                    # pick a random number from the numbers list
                    chosen_chars.append(
                        numbers[self.faker.random_int(min=0, max=len(numbers) - 1)]
                    )
                # If the character type is 2 and special characters are enabled
                if char_type == 2 and enable_special_characters:
                    chosen_chars.append(
                        special_chars[self.faker.random_int(min=0, max=len(special_chars) - 1)]
                    )
            # add the inbetween characters to the password parts list
            password_parts.extend(chosen_chars)
            self.logger.debug(f"Password parts: {password_parts}")
            # Check if the password is greater than or equal to the minimum length
            # and the word count is greater than or equal to the required word count if the password is word based
            if (
                    len(''.join(password_parts)) >= password_min_length
            ) and (
                    len(used_words) >= word_count if (word_based and enable_letters) else True
            ):
                # break the loop
                break

        # Form the password from the password parts list
        password = ''.join(password_parts)
        self.logger.info(f"Generated password!")
        # If leak checking is enabled
        if check_password_against_pwned:
            # Check if the password has been leaked
            self.logger.info("Checking if password is leaked...")
            if self.has_password_leaked(password=password, strict=strict_password_check):
                self.logger.warning("Password is leaked, generating new password...")
                self.current_status.set_status(StatusValue.WARNING)
                # sorry for the recursion, but we need to make sure the password is not leaked
                return self.generate_user_password(
                    enable_letters=enable_letters,
                    enable_numbers=enable_numbers,
                    enable_special_characters=enable_special_characters,
                    password_min_length=password_min_length,
                    word_based=word_based,
                    word_count=word_count,
                    check_password_against_pwned=check_password_against_pwned,
                    strict_password_check=strict_password_check
                )
        self.logger.info("Password generated successfully")
        return password

    def create_ppsk_user(self, user: XIQUser) -> XIQUser | bool:
        """
        Create a PPSK user in XIQ
        :param user: The user object to create
        :type user: XIQUser
        :return: The password of the user or False if the user was not created
        :rtype: XIQUser | bool
        """
        self.logger.info(f"Creating PPSK user: {user.name} - {user.email_address} - {user.user_group_id}")

        # get the user group to check if it exists
        user_group = self.get_usergroup(user.user_group_id)
        if user_group is None:
            self.logger.error(f"Failed to create PPSK user: User group not found - {user.user_group_id}")
            self.current_status.set_status(StatusValue.ERROR)
            return False

        # generate a random password for the user
        password = self.generate_user_password(
            word_count=self.password_word_count,
            word_based=self.password_generator_use_words,
            enable_letters=user_group['password_settings']['enable_letters'],
            enable_numbers=user_group['password_settings']['enable_numbers'],
            enable_special_characters=user_group['password_settings']['enable_special_characters'],
            password_min_length=user_group['password_settings']['password_length'],
            check_password_against_pwned=self.check_password_against_pwned,
            strict_password_check=self.strict_password_check
        )
        user.password = password
        # create the user
        result, response = self.__base_request(
            method="POST",
            url=f"{self.url}/endusers",
            json=user.__dict__
        )
        if result is False:
            self.logger.error("Failed to create PPSK user")
            self.logger.debug(f"Response Body: \t\t{response.text}")
            self.current_status.set_status(StatusValue.ERROR)
            return False
        self.logger.info(f"PPSK user created successfully: {user.name} - {user.email_address} - {user.user_group_id}")
        return user

    def get_ppsk_users(self, user_group_id: str, page_size: int = 100) -> tuple[list[XIQUser], bool]:
        """
        Get PPSK users from XIQ
        :param user_group_id: The user group ID to get the users from
        :type user_group_id: str
        :param page_size: The number of users to get per page
        :type page_size: int
        :return: A tuple of the users list and a boolean indicating if the operation was successful
        :rtype: tuple[list[XIQUser], bool]
        """
        users = []
        page = 1
        page_count = 1
        self.logger.info(f"Getting PPSK users form XIQ...")
        while page <= page_count:
            result, response = self.__base_request(
                method="GET",
                url=f"{self.url}/endusers",
                params={
                    "page": page,
                    "limit": page_size,
                    "user_group_ids": user_group_id
                }
            )

            if result is False:
                self.logger.error("Failed to get PPSK users")
                self.logger.debug(f"Response Body: \t\t{response.text}")
                self.current_status.set_status(StatusValue.ERROR)
                return users, False

            response_json = response.json()
            if 'data' in response_json:
                users.extend(response_json['data'])
            else:
                self.logger.error(
                    f"Failed to get PPSK users: 'data' not found in response"
                )
                self.logger.debug(f"Response Body: \t\t{response.text}")
                self.current_status.set_status(StatusValue.ERROR)
                return users, False

            page_count = response_json['total_pages']
            self.logger.info(f"Got PPSK users: Page {page}/{page_count}")
            page += 1
        self.logger.info(f"Got {len(users)} PPSK users successfully")
        return [XIQUser(user) for user in users], True

    def delete_ppsk_user(self, user_id: str) -> bool:
        """
        Delete a PPSK user from XIQ
        :param user_id: The ID of the user to delete
        :type user_id: str
        :return: The result of the operation as a boolean
        :rtype: bool
        """
        result, response = self.__base_request(
            method="DELETE",
            url=f"{self.url}/endusers/{user_id}"
        )
        if result is False:
            self.logger.error(f"Failed to delete PPSK user: {user_id}")
            self.logger.debug(f"Response Body: \t\t{response.text}")
            self.current_status.set_status(StatusValue.ERROR)
            return False
        self.logger.info(f"PPSK user deleted successfully: {user_id}")
        return True

    def add_user_to_pcg(self, policy_id: str, users: list[PcgUser]) -> bool:
        """
        Add users to a PCG in XIQ
        :param policy_id: The ID of the PCG to add the users to
        :type policy_id: str
        :param users: A list of PcgUser objects to add to the PCG
        :type users: list[PcgUser]
        :return: The result of the operation as a boolean
        :rtype: bool
        """
        result, response = self.__base_request(
            method="POST",
            url=f"{self.url}/pcgs/key-based/network-policy-{policy_id}/users",
            json={
                "users": [u.__dict__() for u in users]
            }
        )
        if result is False:
            self.logger.error(f"Failed to add users to PCG: {policy_id}")
            self.logger.debug(f"Response Body: \t\t{response.text}")
            self.current_status.set_status(StatusValue.ERROR)
            return False
        return True

    def get_pcg_users(self, policy_id: str) -> tuple[list, bool]:
        """
        Get users from a PCG in XIQ
        :param policy_id: The ID of the PCG to get the users from
        :type policy_id: str
        :return: A tuple of the users list and a boolean indicating if the operation was successful
        :rtype: tuple[list, bool]
        """
        result, response = self.__base_request(
            method="GET",
            url=f"{self.url}/pcgs/key-based/network-policy-{policy_id}/users"
        )
        if result is False:
            self.logger.error(f"Failed to get PCG users: {policy_id}")
            self.logger.debug(f"Response Body: \t\t{response.text}")
            self.current_status.set_status(StatusValue.ERROR)
            return [], False
        return response.json(), True

    def remove_user_from_pcg(self, policy_id: str, user_id: str) -> bool:
        """
        Delete a user from a PCG in XIQ
        :param policy_id: The ID of the PCG to delete the user from
        :type policy_id: str
        :param user_id: The ID of the user to delete
        :type user_id: str
        :return: The result of the operation as a boolean
        :rtype: bool
        """
        result, response = self.__base_request(
            method="DELETE",
            url=f"{self.url}/pcgs/key-based/network-policy-{policy_id}/users/{user_id}"
        )
        if result is False:
            self.logger.error(f"Failed to remove user from PCG: {policy_id} - {user_id}")
            self.logger.debug(f"Response Body: \t\t{response.text}")
            self.current_status.set_status(StatusValue.ERROR)
            return False
        return True

    def get_network_policies(self) -> list | bool:
        """
        Get network policies from XIQ
        :return: The list of network policies or False if there was an error
        :rtype: list | bool
        """
        results = []
        next_page = True
        page = 1
        while next_page:
            result, response = self.__base_request(
                method="GET",
                url=f"{self.url}/network-policies",
                params={
                    "page": page,
                    "limit": 100
                }
            )
            if result is False:
                self.logger.error("Failed to get network policies")
                self.logger.debug(f"Response Body: \t\t{response.text}")
                self.current_status.set_status(StatusValue.ERROR)
                return False

            response_json = response.json()
            results.extend(response_json['data'])

            if page >= response_json['total_pages']:
                next_page = False
            page += 1
        return results

    def get_network_policy(self, policy_id: str) -> dict | bool:
        """
        Retrieve a network policy from XIQ
        :param policy_id: The ID of the policy to retrieve
        :type policy_id: str
        :return: The network policy or False if there was an error
        :rtype: dict | bool
        """
        result, response = self.__base_request(
            method="GET",
            url=f"{self.url}/network-policies/{policy_id}"
        )
        if result is False:
            self.logger.error(f"Failed to get network policy: {policy_id}")
            self.logger.debug(f"Response Body: \t\t{response.text}")
            self.current_status.set_status(StatusValue.ERROR)
            return False

        return response.json()

    def get_network_policy_ssids(self, policy_id: str) -> list | bool:
        """
        Get the SSIDs associated with a network policy
        :param policy_id: The ID of the policy to get the SSIDs for
        :type policy_id: str
        :return: The list of SSIDs or False if there was an error
        :rtype: list | bool
        """
        ssids = []
        next_page = True
        page = 1

        while next_page:
            result, response = self.__base_request(
                method="GET",
                url=f"{self.url}/network-policies/{policy_id}/ssids",
                params={
                    "page": page,
                    "limit": 100
                }
            )

            if result is False:
                self.logger.error("Failed to get network policy SSIDs")
                self.logger.debug(f"Response Body: \t\t{response.text}")
                self.current_status.set_status(StatusValue.ERROR)
                return False

            response_json = response.json()
            ssids.extend(response_json['data'])

            if page >= response_json['total_pages']:
                next_page = False
            page += 1
        return ssids

    def get_ssid_advanced_settings(self, ssid_id: str) -> dict | bool:
        """
        Get the advanced settings for an SSID
        :param ssid_id: The ID of the SSID to get the advanced settings for
        :type ssid_id: str
        :return: The advanced settings or False if there was an error
        :rtype: dict | bool
        """
        result, response = self.__base_request(
            method="GET",
            url=f"{self.url}/ssids/advanced-settings/{ssid_id}"
        )
        if result is False:
            self.logger.error(f"Failed to get SSID advanced settings: {ssid_id}")
            self.logger.debug(f"Response Body: \t\t{response.text}")
            self.current_status.set_status(StatusValue.ERROR)
            return False
        return response.json()

    def get_usergroups(self) -> list | bool:
        """
        Get user groups from XIQ
        :return: list of user groups or False if there was an error
        :rtype: list | bool
        """

        next_page = True
        page = 1
        usergroups = []

        while next_page:
            result, response = self.__base_request(
                method="GET",
                url=f"{self.url}/usergroups",
                params={
                    "page": page,
                    "limit": 100
                }
            )
            if result is False:
                self.logger.error("Failed to get user groups")
                self.logger.debug(f"Response Body: \t\t{response.text}")
                self.current_status.set_status(StatusValue.ERROR)
                return False

            response_json = response.json()
            usergroups.extend(response_json['data'])

            if page >= response_json['total_pages']:
                next_page = False
            page += 1
        return usergroups

    def get_usergroup(self, usergroup_id: str) -> dict | bool | None:
        """
        Get a user group by ID
        :param usergroup_id: The ID of the user group to get
        :type usergroup_id: str
        :return: The user group or False if there was an error or None if there was no matching user group
        :rtype: dict | bool | None
        """
        # This function is a helper function to get a user group by ID
        # The api does not have a direct endpoint to get a user group by ID
        # So we will get all user groups and iterate over them to find the user group by ID
        user_groups = self.get_usergroups()
        if user_groups is False:
            return False
        for user_group in user_groups:
            if str(user_group['id']) == str(usergroup_id):
                return user_group
        return None
