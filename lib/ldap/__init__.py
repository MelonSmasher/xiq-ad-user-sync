import ldap3
import logging
import socket
from ldap3.core.exceptions import LDAPException
from lib.util import Status, StatusValue


class InvalidLdapCredentialsException(LDAPException):
    def __init__(self, message):
        super(InvalidLdapCredentialsException, self).__init__(
            f"Invalid LDAP credentials, unable to authenticate with LDAP server.\n{message}"
        )


class EmptyLdapServerPoolException(LDAPException):
    def __init__(self, message):
        super(EmptyLdapServerPoolException, self).__init__(
            f"Empty LDAP Server pool, unable to build connection pool.\n{message}"
        )


class LdapUser:
    def __init__(self, ldap_entry: ldap3.Entry):
        self.username = str(ldap_entry["sAMAccountName"])
        self.email_address = str(ldap_entry["mail"])
        self.first_name = str(ldap_entry["givenName"])
        self.last_name = str(ldap_entry["sn"])
        self.display_name = str(ldap_entry["displayName"])
        self.user_account_control = int(str(ldap_entry["userAccountControl"]))
        self.employee_id = str(ldap_entry["employeeID"])

    def __repr__(self):
        return self.__str__()

    def __dict__(self):
        return {
            'username': self.username,
            'email_address': self.email_address,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'display_name': self.display_name,
            'user_account_control': self.user_account_control,
            'employee_id': self.employee_id
        }

    def __str__(self):
        return f'{self.__dict__()}'


# Define LDAP class
class LDAP:
    def __init__(
            self,
            hosts: list,
            domain: str,
            username: str,
            password: str,
            auth_method: str,
            sasl_mechanism: str,
            auto_bind: str,
            current_status: Status = Status(),
            server_pool: ldap3.ServerPool = None,
            connection: ldap3.Connection = None

    ):

        if auth_method == 'NTLM':
            auth_method = ldap3.NTLM
        elif auth_method == 'ANONYMOUS':
            auth_method = ldap3.ANONYMOUS
        elif auth_method == 'SIMPLE':
            auth_method = ldap3.SIMPLE
        elif auth_method == 'SASL':
            auth_method = ldap3.SASL

        if auth_method == ldap3.SASL:
            if sasl_mechanism == 'EXTERNAL':
                sasl_mechanism = ldap3.EXTERNAL
            elif sasl_mechanism == 'DIGEST-MD5':
                sasl_mechanism = ldap3.DIGEST_MD5
            elif sasl_mechanism == 'GSSAPI':
                sasl_mechanism = ldap3.GSSAPI
            elif sasl_mechanism == 'PLAIN':
                sasl_mechanism = ldap3.PLAIN
        else:
            sasl_mechanism = None

        if auto_bind == 'DEFAULT':
            auto_bind = ldap3.AUTO_BIND_DEFAULT
        elif auto_bind == 'NONE':
            auto_bind = ldap3.AUTO_BIND_NONE
        elif auto_bind == 'NO_TLS':
            auto_bind = ldap3.AUTO_BIND_NO_TLS
        elif auto_bind == 'TLS_BEFORE_BIND':
            auto_bind = ldap3.AUTO_BIND_TLS_BEFORE_BIND
        elif auto_bind == 'TLS_AFTER_BIND':
            auto_bind = ldap3.AUTO_BIND_TLS_AFTER_BIND

        self.hosts = hosts
        self.domain = domain
        self.username = username
        self.password = password
        self.current_status = current_status
        self.logger = logging.getLogger('xiq-ppsk-ldap-sync.lib.LDAP')
        self.auth_method = auth_method
        self.sasl_mechanism = sasl_mechanism
        self.auto_bind = auto_bind
        self.server_pool = server_pool
        self.connection = connection

    def __parse_host_str(self, host: str) -> ldap3.Server | None:
        """
        Function to parse the host string into a ldap3.Server object
        format: server:port:use_ssl e.g. ldap.example.com:389:False
        :param host: The host string to parse
        :type: str
        :return: The ldap3.Server object or None
        :rtype: ldap3.Server | None
        """
        # Default values
        server = host
        port = 389
        use_ssl = False

        # If the host string contains a colon, parse it.
        if ':' in host:
            server = host.split(':')[0]
            port = host.split(':')[1]

            # Check if the port is a digit or a string
            if not port.isdigit():
                # The port is not a digit, so we treat it as a string and check if it is:
                # 't'|'f'|'true'|'false'
                if port.lower().startswith('t'):
                    # Set the use_ssl to True and the port to 636
                    use_ssl = True
                    port = 636
                elif port.lower().startswith('f'):
                    # Set the use_ssl to False and the port to 389
                    use_ssl = False
                    port = 389
                else:
                    # If the port is not a digit, and not a parsable boolean, log a warning and return None
                    # We basically have no idea what the user is trying to do here
                    self.logger.warning(
                        f'Invalid port number: "{port}" for host string: "{host}". '
                        f'The format should be server:port:use_ssl '
                        f'e.g. ldap.example.com:389:False'
                    )
                    self.current_status.set_status(StatusValue.WARNING)
                    return None
                # Return the ldap3.Server object with the provided server, provided use_ssl value, and an inferred port.
                self.logger.warning(
                    f'No port was provided for host: {host}, assuming default port "{port}" '
                    f'based on parsed boolean value of "{host.split(':')[1]}" '
                    f'because it starts with "{host.split(':')[1][0].lower()}".'
                    f'The format should be server:port:use_ssl '
                    f'e.g. ldap.example.com:389:False'
                )
                self.current_status.set_status(StatusValue.WARNING)
                return ldap3.Server(host=server, port=port, use_ssl=use_ssl, get_info=ldap3.ALL)
            else:
                # The port is a digit, so we treat it as an int
                port = int(port)
                if port in [0, 1]:
                    # The port slot is an int but is likely meant to be a boolean for use_ssl without a provided port
                    use_ssl = bool(port)
                    port = 636 if use_ssl else 389
                    # Return the ldap3.Server object with the provided server, provided use_ssl value, and
                    # an inferred port.
                    self.logger.warning(
                        f'No port was provided for host: {host}, assuming default port "{port}" '
                        f'based on parsed boolean value of "{host.split(':')[1]}" '
                        f'because "{host.split(':')[1]}" as a boolean equals "{use_ssl}". '
                        f'The format should be server:port:use_ssl '
                        f'e.g. ldap.example.com:389:False'
                    )
                    self.current_status.set_status(StatusValue.WARNING)
                    return ldap3.Server(host=server, port=port, use_ssl=use_ssl, get_info=ldap3.ALL)

                # If the port is 389, use_ssl default is False
                if port == 389:
                    use_ssl = False
                # If the port is 636, use_ssl default is True
                if port == 636:
                    use_ssl = True

                # Regardless of the default values based on ports if the use_ssl index is present parse it
                if len(host.split(':')) > 2:
                    # If the use_ssl index is True, use_ssl is True
                    if host.split(':')[2].lower().startswith('t'):
                        use_ssl = True
                    elif host.split(':')[2].lower().startswith('f'):
                        use_ssl = False
                    else:
                        if port in [389, 636]:
                            self.logger.warning(
                                f'The use_ssl option was not explicitly set in the host string {host}. '
                                f'The use_ssl value "{use_ssl}" will be inferred from the port "{port}". '
                                f'The format should be server:port:use_ssl '
                                f'e.g. ldap.example.com:389:False'
                            )
                            self.current_status.set_status(StatusValue.WARNING)
                        else:
                            # We have no clue what the user is trying to do here, return none.
                            self.logger.warning(
                                f'Unable to determine the use_ssl value from the host string {host} '
                                f'The format should be server:port:use_ssl '
                                f'e.g. ldap.example.com:389:False'
                            )
                            self.current_status.set_status(StatusValue.WARNING)
                            return None
        else:
            # If the host string does not contain a colon warn and return a server object with
            # sane default port and ssl values
            self.logger.warning(
                f'Malformed host string: "{host}". '
                f'The format should be server:port:use_ssl '
                f'e.g. ldap.example.com:389:False '
                f'Using default values for port and use_ssl: server={server}, port={port}, use_ssl={use_ssl}'
            )
            self.current_status.set_status(StatusValue.WARNING)
        # Return the ldap3.Server object with the provided server, provided port, and provided use_ssl value
        return ldap3.Server(host=server, port=port, use_ssl=use_ssl, get_info=ldap3.ALL)

    def __test_ldap_host(self, server: ldap3.Server) -> bool:
        """
        Function to test if the provided LDAP server is reachable
        :param server: The ldap3.Server object to test
        :type: ldap3.Server
        :return:
        :rtype: bool
        """
        m_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        m_socket.settimeout(2)
        self.logger.debug(f'Testing connection to LDAP server {server.host}:{server.port}...')
        try:
            # Attempt to connect to the provided server
            m_socket.connect((server.host, int(server.port)))
            m_socket.shutdown(2)
        except Exception as e:
            # If the connection fails, log the error and return False
            self.logger.warning(f'Failed to connect to LDAP server {server.host}:{server.port}: {e}')
            self.current_status.set_status(StatusValue.WARNING)
            return False
        self.logger.info(f'Successfully connected to LDAP server {server.host}:{server.port}')
        return True

    def build_connection(self) -> ldap3.Connection:
        """
        Function to build a server pool and LDAP connection from the provided hosts.
        :return: An LDAP connection object
        :rtype: ldap3.Connection
        """
        # Create a new server pool
        server_pool = ldap3.ServerPool(servers=[], exhaust=True, active=True, pool_strategy=ldap3.FIRST)
        # Iterate over the provided hosts
        for host in self.hosts:
            self.logger.debug(f'Parsing host string: {host} ...')
            # Parse the host string into a ldap3.Server object
            server = self.__parse_host_str(host)
            # If the server object is None, skip to the next
            if server is None:
                self.logger.warning(f'Failed to parse host string {host} into server object.')
                self.current_status.set_status(StatusValue.WARNING)
                continue
            self.logger.info(f'Successfully parsed host string {host} into server object: {server}')
            # Test if the server is reachable
            if self.__test_ldap_host(server):
                server_pool.add(server)

        # If no servers are reachable, log an error and raise an exception
        if len(server_pool.servers) == 0:
            self.logger.error('No LDAP servers are reachable.')
            self.current_status.set_status(StatusValue.ERROR)
            # Raise an exception if no servers are reachable
            raise EmptyLdapServerPoolException('No LDAP servers are reachable.')

        self.logger.debug(f'LDAP Server Pool: {server_pool}')
        self.logger.debug(f'Attempting to bind to LDAP server pool...')
        # Test the bind credentials against the server pool
        connection = ldap3.Connection(
            server_pool,
            user=f'{self.domain}\\{self.username}',
            password=self.password,
            authentication=self.auth_method,
            sasl_mechanism=self.sasl_mechanism,
            auto_bind=self.auto_bind
        )

        # If the bind fails, log an error and raise an exception
        if not connection.bind():
            self.logger.error(
                f'Failed to bind to LDAP server {server_pool[0].host}:{server_pool[0].port} with '
                f'user {self.domain}\\{self.username}.'
            )
            self.current_status.set_status(StatusValue.ERROR)
            # Raise an exception if the bind fails
            raise InvalidLdapCredentialsException(
                f'Failed to bind to LDAP server {server_pool[0].host}:{server_pool[0].port} with '
                f'user {self.domain}\\{self.username}.'
            )

        self.connection = connection
        self.server_pool = server_pool
        self.logger.info(
            f'Successfully bound to LDAP server pool with user {self.domain}\\{self.username}.'
        )
        return connection

    def destroy_connection(self):
        """
        Function to destroy the ldap connection and server pool
        :return: The success status of the operation
        :rtype: bool
        """
        if self.connection is None:
            self.logger.warning('No LDAP connection to destroy.')
            self.current_status.set_status(StatusValue.WARNING)
            return False
        self.connection.unbind()
        self.connection = None
        self.server_pool = None
        self.logger.info('LDAP connection and server pool destroyed successfully')
        return True

    @staticmethod
    def __domain_to_search_base(domain: str) -> tuple[str, str]:
        """
        Function to convert a domain string to an LDAP search base string
        :param domain: The domain string to convert
        :type: str
        :return: A tuple containing the search base and the top-level domain
        :rtype: tuple[str, str]
        """
        subdir_list = domain.split('.')
        tdl = subdir_list[-1]
        subdir_list = subdir_list[:-1]
        if subdir_list:
            return 'DC=' + ',DC='.join(subdir_list) + ',DC=' + tdl, tdl
        return 'DC=' + tdl, tdl

    def retrieve_users_from_group(
            self,
            group_dn: str,
            search_base: str = None,
            ldap_search_filter: str = ''
    ) -> list[LdapUser]:
        """
        Function to retrieve users from an LDAP group
        :param group_dn: The distinguished name of the group
        :type: str
        :param search_base: The search base to use for the LDAP query
        :type: str
        :param ldap_search_filter: An additional LDAP search filter to apply
        :type: str
        :return: list of LDAP Users
        :rtype: list[LdapUser]
        """
        results = []
        page_size = 1000
        attrs = [
            'objectClass',
            'userAccountControl',
            'sAMAccountName',
            'name',
            'mail',
            'displayName',
            'sn',
            'givenName',
            'employeeID'
        ]
        # This is an extended match operator that walks the chain of ancestry in objects all the way to the root until it finds a match. This reveals group nesting.
        LDAP_MATCHING_RULE_IN_CHAIN = '1.2.840.113556.1.4.1941'
        search_filter = f'(&(objectClass=user)(memberof:{LDAP_MATCHING_RULE_IN_CHAIN}:={group_dn}){ldap_search_filter})'
        self.logger.debug(f'LDAP Search Filter: {search_filter}')

        if search_base is None:
            self.logger.warning(
                f'No search base provided, attempting to infer search base from domain {self.domain} ...'
            )
            self.current_status.set_status(StatusValue.WARNING)
            # infer search base from domain if a specific search base is not provided
            search_base, tld = self.__domain_to_search_base(self.domain)
        self.logger.info(f'Successfully inferred search base from domain {self.domain}: {search_base}')

        self.logger.info(f'Querying LDAP server pool for users in group {group_dn} ...')
        next_page = True
        page = 1
        cookie = None
        while next_page:
            self.logger.debug(f'Querying LDAP server pool for users in group {group_dn} ... Page: {page}')
            self.connection.search(
                search_base=search_base,
                search_filter=search_filter,
                search_scope=ldap3.SUBTREE,
                attributes=attrs,
                paged_size=page_size,
                paged_cookie=cookie
            )
            results.extend(self.connection.entries)
            self.logger.info(f'Results on page {page}: {len(self.connection.entries)} total: {len(results)}')
            self.logger.debug(f'LDAP Search Results: {self.connection.response}')
            cookie = self.connection.result['controls']['1.2.840.113556.1.4.319']['value']['cookie']
            if cookie:
                page += 1
            else:
                next_page = False

        return [LdapUser(entry) for entry in results]
