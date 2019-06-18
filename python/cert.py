from socket import socket, AF_INET, SOCK_STREAM
from ssl import match_hostname, CertificateError, SSLError, cert_time_to_seconds, create_default_context
from urllib.parse import urlsplit
from urllib.request import urlopen, HTTPSHandler, build_opener, install_opener
from subprocess import Popen as sp_Popen, PIPE as SP_PIPE, DEVNULL as SP_DEVNULL, call as sp_call
from shlex import quote as shlex_quote
from re import compile as re_compile
from datetime import datetime, timedelta
from os.path import exists as os_path_exists, join as os_path_join
from os import remove as os_remove, getpid as os_getpid
from collections import OrderedDict
from json import dumps as json_dumps

CA_CERTS = '/home/digitalworks/alexa/docs/cacert.pem'
SQLITE_TEMP_DIR = '/home/digitalworks/alexa/docs/'


class SslCert(object):

    _separator = '_'                                                    # separator to rename duplicate key
    _url_sep = '_slash_'                                                # separator to replace / for crl filenames
    _warning_cert_timeout = 30                                          # max days validity to raise a warning

    openssl_cmd = '/usr/bin/openssl'
    echo_cmd = '/bin/echo'

    ssl_client_cmd = [openssl_cmd, 's_client', '-connect']              # openssl s_client command line
    ssl_x509_cmd = [openssl_cmd, 'x509']                                # openssl x509 command line

    keys = {'CN': 'commonName',
            'O':  'organizationName',
            'OU': 'organizationalUnitName',
            'L':  'localityName',
            'ST': 'stateOrProvinceName',
            'C':  'countryName'}

    design_keys = OrderedDict((('commonName',               'Common Name'),
                               ('organizationName',         'Organization Name'),
                               ('organizationalUnitName',   'Organizational Unit Name'),
                               ('localityName',             'Locality Name'),
                               ('stateOrProvinceName',      'State Or Province Name'),
                               ('countryName',              'Country Name')))

    err2ignore = ('unable to get certificate CRL', 'unable to verify the first certificate',
                  'unable to get local issuer certificate', 'certificate not trusted')

    def __init__(self):
        self.issuer = None                  # dict containing infos about issuer
        self.subject = None                 # dict containing infos about subject
        self.subjectAltName = None          # dict containing infos about sbject alt name (DNS)
        self.notAfter = None                # validity certificate deadline
        self.notBefore = None               # start certificate date
        self.serialNumber = None            # serial number in hexa
        self.version = None                 # version number
        self.OCSP = None                    # tuple of urls
        self.caIssuers = None               # tuple of urls
        self.crlDistributionPoints = None   # tuple of urls
        self.pem_cert = None                # cert public key in PEM format
        self.errors = None                  # list of error objects
        self.warnings = None                # list of warning objects

    def load_from_dict(self, dict_cert):
        """
        transform a dict to a structured object
        :param dict_cert: dict obtained from ssl library
        :return:
        """
        if 'issuer' in dict_cert:
            self.issuer = self._auth(dict_cert['issuer'])
        if 'subject' in dict_cert:
            self.subject = self._auth(dict_cert['subject'])
        if 'subjectAltName' in dict_cert:
            self.subjectAltName = self._auth_param(dict_cert['subjectAltName'])

        for key, value in dict_cert.items():
            if key not in ('issuer', 'subject', 'subjectAltName'):
                setattr(self, key, value)

        if self.notAfter is not None:
            self.notAfter = datetime.fromtimestamp(cert_time_to_seconds(self.notAfter))
        if self.notBefore is not None:
            self.notBefore = datetime.fromtimestamp(cert_time_to_seconds(self.notBefore))

    @classmethod
    def _auth(cls, tuples):
        """
        from tuples to dict
        :param tuples: tuples from ssl library like (((key, val), ), ((key, val), ), ...)
        :return: dict
        """
        _dict = dict()
        for tup in tuples:
            for key, val in cls._auth_param(tup).items():
                _dict[key] = val
        return _dict

    @classmethod
    def _auth_param(cls, tuples):
        """
        from tuples to dict
        :param tuples: tuples from ssl library like ((key, val), (key, val), ...)
        :return:
        """
        _dict = dict()
        for tup in tuples:
            if len(tup) == 2:
                key, val = tup
                while key in _dict:
                    if cls._separator in key:
                        _split = key.split(cls._separator)
                        key = cls._separator.join((_split[0], str(int(_split[1]) + 1)))
                    else:
                        key = '{}{}1'.format(key, cls._separator)
                _dict[key] = val
        return _dict

    def load_from_openssl(self, netloc, port):
        """
        load directly from openssl with bash commands
        :param netloc: target netloc
        :param port: target port
        :return:
        """
        self._set_error_message(netloc=netloc, port=port)
        self._set_subject(netloc=netloc, port=port)
        self._set_issuer(netloc=netloc, port=port)
        self._set_dates(netloc=netloc, port=port)
        self._set_serial(netloc=netloc, port=port)
        self._set_subject_alt_name(netloc=netloc, port=port)
        self._set_other_params(netloc=netloc, port=port)

    def add_error(self, err):
        """
        add an error object to self.errors
        :param err: error object
        :return:
        """
        if str(err) in self.err2ignore:
            return
        if self.errors is None:
            self.errors = list()
        self.errors.append(err)

    def add_warning(self, warn):
        """
        add a warn object to self.warnings
        :param warn: warning object
        :return:
        """
        if self.warnings is None:
            self.warnings = list()
        self.warnings.append(warn)

    def _set_error_message(self, netloc, port):
        """
        set basic error from openssl (certificate not valid)
        :param netloc: target netloc
        :param port: target port
        :return:
        """
        with sp_Popen([self.echo_cmd], stdout=SP_PIPE) as proc_echo:
            cmd = self.ssl_client_cmd[:]
            cmd.append('{}:{}'.format(shlex_quote(netloc), str(port)))
            cmd.append('-CAfile')
            cmd.append(CA_CERTS)
            with sp_Popen(cmd, stdin=proc_echo.stdout, stdout=SP_DEVNULL, stderr=SP_PIPE) as proc_ssl:
                data = proc_ssl.stderr.read()
                ddata = data.decode('utf-8')
                if ddata is not None:
                    reg = re_compile('error:num=[0-9]+:([^\n]+)')
                    for res in reg.finditer(ddata):
                        # expired checked at the end
                        # print('error msg: {}'.format(res.group(0)))
                        if 'expired' not in res.group(1):
                            self.add_error(err=NameError(res.group(1)))

    def _set_subject(self, netloc, port):
        """
        set subject dict from openssl
        :param netloc: target netloc
        :param port: target port
        :return:
        """
        with sp_Popen([self.echo_cmd], stdout=SP_PIPE) as proc_echo:
            cmd = self.ssl_client_cmd[:]
            cmd.append('{}:{}'.format(shlex_quote(netloc), str(port)))
            with sp_Popen(cmd, stdin=proc_echo.stdout, stdout=SP_PIPE, stderr=SP_DEVNULL) as proc_ssl:
                cmd = self.ssl_x509_cmd[:]
                cmd.append('-noout')
                cmd.append('-subject')
                with sp_Popen(cmd, stdin=proc_ssl.stdout, stdout=SP_PIPE, stderr=SP_DEVNULL) as proc_x509:
                    data = proc_x509.stdout.read()
                    ddata = data.decode('utf-8')
                    if ddata is not None:
                        subject_dict = dict()
                        reg = re_compile('[A-Z]+=[^/\n]+')
                        for res in reg.finditer(ddata):
                            _split = res.group().split('=')
                            if str(_split[0]) in self.keys:
                                subject_dict[self.keys[str(_split[0])]] = _split[1]
                        self.subject = subject_dict

    def _set_issuer(self, netloc, port):
        """
        set issuer dict from openssl
        :param netloc: target netloc
        :param port: target port
        :return:
        """
        with sp_Popen([self.echo_cmd], stdout=SP_PIPE) as proc_echo:
            cmd = self.ssl_client_cmd[:]
            cmd.append('{}:{}'.format(shlex_quote(netloc), str(port)))
            with sp_Popen(cmd, stdin=proc_echo.stdout, stdout=SP_PIPE, stderr=SP_DEVNULL) as proc_ssl:
                cmd = self.ssl_x509_cmd[:]
                cmd.append('-noout')
                cmd.append('-issuer')
                with sp_Popen(cmd, stdin=proc_ssl.stdout, stdout=SP_PIPE, stderr=SP_DEVNULL) as proc_x509:
                    data = proc_x509.stdout.read()
                    ddata = data.decode('utf-8')
                    if ddata is not None:
                        issuer_dict = dict()
                        reg = re_compile('[A-Z]+=[^/\n]+')
                        for res in reg.finditer(ddata):
                            _split = res.group().split('=')
                            if str(_split[0]) in self.keys:
                                issuer_dict[self.keys[str(_split[0])]] = _split[1]
                        self.issuer = issuer_dict

    def _set_dates(self, netloc, port):
        """
        set dates from openssl (notAfter and not Before)
        :param netloc: target netloc
        :param port: target port
        :return:
        """
        with sp_Popen([self.echo_cmd], stdout=SP_PIPE) as proc_echo:
            cmd = self.ssl_client_cmd[:]
            cmd.append('{}:{}'.format(shlex_quote(netloc), str(port)))
            with sp_Popen(cmd, stdin=proc_echo.stdout, stdout=SP_PIPE, stderr=SP_DEVNULL) as proc_ssl:
                cmd = self.ssl_x509_cmd[:]
                cmd.append('-noout')
                cmd.append('-dates')
                with sp_Popen(cmd, stdin=proc_ssl.stdout, stdout=SP_PIPE, stderr=SP_DEVNULL) as proc_x509:
                    data = proc_x509.stdout.read()
                    ddata = data.decode('utf-8')
                    if ddata is not None:
                        reg = re_compile('notBefore=([^\n]+)')
                        res = reg.search(ddata)
                        if res is not None:
                            self.notBefore = datetime.fromtimestamp(cert_time_to_seconds(res.group(1)))
                        reg = re_compile('notAfter=([^\n]+)')
                        res = reg.search(ddata)
                        if res is not None:
                            self.notAfter = datetime.fromtimestamp(cert_time_to_seconds(res.group(1)))

    def _set_serial(self, netloc, port):
        """
        set serial from openssl
        :param netloc: target netloc
        :param port: target port
        :return:
        """
        with sp_Popen([self.echo_cmd], stdout=SP_PIPE) as proc_echo:
            cmd = self.ssl_client_cmd[:]
            cmd.append('{}:{}'.format(shlex_quote(netloc), str(port)))
            with sp_Popen(cmd, stdin=proc_echo.stdout, stdout=SP_PIPE, stderr=SP_DEVNULL) as proc_ssl:
                cmd = self.ssl_x509_cmd[:]
                cmd.append('-noout')
                cmd.append('-serial')
                with sp_Popen(cmd, stdin=proc_ssl.stdout, stdout=SP_PIPE, stderr=SP_DEVNULL) as proc_x509:
                    data = proc_x509.stdout.read()
                    ddata = data.decode('utf-8')
                    if ddata is not None:
                        reg = re_compile('serial=([^\n]+)')
                        res = reg.search(ddata)
                        if res is not None:
                            self.serialNumber = res.group(1)

    def _set_subject_alt_name(self, netloc, port):
        """
        set subject alt name dict from openssl (authorized DNS)
        :param netloc: target netloc
        :param port: target port
        :return:
        """
        with sp_Popen([self.echo_cmd], stdout=SP_PIPE) as proc_echo:
            cmd = self.ssl_client_cmd[:]
            cmd.append('{}:{}'.format(shlex_quote(netloc), str(port)))
            with sp_Popen(cmd, stdin=proc_echo.stdout, stdout=SP_PIPE, stderr=SP_DEVNULL) as proc_ssl:
                cmd = self.ssl_x509_cmd[:]
                cmd.append('-noout')
                cmd.append('-text')
                with sp_Popen(cmd, stdin=proc_ssl.stdout, stdout=SP_PIPE, stderr=SP_DEVNULL) as proc_x509:
                    data = proc_x509.stdout.read()
                    ddata = data.decode('utf-8')
                    if ddata is not None:
                        san_dict = dict()
                        reg = re_compile('DNS:[^,\n]+')
                        idx = 0
                        for res in reg.finditer(ddata):
                            if idx > 0:
                                key = 'DNS{}{}'.format(self._separator, str(idx))
                            else:
                                key = 'DNS'
                            san_dict[key] = res.group().split(':')[1]
                            idx += 1
                        self.subjectAltName = san_dict

    def _set_other_params(self, netloc, port):
        """
        set other params from openssl (OCSP, CRL, caIssuers)
        :param netloc: target netloc
        :param port: target port
        :return:
        """
        with sp_Popen([self.echo_cmd], stdout=SP_PIPE) as proc_echo:
            cmd = self.ssl_client_cmd[:]
            cmd.append('{}:{}'.format(shlex_quote(netloc), str(port)))
            with sp_Popen(cmd, stdin=proc_echo.stdout, stdout=SP_PIPE, stderr=SP_DEVNULL) as proc_ssl:
                cmd = self.ssl_x509_cmd[:]
                cmd.append('-noout')
                cmd.append('-text')
                with sp_Popen(cmd, stdin=proc_ssl.stdout, stdout=SP_PIPE, stderr=SP_DEVNULL) as proc_x509:
                    data = proc_x509.stdout.read()
                    ddata = data.decode('utf-8')
                    if ddata is not None:
                        reg = re_compile('Version: ([0-9]+)')
                        res = reg.search(ddata)
                        if res is not None:
                            self.version = int(res.group(1))
                        reg = re_compile('OCSP - URI:([^\n]+)')
                        res = reg.search(ddata)
                        if res is not None:
                            self.OCSP = res.group(1),
                        reg = re_compile('CA Issuers - URI:([^\n]+)')
                        res = reg.search(ddata)
                        if res is not None:
                            self.caIssuers = res.group(1),
                        reg = re_compile('CRL Distribution Points:([ \n]*Full Name:[ \n]*URI:[^\n]+)+')
                        res = reg.search(ddata)
                        if res is not None:
                            crls = list()
                            _str = res.group(0)
                            reg = re_compile('URI:([^\n]+)')
                            for res in reg.finditer(_str):
                                crls.append(res.group(1))
                            self.crlDistributionPoints = tuple(crls)

    def create_dict(self):
        """
        get dict from self object to check hostname with ssl library
        :return: dict
        """
        dict_cert = dict(self.__dict__)
        dict_cert['subject'] = self._invert_auth(dict_cert['subject'])
        dict_cert['issuer'] = self._invert_auth(dict_cert['issuer'])
        dict_cert['subjectAltName'] = self._invert_auth_params(dict_cert['subjectAltName'])
        del(dict_cert['errors'])
        del(dict_cert['warnings'])
        return dict_cert

    @classmethod
    def _invert_auth(cls, params):
        """
        get tuples from dict
        :param params: dict
        :return: tuple like (((key, val), ), ((key, val), ), ...)
        """
        tuples = list()
        for key, val in params.items():
            _dict = {key: val}
            tuples.append(cls._invert_auth_params(params=_dict))
        return tuple(tuples)

    @classmethod
    def _invert_auth_params(cls, params):
        """
        get tuples from dict
        :param params: dict
        :return: tuple like ((key, val), (key, val), ...)
        """
        tuples = list()
        for key, val in params.items():
            if cls._separator in key:
                key = key.split(cls._separator)[0]
            tuples.append((key, val))
        return tuple(tuples)

    def check_dates(self):
        """
        raise error if cert is expired or warning if cert will expire soon
        :return:
        """
        if self.notAfter is None:
            self.add_error(NameError('no expire date found in certificate'))
            return
        if self.notAfter < datetime.today():
            self.add_error(NameError('certificate is expired since {}'.
                                     format(self.notAfter.strftime('%Y-%m-%d %H-%M-%S'))))
        elif self.notAfter < datetime.today() + timedelta(self._warning_cert_timeout):
            self.add_warning(Warning('certificate will expire soon, on {}'.
                                     format(self.notAfter.strftime('%Y-%m-%d %H-%M-%S'))))

    def check_revocation(self, netloc, port):
        """
        check if one of the chain certs is revoked
        :param netloc: target netloc
        :param port: target port
        :return:
        """
        if self.crlDistributionPoints is not None and self.pem_cert is not None:
            pid = os_getpid()
            temp_cert_path = os_path_join(SQLITE_TEMP_DIR, 'temp_cert_{}.pem'.format(pid))
            try:
                temp_cert_file = open(temp_cert_path, 'w')          # file containing cert in PEM format
            except OSError:
                return None
            else:
                temp_cert_file.write(self.pem_cert)
                temp_cert_file.close()

            for crl_url in self.crlDistributionPoints:              # for each crl given
                _split = urlsplit(crl_url)
                der_path = os_path_join(SQLITE_TEMP_DIR, '{}{}'.format(_split.netloc,
                                                                       _split.path.replace('/', self._url_sep)))
                pem_path = '{}_{}.pem'.format(der_path, pid)

                if not os_path_exists(der_path):                    # create crl in DER format if does not exist
                    opener = build_opener(HTTPSHandler)
                    install_opener(opener)
                    try:
                        req = urlopen(url=crl_url)
                    except:
                        continue
                    data = req.read(10000000)
                    if data is None:
                        continue
                    try:
                        der_file = open(der_path, 'wb')
                    except OSError:
                        continue
                    else:
                        der_file.write(data)
                        der_file.close()

                try:                                                # PEM file which will contain crl + chain certs
                    pem_file = open(pem_path, 'w')
                except OSError:
                    continue
                else:
                    cmd = [self.openssl_cmd, 'crl', '-inform', 'DER', '-in', der_path, '-outform', 'PEM']
                    # print(' '.join(cmd))      # debug
                    sp_call(cmd, stdout=pem_file, stderr=SP_DEVNULL)

                    with sp_Popen([self.echo_cmd], stdout=SP_PIPE, stderr=SP_DEVNULL) as proc_echo:
                        cmd = [self.openssl_cmd, 's_client', '-connect', '{}:{}'.format(netloc, port), '-showcerts']
                        with sp_Popen(cmd, stdin=proc_echo.stdout, stdout=SP_PIPE, stderr=SP_DEVNULL) as proc_certs:
                            data = proc_certs.stdout.read()
                            ddata = data.decode('utf-8')
                            if ddata is not None:
                                reg = re_compile('-+BEGIN CERTIFICATE-+[^-]+-+END CERTIFICATE-+\n')
                                for res in reg.finditer(ddata):
                                    pem_file.write(res.group(0))
                    pem_file.close()

                    # finally verify if cert is revoked
                    cmd = [self.openssl_cmd, 'verify', '-crl_check', '-CAfile', pem_path, temp_cert_path]
                    # print(' '.join(cmd))      # debug
                    with sp_Popen(cmd, stdout=SP_PIPE, stderr=SP_DEVNULL) as proc_verify:
                        data = proc_verify.stdout.read()
                        ddata = data.decode('utf-8')
                        if ddata is not None:
                            reg = re_compile('lookup:([^\n]+)')
                            for res in reg.finditer(ddata):
                                if 'revoked' in res.group(1):
                                    self.add_error(NameError(res.group(1)))
                    os_remove(pem_path)
            os_remove(temp_cert_path)

    def set_pem_cert(self, netloc, port):
        """
        set pem cert from openssl
        :param netloc: target netloc
        :param port: target port
        :return:
        """
        with sp_Popen([self.echo_cmd], stdout=SP_PIPE) as proc_echo:
            cmd = self.ssl_client_cmd[:]
            cmd.append('{}:{}'.format(shlex_quote(netloc), str(port)))
            with sp_Popen(cmd, stdin=proc_echo.stdout, stdout=SP_PIPE, stderr=SP_DEVNULL) as proc_ssl:
                data = proc_ssl.stdout.read()
                ddata = data.decode('utf-8')
                if ddata is not None:
                    reg = re_compile('-+BEGIN CERTIFICATE-+[^-]+-+END CERTIFICATE-+\n')
                    res = reg.search(ddata)
                    if res is not None:
                        self.pem_cert = res.group(0)

    def design(self):
        if self.notBefore is not None:
            self.notBefore = self.notBefore.strftime('%Y-%m-%d %H-%M-%S')

        if self.notAfter is not None:
            self.notAfter = self.notAfter.strftime('%Y-%m-%d %H-%M-%S')

        if self.warnings is not None:
            _warnings = [str(_) for _ in self.warnings]
            self.warnings = _warnings

        if self.errors is not None:
            _errors = [str(_) for _ in self.errors]
            self.errors = _errors

        _ordered_dict = OrderedDict()
        if self.subject:
            for key, design_key in self.design_keys.items():
                if key in self.subject:
                    _ordered_dict[design_key] = self.subject[key]
            self.subject = _ordered_dict

        _ordered_dict = OrderedDict()
        if self.issuer:
            for key, design_key in self.design_keys.items():
                if key in self.issuer:
                    _ordered_dict[design_key] = self.issuer[key]
            self.issuer = _ordered_dict

        _ordered_dict = OrderedDict()
        if self.subjectAltName:
            if 'DNS' in self.subjectAltName:
                _ordered_dict['DNS'] = self.subjectAltName['DNS']
            idx = 1
            while True:
                if 'DNS_{}'.format(str(idx)) in self.subjectAltName:
                    _ordered_dict['DNS {}'.format(str(idx))] = self.subjectAltName['DNS_{}'.format(str(idx))]
                else:
                    break
                idx += 1
            self.subjectAltName = _ordered_dict


def cert_from_netloc(netloc, port=443, pem_cert=True, check_revoc=True, check_host=True):
    """

    :param netloc:
    :param port:
    :return:
    """
    ssl_cert = SslCert()
    dict_cert = None

    sock = socket(family=AF_INET, type=SOCK_STREAM)

    ssl_context = create_default_context(cafile=CA_CERTS)  # create context to bypass proxy
    ssl_context.check_hostname = False  # check hostname after
    ssl_sock = ssl_context.wrap_socket(sock=sock, server_hostname=netloc)  # get SSLSocket object
    ssl_sock.settimeout(20)  # set timeout

    try:
        ssl_sock.connect((netloc, port))  # connect with context
    except SSLError:
        ssl_cert.load_from_openssl(netloc=netloc, port=port)
        dict_cert = ssl_cert.create_dict()
    except OSError as err:
        ssl_cert.add_error(err=err)
        ssl_cert.design()
        sock.close()
        ssl_sock.close()
        return ssl_cert

    if dict_cert is None:
        try:
            dict_cert = ssl_sock.getpeercert()  # get certificate if possible
            ssl_cert.load_from_dict(dict_cert=dict_cert)
        except ValueError:
            ssl_cert.load_from_openssl(netloc=netloc, port=port)
            dict_cert = ssl_cert.create_dict()

    if check_host:
        try:
            match_hostname(cert=dict_cert, hostname=netloc)  # check hostname
        except CertificateError as err:
            ssl_cert.add_error(err=err)

    ssl_cert.check_dates()
    if pem_cert:
        ssl_cert.set_pem_cert(netloc=netloc, port=port)
    if check_revoc:
        ssl_cert.check_revocation(netloc=netloc, port=port)
    ssl_cert.design()
    sock.close()
    ssl_sock.close()
    return ssl_cert