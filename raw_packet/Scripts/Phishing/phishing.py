#!/usr/bin/env python3
# -*- coding: utf-8 -*-

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
from raw_packet.Servers.Phishing.phishing import PhishingServer
from argparse import ArgumentParser, RawDescriptionHelpFormatter
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
__script_name__ = 'Phishing HTTP server (phishing)'
# endregion


# region Main function
def main() -> None:
    """
    Start Phishing HTTP server (phishing)
    :return: None
    """

    # region Init Raw-packet Base class
    base: Base = Base(admin_only=True, available_platforms=['Linux', 'Darwin', 'Windows'])
    # endregion

    # region Parse script arguments
    parser: ArgumentParser = ArgumentParser(description=base.get_banner(__script_name__),
                                            formatter_class=RawDescriptionHelpFormatter)
    parser.add_argument('-a', '--address', type=str, help='Set address for listen (default: "0.0.0.0")',
                        default='0.0.0.0')
    parser.add_argument('-p', '--port', type=int, help='Set port for listen (default: 80)', default=80)
    parser.add_argument('-s', '--site', type=str, help='Set site template "google" or "apple"', default='apple')
    parser.add_argument('-r', '--redirect', type=str, help='Set site domain for redirect', default='authentication.net')
    parser.add_argument('-q', '--quiet', action='store_true', help='Minimal output')
    args = parser.parse_args()
    # endregion

    # region Print banner
    if not args.quiet:
        base.print_banner(__script_name__)
    # endregion

    # region Start Phishing HTTP server
    try:
        phishing_server: PhishingServer = PhishingServer()
        phishing_server.start(address=args.address, port=args.port, site=args.site,
                              redirect=args.redirect, quiet=args.quiet)

    except KeyboardInterrupt:
        if not args.quiet:
            base.print_info('Exit')
        exit(0)

    except AssertionError as Error:
        if not args.quiet:
            base.print_error(Error.args[0])
        exit(1)
    # endregion

# endregion


# region Call Main function
if __name__ == "__main__":
    main()
# endregion
