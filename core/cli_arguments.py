import argparse

from core.constants import search_engines


def create_parser():
    engines = '\n\t'.join(search_engines)
    parser = argparse.ArgumentParser(description='Spaghetti - Web Application Security Scanner')
    parser.add_argument('-u', '--url', type=str,
                        help='Target URL (eg: http://example.com)')
    parser.add_argument('-e', '--engine', type=str,
                        help=f"Search engine. Default is all. Possible values: {engines}")
    parser.add_argument('-s', '--start', type=int, default=0,
                        help='Number of start page. Default 0')
    parser.add_argument('-l', '--limit', type=int, default=100,
                        help='Number of end page. Default 100')
    parser.add_argument('-sl', '--silent', default=False, action='store_true',
                        help="Run all without y/n questions")
    parser.add_argument('-v', '--virtual', default=False, action='store_true',
                        help="Use virtual host for search")
    parser.add_argument('-n', '--no-color', default=False, action='store_true',
                        help="Print results without color")
    return parser.parse_args()


cli_arguments = create_parser()
