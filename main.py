import argparse
import requests
import logging
from bs4 import BeautifulSoup
import sys
import re
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class VscanErrorAnalyzer:
    """
    Scans HTTP responses for common error codes and attempts to correlate them with potential security misconfigurations or vulnerabilities.
    """

    def __init__(self, url, user_agent=None, timeout=10, ignore_ssl_errors=False):
        """
        Initializes the VscanErrorAnalyzer.

        Args:
            url (str): The URL to scan.
            user_agent (str, optional): The User-Agent string to use for requests. Defaults to None.
            timeout (int, optional): The request timeout in seconds. Defaults to 10.
            ignore_ssl_errors (bool, optional): Whether to ignore SSL certificate verification errors. Defaults to False.
        """
        if not isinstance(url, str):
            raise TypeError("URL must be a string.")
        if not url.startswith(('http://', 'https://')):
            raise ValueError("URL must start with http:// or https://")

        self.url = url
        self.user_agent = user_agent or "vscan-error-code-analyzer/1.0"
        self.timeout = timeout
        self.ignore_ssl_errors = ignore_ssl_errors
        self.headers = {'User-Agent': self.user_agent}
        self.error_patterns = {
            400: "Possible input validation issues. Check for malformed requests.",
            401: "Authentication required. Investigate authentication mechanisms and bypasses.",
            403: "Forbidden. Potential directory listing vulnerability or access control misconfiguration.",
            404: "Not Found. Check for information disclosure or path traversal vulnerabilities.",
            405: "Method Not Allowed. Investigate allowed methods and potential for exploitation.",
            500: "Internal Server Error. Check server logs for details. Potential for remote code execution or information disclosure.",
            503: "Service Unavailable. Check for denial-of-service vulnerabilities.",
        }

    def scan(self):
        """
        Performs the error code analysis scan.

        Returns:
            dict: A dictionary containing the scan results.
        """
        try:
            logging.info(f"Scanning URL: {self.url}")
            response = requests.get(self.url, headers=self.headers, timeout=self.timeout, verify=not self.ignore_ssl_errors)
            response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)

            status_code = response.status_code
            logging.info(f"Received status code: {status_code}")

            if status_code in self.error_patterns:
                logging.warning(f"Found error code: {status_code} - {self.error_patterns[status_code]}")
                return {
                    "url": self.url,
                    "status_code": status_code,
                    "description": self.error_patterns[status_code],
                    "vulnerable": True,
                    "response_headers": dict(response.headers)
                }
            else:
                logging.info("No common error codes found.")
                return {
                    "url": self.url,
                    "status_code": status_code,
                    "description": "No known vulnerability associated with this status code.",
                    "vulnerable": False,
                    "response_headers": dict(response.headers)
                }


        except requests.exceptions.RequestException as e:
            logging.error(f"Request error: {e}")
            return {
                "url": self.url,
                "status_code": None,
                "description": f"Request error: {e}",
                "vulnerable": False,
                "response_headers": {}
            }
        except Exception as e:
            logging.error(f"An unexpected error occurred: {e}")
            return {
                "url": self.url,
                "status_code": None,
                "description": f"An unexpected error occurred: {e}",
                "vulnerable": False,
                "response_headers": {}
            }

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        argparse.ArgumentParser: The configured argument parser.
    """
    parser = argparse.ArgumentParser(description="Scans HTTP responses for common error codes and potential vulnerabilities.")
    parser.add_argument("url", help="The URL to scan.")
    parser.add_argument("-u", "--user-agent", help="The User-Agent string to use.", default="vscan-error-code-analyzer/1.0")
    parser.add_argument("-t", "--timeout", type=int, help="The request timeout in seconds.", default=10)
    parser.add_argument("--ignore-ssl", action="store_true", help="Ignore SSL certificate verification errors.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging.")
    return parser


def main():
    """
    The main function of the script.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)  # Set logging level to DEBUG for verbose output

    try:
        analyzer = VscanErrorAnalyzer(args.url, args.user_agent, args.timeout, args.ignore_ssl)
        result = analyzer.scan()

        if result:
            print(f"URL: {result['url']}")
            print(f"Status Code: {result['status_code']}")
            print(f"Description: {result['description']}")
            print(f"Vulnerable: {result['vulnerable']}")
            print("Response Headers:")
            for key, value in result['response_headers'].items():
                print(f"  {key}: {value}")

        else:
            print("No results found.")

    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except TypeError as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    # Usage examples:
    # python main.py https://example.com
    # python main.py https://example.com -u "MyCustomAgent"
    # python main.py https://example.com -t 5
    # python main.py https://example.com --ignore-ssl
    # python main.py https://example.com -v
    main()