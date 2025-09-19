#!/usr/bin/env python3
import argparse
import requests

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def parse_arguments():
    """Prepares the argument parser."""
    parser = argparse.ArgumentParser(
        description="Change SSR user password",
        conflict_handler="resolve")
    parser.add_argument('--hostname', default='localhost',
        help='Old password (if not provided "128Tadmin" will be used')
    parser.add_argument('--old-password', '-o', default='128Tadmin',
        help='Old password (if not provided "128Tadmin" will be used')
    parser.add_argument('--new-password', '-n', required=True,
        help='New password')
    parser.add_argument('--username', '-u', default='admin',
        help='User to be modified (default: admin)')
    parser.add_argument('--quiet', '-q', action='store_true',
        help='Do not show error messages')
    return parser.parse_args()


def main():
    args = parse_arguments()
    base_url = f'https://{args.hostname}'

    with requests.Session() as session:
        session.verify = False

        login_payload = {
            'username': args.username,
            'password': args.old_password,
        }
        login_url = base_url + '/api/v1/login'
        login_response = session.post(login_url, json=login_payload)

        if login_response.status_code == 200:
            session.headers['Authorization'] = f'Bearer {login_response.json()["token"]}'

            admin_patch_payload = {
                'password': args.new_password,
                'oldPassword': args.old_password,
            }
            patch_url = base_url + '/api/v1/user/admin'
            patch_response = session.patch(patch_url, json=admin_patch_payload)
        else:
            if not args.quiet:
                print('ERROR: old password is not correct.')


if __name__ == "__main__":
    main()
