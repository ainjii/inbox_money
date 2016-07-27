#!/usr/bin/python
''' Automatically respond to dev-tools threads that have not
yet received a response from our team. '''

import httplib2
import argparse
import base64
import email
import re

from apiclient.discovery import build
from oauth2client.client import flow_from_clientsecrets
from oauth2client.file import Storage
from oauth2client.tools import run_flow, argparser

CLIENT_SECRET_FILE = 'secrets.json'
SCOPE = 'https://www.googleapis.com/auth/gmail.modify'
STORED_CREDENTIALS = Storage('gmail.storage')

WATCHED_LABELS = ['Label_48']


def main():
    print "Starting ..."
    gmail = authenticate_and_build_gmail()
    msg_ids = get_all_msg_ids_with_label(gmail, WATCHED_LABELS)
    click_links(gmail, msg_ids)
    trash_msgs(gmail, msg_ids)
    print "Done!"


def authenticate_and_build_gmail():
    flags = parse_arguments()
    authd_http = retrieve_credentials_and_authorize(flags)
    gmail = build_gmail(authd_http)

    return gmail


def parse_arguments():
    ''' Parse the command-line arguments (e.g. --noauth_local_webserver) '''
    parser = argparse.ArgumentParser(parents=[argparser])
    flags = parser.parse_args()

    return flags


def retrieve_credentials_and_authorize(flags):
    print "Authenticating ..."

    # Start the OAuth flow to retrieve credentials
    flow = flow_from_clientsecrets(CLIENT_SECRET_FILE, scope=SCOPE)
    http = httplib2.Http()

    # Try to retrieve credentials from storage or run the flow to generate them
    credentials = STORED_CREDENTIALS.get()

    if credentials is None or credentials.invalid:
        credentials = run_flow(flow, STORED_CREDENTIALS, flags, http=http)

    # Authorize the httplib2.Http object with our credentials
    authorized = credentials.authorize(http)

    return authorized


def build_gmail(http):
    ''' Build the Gmail service from discovery. '''
    print "Building gmail ..."

    gmail_service = build('gmail', 'v1', http=http)

    return gmail_service.users()


def get_all_msg_ids_with_label(gmail, label):
    ''' Return all threads with the specified label. '''

    print "Getting list of message ids ..."

    msg_response = gmail.messages().list(userId='me', labelIds=WATCHED_LABELS).execute()
    msg_and_thread_ids = msg_response.get('messages', [])

    msg_ids = [msg['id'] for msg in msg_and_thread_ids]

    return msg_ids


def click_links(gmail, msg_ids):
    link_list = make_link_list(gmail, msg_ids)
    browser = build_browser()
    open_links(browser, link_list)


def make_link_list(gmail, msg_ids):
    print "Making list of links ..."

    links = set()

    for msg_id in msg_ids:
        message = gmail.messages().get(userId='me', id=msg_id,
                                       format='raw').execute()
        msg_str = base64.urlsafe_b64decode(message['raw'].encode('ASCII'))
        mime_msg = email.message_from_string(msg_str)
        msg_content = mime_msg.as_string()

        link_match = re.search(r'"http://www\.inbox(pays|dollars)\.com/(?!image)(.*?)"', msg_content)
        link = link_match.group(0)
        link = link.strip('"')
        links.add(link)

        return links


def build_browser():
    print "Building browser ..."

    import mechanize

    browser = mechanize.Browser()

    browser.set_handle_robots(False)
    browser.set_handle_redirect(True)
    browser.set_handle_referer(True)

    return browser


def open_links(browser, links):
    print "Opening links ..."

    for link in links:
        response = browser.open(link)


def trash_msgs(gmail, msg_ids):
    print "Deleting messages ..."

    for msg_id in msg_ids:
        gmail.messages().trash(userId='me', id=msg_id).execute()


if __name__ == '__main__':
    main()
