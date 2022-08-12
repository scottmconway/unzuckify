#!/usr/bin/env python3

import argparse
import datetime
import json
import logging
import os
import random
import re
from collections import defaultdict
from typing import Dict, Iterable, List, Optional, Set

import esprima
import requests

VALID_COMMANDS = ["inbox", "send", "read"]


class Unzuckify:
    ROOT_URL = "https://www.messenger.com"
    API_URL = f"{ROOT_URL}/api/graphql/"
    LOGIN_URL = f"{ROOT_URL}/login/password"

    DATR_REGEX = re.compile(r'"_js_datr",\s*"([^"]+)"')
    LSD_REGEX = re.compile(r'name="lsd"\s+value="([^"]+)"')
    INITIAL_REQUEST_ID_REGEX = re.compile(
        r'name="initial_request_id"\s+value="([^"]+)"'
    )
    SCHEMA_VERSION_REGEX = re.compile(r'"schemaVersion"\s*:\s*"([^"]+)"')
    VERSION_REGEX = re.compile(r'"version\":([0-9]{2,})')
    DEVICE_ID_REGEX = re.compile(r'"(?:deviceId|clientID|device_id)"\s*:\s*"([^\"]+)"')
    DTSG_REGEX = re.compile(r'DTSG.+"token":"([^"]+)"')
    SCRIPTS_REGEX = re.compile(r'"([^"]+rsrc\.php/[^"]+\.js[^"]+)"')
    LSVERSION_REGEX = re.compile(
        r'__d\s*\(\s*"LSVersion".{,50}exports\s*=\s*"([0-9]+)"'
    )
    QUERY_ID_REGEX = re.compile(
        r'id:\s*"([0-9]+)".{,50}name:\s*"LSPlatformGraphQLLightspeedRequestQuery"'
    )

    def __init__(self, config: Dict) -> None:
        self.config = config
        self.global_cookies = dict()

        # logging setup
        self.logger = logging.getLogger("unzuckify")
        logging.basicConfig()
        logging_conf = self.config.get("logging", dict())
        self.logger.setLevel(logging_conf["log_level"])

        if "gotify" in logging_conf:
            from gotify_handler import GotifyHandler

            self.logger.addHandler(GotifyHandler(**logging_conf["gotify"]))

        # messenger session setup
        self.messenger_session = requests.Session()
        self.messenger_session.hooks["response"] = messenger_err_hook

    def do_main(self, args):
        """
        (presently) main function to execute the user's will
        """

        chat_page_data = None
        if not args.no_cookies:
            self.logger.debug(f"[cookie] READ {self.config['cookie_file_path']}")
            try:
                self.load_cookies()
                chat_page_data = self.get_chat_page_data()

            # TODO log this if it's not just an expired session cookie
            except BaseException:
                pass

            if not chat_page_data:
                self.logger.debug(f"[cookie] CLEAR due to failed auth")
                self.clear_cookies()

        if not chat_page_data:
            self.login()
            self.logger.debug(f"[cookie] WRITE {self.config['cookie_file_path']}")
            self.save_cookies()
            chat_page_data = self.get_chat_page_data()

        if not chat_page_data:
            raise Exception("Authentication failure")

        if args.cmd == "inbox":
            inbox_js = self.get_inbox_js(**chat_page_data)
            conversations = get_inbox_data(inbox_js, args.unread_only)

            if not conversations:
                return

            # log a digest of all conversations in inbox
            if len(conversations) > 1:
                digest = f"{len(conversations)} thread updates:"
            else:
                digest = "1 thread update:"

            for thread_info in conversations.values():
                digest += (
                    f"\n{thread_info['group_name']} - {thread_info['last_message']}"
                )

            self.logger.info(digest)

            if args.mark_read:
                for thread_id, thread_info in conversations.items():
                    if thread_info["unread"]:
                        self.interact_with_thread(**chat_page_data, thread_id=thread_id)

        elif args.cmd == "read":
            for thread_id in args.thread:
                self.interact_with_thread(**chat_page_data, thread_id=thread_id)

        elif args.cmd == "send":
            self.interact_with_thread(
                **chat_page_data, thread_id=args.thread, message=args.message
            )

        else:
            raise Exception(f'Invalid command type - "{args.cmd}"')

    def login(self) -> None:
        """
        Logs into messenger

        :rtype: None
        """

        # grab necessary values from the root site before authenticating
        self.logger.debug(f"[http] GET {Unzuckify.ROOT_URL} (unauthenticated)")
        page = self.messenger_session.get(Unzuckify.ROOT_URL)
        datr = Unzuckify.DATR_REGEX.search(page.text).group(1)
        lsd = Unzuckify.LSD_REGEX.search(page.text).group(1)
        initial_request_id = Unzuckify.INITIAL_REQUEST_ID_REGEX.search(page.text).group(
            1
        )

        # log in
        self.logger.debug(f"[http] POST {Unzuckify.LOGIN_URL}")
        self.messenger_session.post(
            Unzuckify.LOGIN_URL,
            cookies={"datr": datr},
            data={
                "lsd": lsd,
                "initial_request_id": initial_request_id,
                "email": self.config["auth_info"]["email"],
                "pass": self.config["auth_info"]["password"],
                "login": "1",
                "persistent": "1",
            },
        )

        return

    def get_chat_page_data(self) -> Dict[str, str]:
        """
        Given a logged-in messenger session,
        returns all parameters needed for interacting with threads.

        Those values are as follows:
            device_id
            dtsg
            query_id
            schema_version

        :return: A dict containing the above parameters
        :rtype: Dict[str, str]
        """
        self.logger.debug(f"[http] GET {Unzuckify.ROOT_URL}")
        page = self.messenger_session.get(Unzuckify.ROOT_URL)
        schema_match = Unzuckify.SCHEMA_VERSION_REGEX.search(
            page.text
        ) or Unzuckify.VERSION_REGEX.search(page.text)

        script_urls = set(Unzuckify.SCRIPTS_REGEX.findall(page.text))

        return_dict = {
            "device_id": Unzuckify.DEVICE_ID_REGEX.search(page.text).group(1),
            "schema_version": schema_match
            and schema_match.group(1),  # TODO why the and?
            "dtsg": Unzuckify.DTSG_REGEX.search(page.text).group(1),
        }

        # TODO this may override `schema_version` with an invalid value?
        return_dict.update(get_script_data(script_urls))
        return return_dict

    def interact_with_thread(
        self,
        schema_version: str,
        query_id: str,
        dtsg: str,
        device_id: str,
        thread_id: int,
        message: Optional[str] = None,
    ) -> None:
        # TODO better docs
        """

        :param schema_version:
        :type schema_version: str
        :param query_id:
        :type query_id: str
        :param dtsg:
        :type dtsg: str
        :param device_id:
        :type device_id: str
        :param thread_id: The ID of the thread to interact with
        :type thread_id: int
        :param message: If specified, a message to send to the given thread
        :type message: Optional[str]
        :rtype: None
        """

        # TODO make more readable
        timestamp = int(datetime.datetime.now().timestamp() * 1000)
        epoch = timestamp << 22

        tasks = [
            {
                "label": "21",
                "payload": json.dumps(
                    {
                        "thread_id": thread_id,
                        "last_read_watermark_ts": timestamp,
                        "sync_group": 1,
                    }
                ),
                "queue_name": str(thread_id),
                "task_id": 1,
            }
        ]

        if message:
            otid = epoch + random.randrange(2**22)
            tasks.insert(
                0,
                {
                    "label": "46",
                    "payload": json.dumps(
                        {
                            "thread_id": thread_id,
                            "otid": str(otid),
                            "source": 0,
                            "send_type": 1,
                            "text": message,
                            "initiating_source": 1,
                        }
                    ),
                    "queue_name": str(thread_id),
                    "task_id": 0,
                },
            )
        self.logger.debug(f"[http] POST {Unzuckify.API_URL}")
        self.messenger_session.post(
            Unzuckify.API_URL,
            data={
                "doc_id": query_id,
                "fb_dtsg": dtsg,
                "variables": json.dumps(
                    {
                        "deviceId": device_id,
                        "requestId": 0,
                        "requestPayload": json.dumps(
                            {
                                "version_id": schema_version,
                                "epoch_id": epoch,
                                "tasks": tasks,
                            }
                        ),
                        "requestType": 3,
                    }
                ),
            },
        )

        return

    def get_inbox_js(
        self, schema_version: str, query_id: str, dtsg: str, device_id: str
    ) -> str:
        self.logger.debug(f"[http] POST {Unzuckify.API_URL}")
        graph = self.messenger_session.post(
            Unzuckify.API_URL,
            data={
                "doc_id": query_id,
                "fb_dtsg": dtsg,
                "variables": json.dumps(
                    {
                        "deviceId": device_id,
                        "requestId": 0,
                        "requestPayload": json.dumps(
                            {
                                "database": 1,
                                "version": schema_version,
                                "sync_params": json.dumps({}),
                            }
                        ),
                        "requestType": 1,
                    }
                ),
            },
        )

        res_js = graph.json()
        if "errors" in res_js:
            raise Exception(
                f"Exception retrieving inbox - {res_js['errors'][0]['message']}"
            )

        return res_js["data"]["viewer"]["lightspeed_web_request"]["payload"]

    def load_cookies(self) -> None:
        """
        Simple function to clear and re-load messenger cookies

        :rtype: None
        """

        self.messenger_session.cookies.clear()
        with open(self.config["cookie_file_path"]) as f:
            self.global_cookies = json.load(f)

        self.messenger_session.cookies.update(
            self.global_cookies.get(self.config["auth_info"]["email"])
        )
        return

    def save_cookies(self) -> None:
        """
        Simple function to save the messenger session's cookies to disk

        :rtype: None
        """

        path = self.config.get("cookie_file_path", "./cookies.json")
        os.makedirs(os.path.abspath(os.path.dirname(path)), exist_ok=True)
        self.global_cookies[self.config["auth_info"]["email"]] = dict(
            self.messenger_session.cookies
        )

        with open(path, "w") as f:
            json.dump(self.global_cookies, f)

    def clear_cookies(self) -> None:
        """
        Simple function to clear the messenger session's cookies and
        remove locally stored cookies

        :rtype: None
        """

        self.messenger_session.cookies.clear()

        path = self.config.get("cookie_file_path", "./cookies.json")
        if os.path.exists(path):
            with open(path, "r") as f:
                self.global_cookies = json.load(f)
                if self.config["auth_info"]["email"] in self.global_cookies:
                    del self.global_cookies[self.config["auth_info"]["email"]]

            with open(path, "w") as f:
                json.dump(self.global_cookies, f)


def messenger_err_hook(http_response: requests.Response, *args, **kwargs) -> None:
    http_response.raise_for_status()

    # TODO verify login errors, such as these
    # should only come from a response to a POST to the login endpoint
    """
    Please re-enter your password
    The password you’ve entered is incorrect.

    Incorrect Email
    The email you entered isn’t connected to an account. Find your account and log in.
    """
    return


def get_script_data(script_urls: Set[str]) -> Dict:
    """
    Given a list of script URLS,
    request each and extract "query_id" and "schema_version"
    from the first script that contains them.

    :param script_urls: A set of URLs
    :type script_urls: Set[str]
    :return: A dict containing "query_id" and "maybe_schema_version"
    :rtype: Dict
    """

    for script_url in script_urls:
        script_res = requests.get(script_url)
        script_res.raise_for_status()

        # TODO this should instead check for both regexes working
        if "LSPlatformGraphQLLightspeedRequestQuery" not in script_res.text:
            continue

        maybe_schema_match = Unzuckify.LSVERSION_REGEX.search(script_res.text)

        return {
            "query_id": Unzuckify.QUERY_ID_REGEX.search(script_res.text).group(1),
            "schema_version": maybe_schema_match and maybe_schema_match.group(1),
        }  # TODO why the and?

    raise Exception("LSPlatformGraphQLLightspeedRequestQuery not found")


def node_to_literal(node):
    if node.type == "Literal":
        return node.value

    elif node.type == "ArrayExpression":
        return [node_to_literal(elt) for elt in node.elements]

    elif node.type == "Identifier" and node.name == "U":
        return None

    elif node.type == "UnaryExpression" and node.prefix and node.operator == "-":
        return -node_to_literal(node.argument)

    else:
        return f"<{node.type}>"


def read_lightspeed_call(node):
    if not (
        node.type == "CallExpression"
        and node.callee.type == "MemberExpression"
        and node.callee.object.type == "Identifier"
        and node.callee.object.name == "LS"
        and node.callee.property.type == "Identifier"
        and node.callee.property.name == "sp"
    ):
        return None
    return [node_to_literal(node) for node in node.arguments]


def convert_fbid(l: List[int]) -> int:
    """
    Given an iterable of length two containing ints,
    return the "fbid" of the iterable.

    :param l:
    :type l: Iterable
    :return: The "fbid" of the iterable
    :rtype: int
    """

    return (2**32) * l[0] + l[1]


def get_inbox_data(inbox_js, unread_only: bool = False) -> Dict:
    my_user_id = None
    user_name_lookup = dict()
    conversations = dict()
    conversation_participants = defaultdict(set)

    lightspeed_calls = defaultdict(list)

    def delegate(node, meta):
        # TODO simplify this
        if not (args := read_lightspeed_call(node)):
            return

        (fn, *args) = args
        lightspeed_calls[fn].append(args)

    esprima.parseScript(inbox_js, delegate=delegate)

    # retrieve a list of users to map their IDs to their names
    for args in lightspeed_calls["verifyContactRowExists"]:
        user_id, _, _, name, *rest = args
        user_id = convert_fbid(user_id)
        _, _, _, is_me = [arg for arg in rest if isinstance(arg, bool)]

        if is_me:
            my_user_id = user_id

        user_name_lookup[user_id] = name

    assert my_user_id, "Current user's user ID was not found"

    # retrieve participant lists for all conversations
    for args in lightspeed_calls["addParticipantIdToGroupThread"]:
        thread_id, user_id, *rest = args
        user_id = convert_fbid(user_id)

        # skip adding "me" as a participant to threads
        if user_id == my_user_id:
            continue

        conversation_participants[convert_fbid(thread_id)].add(
            user_name_lookup[user_id]
        )

    # retrieve all conversations
    # TODO deal with edge-case of having your own "note-to-self" chat

    # For whatever reason, the websocket response likes to duplicate some responses
    for args in lightspeed_calls["deleteThenInsertThread"]:
        # TODO determine if this thing is a  message request
        # doesn't matter?
        (
            last_sent_ts,
            last_read_ts,
            last_msg,
            group_name,
            some_url_0,
            thing_0,
            int_array_0,
            thread_id,
            int_array_1,
            int_array_2,
            msg_status,
            some_url_1,
            int_array_3,
            int_array_4,
            int_array_5,
            int_array_6,
            bool_0,
            last_author,
            *rest,
        ) = args

        if unread_only and last_sent_ts == last_read_ts:
            continue

        else:
            thread_id = convert_fbid(thread_id)

            # skip empty conversations
            # TODO what about groups where everyone was removed except you?
            if not conversation_participants[thread_id]:
                continue

            # TODO figure out what kind of message this is
            # or rather, what zone it's in
            #
            # eg. normal  - "inbox"
            # msg request - "pending"
            if msg_status == "pending":
                is_msg_request = True
            else:
                is_msg_request = False

            # Set the "group name" to all participants if it's None
            if group_name is None:
                group_name = ", ".join(conversation_participants[thread_id])

            conversations[thread_id] = {
                "unread": last_sent_ts != last_read_ts,
                "last_message": last_msg,
                "last_message_author": user_name_lookup[convert_fbid(last_author)],
                "group_name": group_name,
                "is_message_request": is_msg_request,
                "participants": list(
                    conversation_participants[thread_id]
                ),  # for JSON serializability
            }

    return conversations


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser("unzuckify")
    parser.add_argument(
        "--config",
        type=str,
        default="./config.json",
        help="Path to config file - defaults to ./config.json",
    )
    parser.add_argument(
        "-ll",
        "--log-level",
        type=int,
        default=None,
        help="If specified, overrides the log_level parameter in the config file",
    )
    parser.add_argument(
        "-n",
        "--no-cookies",
        action="store_true",
        help="If set, ignore locally cached cookies",
    )
    subparsers = parser.add_subparsers(dest="cmd")
    cmd_inbox = subparsers.add_parser("inbox")
    cmd_inbox.add_argument(
        "-u",
        "--unread-only",
        action="store_true",
        help="If set, only return threads with unread messages",
    )
    cmd_inbox.add_argument(
        "--mark-read",
        action="store_true",
        help="If set, mark all currently unread threads in the inbox as read",
    )
    cmd_send = subparsers.add_parser("send")
    cmd_send.add_argument(
        "-t",
        "--thread",
        required=True,
        type=int,
        help="The ID of the thread in which to send a message",
    )
    cmd_send.add_argument(
        "-m", "--message", required=True, help="Content of the message to send"
    )
    cmd_read = subparsers.add_parser("read")
    cmd_read.add_argument(
        "-t",
        "--thread",
        required=True,
        type=int,
        action="append",
        help="The ID of the thread(s) in which to send a read receipt",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    with open(args.config, "r") as f:
        config = json.load(f)

    # allow the user to override the log level if specified as an argument
    if args.log_level:
        config["logging"]["log_level"] = args.log_level

    if args.cmd not in VALID_COMMANDS:
        raise Exception(f'Invalid command type - "{args.cmd}"')

    # set defaults for required config params if not present
    if "cookie_file_path" not in config:
        config["cookie_file_path"] = "./cookies.json"

    zuck = Unzuckify(config)
    try:
        zuck.do_main(args)
    except BaseException as be:
        zuck.logger.exception(
            f'Exception during execution "{type(be).__name__}" - {be}'
        )


if __name__ == "__main__":
    main()
