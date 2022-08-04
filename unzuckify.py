#!/usr/bin/env python3

import argparse
import collections
import datetime
import json
import logging
import os
import random
import re
from typing import Dict, Optional, Set

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

            inbox_data = get_inbox_data(inbox_js)

            # inbox_data is a dict of users and conversations items
            # TODO first - do we want to change the return type?
            # second - how should we interpret this data?

            print(json.dumps(inbox_data))  # TODO should be logged
            # TODO further process this json object

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

    def get_chat_page_data(self) -> Dict:
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
            cookies = json.load(f).get(self.config["auth_info"]["email"])

        self.messenger_session.cookies.update(cookies)
        return

    def save_cookies(self) -> None:
        """
        Simple function to save the messenger session's cookies to disk

        :rtype: None
        """

        path = self.config["cookie_file_path"]
        os.makedirs(os.path.abspath(os.path.dirname(path)), exist_ok=True)
        cookie_dict = {
            self.config["auth_info"]["email"]: dict(self.messenger_session.cookies)
        }

        with open(path, "w") as f:
            json.dump(cookie_dict, f)

    def clear_cookies(self) -> None:
        """
        Simple function to clear the messenger session's cookies and
        remove locally stored cookies

        :rtype: None
        """

        self.messenger_session.cookies.clear()

        path = self.config["cookie_file_path"]
        if os.path.exists(path):
            os.remove(path)


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


def convert_fbid(l):
    return (2**32) * l[0] + l[1]


def get_inbox_data(inbox_js) -> Dict[str, Dict]:
    lightspeed_calls = collections.defaultdict(list)

    def delegate(node, meta):
        # TODO simplify this
        if not (args := read_lightspeed_call(node)):
            return

        (fn, *args) = args
        lightspeed_calls[fn].append(args)

    esprima.parseScript(inbox_js, delegate=delegate)

    users = dict()
    conversations = dict()

    for args in lightspeed_calls["deleteThenInsertThread"]:
        last_sent_ts, last_read_ts, last_msg, group_name, *rest = args
        thread_id, last_msg_author = [
            arg for arg in rest if isinstance(arg, list) and arg[0] > 0
        ][
            :2
        ]  # TODO what's with the [:2] at the end?
        conversations[convert_fbid(thread_id)] = {
            "unread": last_sent_ts != last_read_ts,
            "last_message": last_msg,
            "last_message_author": convert_fbid(last_msg_author),
            "group_name": group_name,
            "participants": list(),
        }

    for args in lightspeed_calls["addParticipantIdToGroupThread"]:
        thread_id, user_id, *rest = args
        conversations[convert_fbid(thread_id)]["participants"].append(
            convert_fbid(user_id)
        )

    for args in lightspeed_calls["verifyContactRowExists"]:
        user_id, _, _, name, *rest = args
        _, _, _, is_me = [arg for arg in rest if isinstance(arg, bool)]
        users[convert_fbid(user_id)] = {"name": name, "is_me": is_me}

    for user_id in users:
        if all(user_id in c["participants"] for c in conversations.values()):
            my_user_id = user_id
            break

    my_user_ids = [uid for uid in users if users[uid]["is_me"]]
    assert len(my_user_ids) == 1  # TODO handle exception
    (my_user_id,) = my_user_ids

    for conversation in conversations.values():
        conversation["participants"].remove(my_user_id)

    return {
        "users": users,
        "conversations": conversations,
    }


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
