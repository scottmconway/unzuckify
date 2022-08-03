#!/usr/bin/env python3

import argparse
import collections
import concurrent.futures
import datetime
import json
import logging
import random
import re

import esprima
import requests
import xdg
from typing import Dict


class Unzuckify:
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
        self.messenger_session.hooks["response"] = lambda r, *args, **kwargs: r.raise_for_status()

    def do_main(self, args):
        chat_page_data = None
        if not args.no_cookies and self.load_cookies():
            self.logger.debug(f"[cookie] READ {self.get_cookies_path()}")
            chat_page_data = self.get_chat_page_data()
            if not chat_page_data:
                self.logger.debug(f"[cookie] CLEAR due to failed auth")
                self.clear_cookies()

        if not chat_page_data:
            unauthenticated_page_data = self.get_unauthenticated_page_data()
            self.do_login(unauthenticated_page_data)
            self.save_cookies()
            self.logger.debug(f"[cookie] WRITE {self.get_cookies_path()}")
            chat_page_data = self.get_chat_page_data()
            assert chat_page_data, "auth failed"
        script_data = get_script_data(chat_page_data)
        if args.cmd == "inbox":
            inbox_js = self.get_inbox_js(chat_page_data, script_data)
            inbox_data = get_inbox_data(inbox_js)
            print(json.dumps(inbox_data))   # TODO should be logged

        elif args.cmd == "send":
            self.interact_with_thread(
                chat_page_data, script_data, args.thread, args.message
            )
        elif args.cmd == "read":
            for thread_id in args.thread:
                self.interact_with_thread(
                    chat_page_data, script_data, thread_id
                )
        else:
            assert False, args.cmd


    def get_unauthenticated_page_data(self):
        url = "https://www.messenger.com"
        self.logger.debug(f"[http] GET {url} (unauthenticated)")
        page = self.messenger_session.get(url, allow_redirects=False)
        page.raise_for_status()
        return {
            "datr": re.search(r'"_js_datr",\s*"([^"]+)"', page.text).group(1),
            "lsd": re.search(r'name="lsd"\s+value="([^"]+)"', page.text).group(1),
            "initial_request_id": re.search(
                r'name="initial_request_id"\s+value="([^"]+)"', page.text
            ).group(1),
        }

    def do_login(self, unauthenticated_page_data):
        url = "https://www.messenger.com/login/password/"
        self.logger.debug(f"[http] POST {url}")
        self.messenger_session.post(
            url,
            cookies={"datr": unauthenticated_page_data["datr"]},
            data={
                "lsd": unauthenticated_page_data["lsd"],
                "initial_request_id": unauthenticated_page_data["initial_request_id"],
                "email": self.config['auth_info']['email'],
                "pass": self.config['auth_info']['password'],
                "login": "1",
                "persistent": "1",
            },
            allow_redirects=False,
        )

    def get_chat_page_data(self):
        url = "https://www.messenger.com"
        self.logger.debug(f"[http] GET {url}")
        page = self.messenger_session.get(
            url,
            allow_redirects=True,
        )
        with open("/tmp/page.html", "w") as f:
            f.write(page.text)
        maybe_schema_match = re.search(
            r'"schemaVersion"\s*:\s*"([^"]+)"', page.text
        ) or re.search(r'\\"version\\":([0-9]{2,})', page.text)
        return {
            "device_id": re.search(
                r'"(?:deviceId|clientID)"\s*:\s*"([^"]+)"', page.text
            ).group(1),
            "maybe_schema_version": maybe_schema_match and maybe_schema_match.group(1),
            "dtsg": re.search(r'DTSG.{,20}"token":"([^"]+)"', page.text).group(1),
            "scripts": sorted(
                set(re.findall(r'"([^"]+rsrc\.php/[^"]+\.js[^"]+)"', page.text))
            ),
        }

    def interact_with_thread(
        self,
        chat_page_data,
        script_data,
        thread_id,
        message=None,
    ):
        schema_version = (
            chat_page_data["maybe_schema_version"] or script_data["maybe_schema_version"]
        )
        url = "https://www.messenger.com/api/graphql/"
        self.logger.debug(f"[http] POST {url}")

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
        self.messenger_session.post(
            url,
            data={
                "doc_id": script_data["query_id"],
                "fb_dtsg": chat_page_data["dtsg"],
                "variables": json.dumps(
                    {
                        "deviceId": chat_page_data["device_id"],
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
    def get_inbox_js(self, chat_page_data, script_data):
        url = "https://www.messenger.com/api/graphql/"
        self.logger.debug(f"[http] POST {url}")
        schema_version = (
            chat_page_data["maybe_schema_version"] or script_data["maybe_schema_version"]
        )
        assert schema_version
        graph = self.messenger_session.post(
            url,
            data={
                "doc_id": script_data["query_id"],
                "fb_dtsg": chat_page_data["dtsg"],
                "variables": json.dumps(
                    {
                        "deviceId": chat_page_data["device_id"],
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
        return graph.json()["data"]["viewer"]["lightspeed_web_request"]["payload"]

    def load_cookies(self):
        self.messenger_session.cookies.clear()
        try:
            with open(self.get_cookies_path()) as f:
                cookies = json.load(f).get(self.config['auth_info']['email'])
        except FileNotFoundError:
            return False
        except json.JSONDecodeError:
            return False
        if not cookies:
            return False
        self.messenger_session.cookies.update(cookies)
        return True

    def get_cookies_path(self):
        # TODO change this
        return xdg.xdg_cache_home() / "unzuckify" / "cookies.json"




    def save_cookies(self):
        # TODO simplify this
        path = self.get_cookies_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a+") as f:
            f.seek(0)
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                data = {}
            data[self.config['auth_info']['email']] = dict(self.messenger_session.cookies)
            f.seek(0)
            f.truncate()
            json.dump(data, f, indent=2)
            f.write("\n")


    def clear_cookies(self):
        # TODO simplify this
        self.messenger_session.cookies.clear()
        path = self.get_cookies_path()
        try:
            with open(path, "a+") as f:
                f.seek(0)
                try:
                    data = json.load(f)
                except json.JSONDecodeError:
                    data = {}
                try:
                    data.pop(self.config['auth_info']['email'])
                except KeyError:
                    pass
                if not data:
                    path.unlink()
                f.seek(0)
                f.truncate()
                json.dump(data, f, indent=2)
                f.write("\n")
        except FileNotFoundError:
            pass


def get_script_data(chat_page_data):
    # TODO simplify this
    def get(url):
        #logger.debug(f"[http] GET {url}")
        return requests.get(url)

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        scripts = executor.map(get, chat_page_data["scripts"])
    for script in scripts:
        script.raise_for_status()   # TODO should this be an unauthenticated call?

        if "LSPlatformGraphQLLightspeedRequestQuery" not in script.text:
            continue

        maybe_schema_match = re.search(
            r'__d\s*\(\s*"LSVersion".{,50}exports\s*=\s*"([0-9]+)"', script.text
        )

        return {
            "query_id": re.search(
                r'id:\s*"([0-9]+)".{,50}name:\s*"LSPlatformGraphQLLightspeedRequestQuery"',
                script.text,
            ).group(1),
            "maybe_schema_version": maybe_schema_match and maybe_schema_match.group(1),
        }
    assert False, "no script had LSPlatformGraphQLLightspeedRequestQuery"


def node_to_literal(node):
    if node.type == "Literal":
        return node.value
    if node.type == "ArrayExpression":
        return [node_to_literal(elt) for elt in node.elements]
    if node.type == "Identifier" and node.name == "U":
        return None
    if node.type == "UnaryExpression" and node.prefix and node.operator == "-":
        return -node_to_literal(node.argument)
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


def get_inbox_data(inbox_js):
    lightspeed_calls = collections.defaultdict(list)

    def delegate(node, meta):
        # TODO simplify this
        if not (args := read_lightspeed_call(node)):
            return
        (fn, *args) = args
        lightspeed_calls[fn].append(args)

    esprima.parseScript(inbox_js, delegate=delegate)

    users = {}
    conversations = {}

    for args in lightspeed_calls["deleteThenInsertThread"]:
        last_sent_ts, last_read_ts, last_msg, group_name, *rest = args
        thread_id, last_msg_author = [
            arg for arg in rest if isinstance(arg, list) and arg[0] > 0
        ][:2]
        conversations[convert_fbid(thread_id)] = {
            "unread": last_sent_ts != last_read_ts,
            "last_message": last_msg,
            "last_message_author": convert_fbid(last_msg_author),
            "group_name": group_name,
            "participants": [],
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
    assert len(my_user_ids) == 1
    (my_user_id,) = my_user_ids

    for conversation in conversations.values():
        conversation["participants"].remove(my_user_id)

    return {
        "users": users,
        "conversations": conversations,
    }





def parse_args():
    parser = argparse.ArgumentParser("unzuckify")
    parser.add_argument("--config", type=str, default="./config.json")
    parser.add_argument("-ll", "--log-level", type=int, default=None)
    parser.add_argument("-n", "--no-cookies", action="store_true")
    subparsers = parser.add_subparsers(dest="cmd")
    cmd_inbox = subparsers.add_parser("inbox")
    cmd_send = subparsers.add_parser("send")
    cmd_send.add_argument("-t", "--thread", required=True, type=int)
    cmd_send.add_argument("-m", "--message", required=True)
    cmd_read = subparsers.add_parser("read")
    cmd_read.add_argument("-t", "--thread", required=True, type=int, action="append")
    return parser.parse_args()

def main():
    args = parse_args()
    with open(args.config, "r") as f:
        config = json.load(f)

    # allow the user to override the log level if specified as an argument
    if args.log_level:
        config["logging"]["log_level"] = args.log_level

    zuck = Unzuckify(config)
    zuck.do_main(args)


if __name__ == "__main__":
    main()
