import hashlib
import hmac
import json
import os
import signal
import subprocess
import threading
import time
from enum import Enum
from functools import partial
from http.server import HTTPServer, BaseHTTPRequestHandler
import readchar


class Operation(Enum):
    RUN = 1
    HALT = 2
    RESTART = 3
    KILL = 4


thread_flag = threading.Condition()
actual_operation = Operation.HALT


def init_config(config_path):
    config_loc = {}
    try:
        config_file = open(config_path, 'r')
        config_loc = json.load(config_file)

        if not config_loc:
            raise ValueError("Loading failed, resulting in an empty dictionary.")
    except BaseException as err:
        print(f"[Wrapper] Was not able to load the config: {err}, {type(err)}")
        quit()
    else:
        config_file.close()
    return config_loc


def git_pull():
    git_proc = subprocess.Popen("git pull".split(), preexec_fn=os.setpgrp)
    git_proc.wait()
    print("[Wrapper] Successfully pulled the latest version.")


def signal_handler(signum, frame):
    global actual_operation
    global thread_flag

    print("\n[Wrapper] SIGINT was received, what do you want to do?")
    print("[Wrapper] 0 - kill wrapper, 1 - restart program, 2 - kill program")
    print("[Wrapper] Command: ", end="", flush=True)

    command = readchar.readchar()
    print("")

    thread_flag.acquire()
    if command == '0':
        print("Killing wrapper...")
        actual_operation = Operation.KILL
        quit()
    elif command == '1':
        actual_operation = Operation.RESTART
    elif command == '2':
        actual_operation = Operation.HALT
    else:
        print("[Wrapper] The command does not match any available option.")
    thread_flag.notify_all()
    thread_flag.release()


class GitHubHandler(BaseHTTPRequestHandler):
    def __init__(self, config_loc, *args, **kwargs):
        self.config = config_loc
        super().__init__(*args, **kwargs)

    def _validate_signature(self, data):
        sha_name, signature = self.headers['X-Hub-Signature'].split('=')
        if sha_name != 'sha1':
            return False

        mac_key = hmac.new(str.encode(self.config.get("secret-key")), msg=data, digestmod=hashlib.sha1)
        return hmac.compare_digest(mac_key.hexdigest(), signature)

    def _response_loc(self, code, message):
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(message.encode(encoding='utf_8'))

    def do_POST(self):
        post_data = self.rfile.read(int(self.headers['Content-Length']))
        if not self.client_address[0]:
            self._response_loc(401, "Invalid IP address.")
            return

        if "whitelist" in self.config and self.config.get("whitelist") and len(self.config.get("whitelist")) != 0:
            actual_parts = self.client_address[0].split(".")
            if len(actual_parts) == 4:
                for ip in self.config.get("whitelist"):
                    parts = ip.split(".")
                    if len(parts) != 4:
                        continue
                    for part_index in range(len(parts)):
                        if parts[part_index] == "*" or actual_parts[part_index] == parts[part_index]:
                            continue
                        self._response_loc(401, "The used IP address is not in the whitelist.")
                        return
                print("[Wrapper] The IP address passed the whitelist check.")

        if not self._validate_signature(post_data):
            self._response_loc(401, "Invalid signature.")
            return

        self.handle_payload(json.loads(post_data.decode('utf-8')))
        self._response_loc(200, "Wrapper successfully handled hot-swap.")


class ListenerHandler(GitHubHandler):
    def handle_payload(self, payload):
        global actual_operation
        global thread_flag

        print("[Wrapper] Pull was made on remote repository, starting update.")

        thread_flag.acquire()
        actual_operation = Operation.HALT
        thread_flag.notify_all()
        thread_flag.release()

        time.sleep(0.5)
        git_pull()

        thread_flag.acquire()
        actual_operation = Operation.RESTART
        thread_flag.notify_all()
        thread_flag.release()
        print("[Wrapper] Wrapper successfully made a hot-swap.")


class GitHub(threading.Thread):
    def __init__(self, config_loc):
        threading.Thread.__init__(self)
        self.name = "GitHub-Handler"
        self.config = config_loc
        self.is_starting = True

        global actual_operation
        global thread_flag

        try:
            if "secret-key" not in self.config:
                raise ValueError("Was not able to find the secret key in the config.")

            server_handler = partial(ListenerHandler, self.config)
            self.server = HTTPServer((self.config.get("ip-address"), int(self.config.get("port"))), server_handler)
        except BaseException as err:
            print(f"[Wrapper] Was not able to start a GitHub listener: {err}, {type(err)}")

            thread_flag.acquire()
            actual_operation = Operation.KILL
            thread_flag.notify_all()
            thread_flag.release()
            quit()

    def run(self):
        global actual_operation
        global thread_flag

        print("[Wrapper] GitHub handler was successfully started.")
        if self.is_starting:
            git_pull()

            thread_flag.acquire()
            actual_operation = Operation.RESTART
            thread_flag.notify_all()
            thread_flag.release()
            time.sleep(1)
        self.server.serve_forever()

    def kill(self):
        self.server.shutdown()


class OurProgram(threading.Thread):
    def __init__(self, config_loc):
        threading.Thread.__init__(self)
        self.name = "Program-Thread"
        self.config = config_loc

        global actual_operation
        global thread_flag

        if not ("run-command" in self.config):
            print("[Wrapper] Was not able to find the key run-command.")

            thread_flag.acquire()
            actual_operation = Operation.KILL
            thread_flag.notify_all()
            thread_flag.release()
            quit()

        self.process = subprocess.Popen(self.config.get("run-command").split(), preexec_fn=os.setpgrp)

    def run(self):
        print("[Wrapper] Wrapper successfully started the program.")
        self.process.wait()
        print("[Wrapper] The program thread died.")

    def kill(self):
        print("[Wrapper] Wrapper successfully terminated the program.")
        self.process.send_signal(signal.SIGUSR1)
        self.process.kill()


class Wrapper(threading.Thread):
    def __init__(self, config_loc, parent_thread):
        threading.Thread.__init__(self)
        self.name = "Wrapper"
        self.config = config_loc
        self.parent_thread = parent_thread

    def run(self):
        global actual_operation
        global thread_flag

        thread = None
        print("[Wrapper] Wrapper successfully started.")
        while True:
            if actual_operation == Operation.KILL:
                self.parent_thread.kill()
                thread.kill()
                break

            if not (thread and thread.is_alive()) and \
                    (actual_operation == Operation.RUN or actual_operation == Operation.RESTART):
                thread = OurProgram(self.config)
                thread.start()
            elif thread and thread.is_alive() and \
                    (actual_operation == Operation.HALT or actual_operation == Operation.RESTART):
                thread.kill()

            if actual_operation == Operation.RESTART:
                thread_flag.acquire()
                actual_operation = Operation.RUN
                thread_flag.notify_all()
                thread_flag.release()

            time.sleep(0.2)
        print("[Wrapper] The wrapper thread died.")


def main():
    config = init_config("./config-sync.json")
    print("[Wrapper] Config was successfully loaded.")
    signal.signal(signal.SIGINT, signal_handler)

    github_thread = GitHub(config)
    program_thread = Wrapper(config, github_thread)

    program_thread.start()
    github_thread.start()
    program_thread.join()
    github_thread.join()

    print("[Wrapper] All operations ended.")


main()
