import argparse
import hashlib
import hmac
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import pprint
import os
import sys
import readchar
import signal
from enum import Enum
import subprocess
import threading
import time
from functools import partial


class Operation(Enum):
    RUN = 1
    HALT = 2
    RESTART = 3
    KILL = 4


thread_flag = threading.Condition()
actual_operation = Operation.HALT


def init_config(config_path):
    config = {}
    try:
        config_file = open(config_path, 'r')
        config = json.load(config_file)

        if not config:
            raise ValueError('Loading failed, resulting empty dict.')
    except BaseException as err:
        print(f"Was not able to load config: {err}, {type(err)}")
        quit()
    else:
        config_file.close()
    return config;


def signal_handler(signum, frame):
    global actual_operation
    global thread_flag

    print("\nSIGINT was recieved. What do you want to do?")
    print("0 - kill wrapper, 1 - restart program, 2 - kill program")
    print("Command: ", end="", flush=True)

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
        print("Operation was receieved, however does not match any avalible option.")
    thread_flag.notify_all()
    thread_flag.release()


class GitHubHandler(BaseHTTPRequestHandler):
    def __init__(self, config, *args, **kwargs):
        self.config = config
        super().__init__(*args, **kwargs)

    def _validate_signature(self, data):
        sha_name, signature = self.headers['X-Hub-Signature'].split('=')
        if sha_name != 'sha1':
            return False

        mac = hmac.new(str.encode(self.config.get("secret-key")), msg=data, digestmod=hashlib.sha1)
        return hmac.compare_digest(mac.hexdigest(), signature)

    def do_POST(self):
        data_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(data_length)

        if self.client_address[0] is None:
            self.send_response(401)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write("Invalid IP address.".encode(encoding='utf_8'))
            return

        if ("whitelist" in self.config and self.config.get("whitelist") is not None and len(
                self.config.get("whitelist")) != 0):
            actual_parts = self.client_address[0].split(".")
            if (len(actual_parts) == 4):
                for ip in self.config.get("whitelist"):
                    parts = ip.split(".")
                    if (len(parts) != 4):
                        continue
                    for part_index in range(len(parts)):
                        if parts[part_index] == "*" or actual_parts[part_index] == parts[part_index]:
                            continue
                        self.send_response(401)
                        self.send_header('Content-Type', 'application/json')
                        self.end_headers()
                        self.wfile.write("Used IP address is not in whitelist.".encode(encoding='utf_8'))
                        return
                print("IP address passed whitelist")

        if not self._validate_signature(post_data):
            self.send_response(401)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write("Invalid signature.".encode(encoding='utf_8'))
            return

        payload = json.loads(post_data.decode('utf-8'))
        self.handle_payload(payload)
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write("Wrapper successfully handled hot-swap.".encode(encoding='utf_8'))


class ListenerHandler(GitHubHandler):
    def handle_payload(self, json_payload):
        global actual_operation
        global thread_flag

        print("Pull was made on remote repository, starting update.")
        thread_flag.acquire()
        actual_operation = Operation.HALT
        thread_flag.notify_all()
        thread_flag.release()
        time.sleep(1)

        git_pull = subprocess.Popen("git pull".split(), preexec_fn=os.setpgrp)
        git_pull.wait()
        print("Successfully pulled latest version.")

        thread_flag.acquire()
        actual_operation = Operation.RESTART
        thread_flag.notify_all()
        thread_flag.release()
        print("Successfully made hot swap.")


class GitHub(threading.Thread):
    def __init__(self, config):
        threading.Thread.__init__(self)
        self.name = "GitHub-Handler"
        self.config = config
        self.is_starting = True

        try:
            if "secret-key" not in self.config:
                raise ValueError("Was not able to found secret-key in config")

            server_handler = partial(ListenerHandler, self.config)
            self.server = HTTPServer((self.config.get("ip-address"), int(self.config.get("port"))), server_handler)
        except BaseException as err:
            print(f"Was not able to start GitHub listener: {err}, {type(err)}")
            thread_flag.acquire()
            actual_operation = Operation.KILL
            thread_flag.notify_all()
            thread_flag.release()
            quit()

    def run(self):
        global actual_operation
        global thread_flag

        print("GitHub handler was successfully started.")
        if (self.is_starting):
            git_pull = subprocess.Popen("git pull".split(), preexec_fn=os.setpgrp)
            git_pull.wait()
            print("Successfully pulled latest version.")
            self.is_starting = False

            thread_flag.acquire()
            actual_operation = Operation.RESTART
            thread_flag.notify_all()
            thread_flag.release()
            time.sleep(1)

        self.server.serve_forever()

    def kill(self):
        self.server.shutdown()


class OurProgram(threading.Thread):
    def __init__(self, config):
        threading.Thread.__init__(self)
        self.name = "Program-Thread"
        self.config = config

        global actual_operation
        global thread_flag

        if not ("run-command" in self.config):
            print("Was not able to found key run-command.")
            thread_flag.acquire()
            actual_operation = Operation.KILL
            thread_flag.notify_all()
            thread_flag.release()
            quit()

        self.process = subprocess.Popen(self.config.get("run-command").split(), preexec_fn=os.setpgrp)

    def run(self):
        print("Wrapper successfull started program.")
        self.process.wait()
        print("Program thread died.")

    def kill(self):
        print("Wrapper successfully terminatet program.")
        self.process.send_signal(signal.SIGUSR1)
        self.process.kill()


class Wrapper(threading.Thread):
    def __init__(self, config, parent_thread):
        threading.Thread.__init__(self)
        self.name = "Wrapper"
        self.config = config
        self.parent_thread = parent_thread

    def run(self):
        global actual_operation
        global thread_flag

        thread = None
        print("Wrapper successfully started.")
        while (True):

            if (actual_operation == Operation.KILL):
                self.parent_thread.kill()
                thread.kill()
                break;

            if ((thread is None or not thread.is_alive()) and (
                    actual_operation == Operation.RUN or actual_operation == Operation.RESTART)):
                thread = OurProgram(config)
                thread.start()
            elif (thread is not None and thread.is_alive() and (
                    actual_operation == Operation.HALT or actual_operation == Operation.RESTART)):
                thread.kill()

            if (actual_operation == Operation.RESTART):
                thread_flag.acquire()
                actual_operation = Operation.RUN
                thread_flag.notify_all()
                thread_flag.release()

            time.sleep(0.2)
        print("Wrapper thread died.")


config = init_config("./config-sync.json")
print("Config was successfully loaded.")
signal.signal(signal.SIGINT, signal_handler)

actual_operation = Operation.HALT
github_thread = GitHub(config)
program_thread = Wrapper(config, github_thread)

program_thread.start()
github_thread.start()
program_thread.join()
github_thread.join()

print("All operations ended.")
