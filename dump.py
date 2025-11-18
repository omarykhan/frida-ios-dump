#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Author : AloneMonkey
# blog: www.alonemonkey.com


# Fork by omarykhan


from __future__ import print_function
from __future__ import unicode_literals
import sys
import codecs
import frida
import threading
import os
import shutil
import argparse
import tempfile
import subprocess
import re
import paramiko
from scp import SCPClient
from tqdm import tqdm
import traceback
import time

import select


try:
    import SocketServer
except ImportError:
    import socketserver as SocketServer


IS_PY2 = sys.version_info[0] < 3
if IS_PY2:
    reload(sys)
    sys.setdefaultencoding('utf8')

script_dir = os.path.dirname(os.path.realpath(__file__))

DUMP_JS = os.path.join(script_dir, 'dump.js')

TEMP_DIR = tempfile.gettempdir()
PAYLOAD_DIR = 'Payload'
PAYLOAD_PATH = os.path.join(TEMP_DIR, PAYLOAD_DIR)
file_dict = {}

finished = threading.Event()


exitLock = threading.Lock()

exitFlag = False

g_verbose = True


class ForwardServer(SocketServer.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


class Handler(SocketServer.BaseRequestHandler):
    def handle(self):
        try:
            chan = self.ssh_transport.open_channel(
                "direct-tcpip",
                (self.chain_host, self.chain_port),
                self.request.getpeername(),
            )
        except Exception as e:
            verbose(
                "Incoming request to %s:%d failed: %s"
                % (self.chain_host, self.chain_port, repr(e))
            )
            return
        if chan is None:
            verbose(
                "Incoming request to %s:%d was rejected by the SSH server."
                % (self.chain_host, self.chain_port)
            )
            return

        verbose(
            "Connected!  Tunnel open %r -> %r -> %r"
            % (
                self.request.getpeername(),
                chan.getpeername(),
                (self.chain_host, self.chain_port),
            )
        )
        while True:
            r, w, x = select.select([self.request, chan], [], [])
            if self.request in r:
                data = self.request.recv(1024)
                if len(data) == 0:
                    break
                chan.send(data)
            if chan in r:
                data = chan.recv(1024)
                if len(data) == 0:
                    break
                self.request.send(data)

        peername = self.request.getpeername()
        chan.close()
        self.request.close()
        verbose("Tunnel closed from %r" % (peername,))


def forward_tunnel(local_host, local_port, remote_host, remote_port, transport):
    # this is a little convoluted, but lets me configure things for the Handler
    # object.  (SocketServer doesn't give Handlers any way to access the outer
    # server normally.)
    class SubHander(Handler):
        chain_host = remote_host
        chain_port = remote_port
        ssh_transport = transport

    global exitLock

    global exitFlag

    forwardServer = ForwardServer((local_host, local_port), SubHander)

    forwardServer.timeout = 10

    while True:

        forwardServer.handle_request()

        exitLock.acquire()

        if True == exitFlag:

            break

        exitLock.release()

    exitLock.release()


def verbose(s):
    if g_verbose:
        print(s)


def get_ssh_iphone(fridaSocket):

    device_manager = frida.get_device_manager()

    changed = threading.Event()

    def on_changed():
        changed.set()

    device_manager.on('changed', on_changed)

    device = device_manager.add_remote_device(fridaSocket)

    device_manager.off('changed', on_changed)

    return device


def generate_ipa(path, display_name):
    ipa_filename = display_name + '.ipa'

    print('Generating "{}"'.format(ipa_filename))
    try:
        app_name = file_dict['app']

        for key, value in file_dict.items():
            from_dir = os.path.join(path, key)
            to_dir = os.path.join(path, app_name, value)
            if key != 'app':
                shutil.move(from_dir, to_dir)

        target_dir = './' + PAYLOAD_DIR
        zip_args = ('zip', '-qr', os.path.join(os.getcwd(),
                    ipa_filename), target_dir)
        subprocess.check_call(zip_args, cwd=TEMP_DIR)
        shutil.rmtree(PAYLOAD_PATH)
    except Exception as e:
        print(e)
        finished.set()


def on_message(message, data):
    t = tqdm(unit='B', unit_scale=True, unit_divisor=1024, miniters=1)
    last_sent = [0]

    def progress(filename, size, sent):
        baseName = os.path.basename(filename)
        if IS_PY2 or isinstance(baseName, bytes):
            t.desc = baseName.decode("utf-8")
        else:
            t.desc = baseName
        t.total = size
        t.update(sent - last_sent[0])
        last_sent[0] = 0 if size == sent else sent

    if 'payload' in message:
        payload = message['payload']
        if 'dump' in payload:
            origin_path = payload['path']
            dump_path = payload['dump']

            scp_from = dump_path
            scp_to = PAYLOAD_PATH + '/'

            with SCPClient(ssh.get_transport(), progress=progress, socket_timeout=60) as scp:
                scp.get(scp_from, scp_to)

            chmod_dir = os.path.join(PAYLOAD_PATH, os.path.basename(dump_path))
            chmod_args = ('chmod', '655', chmod_dir)
            try:
                subprocess.check_call(chmod_args)
            except subprocess.CalledProcessError as err:
                print(err)

            index = origin_path.find('.app/')
            file_dict[os.path.basename(dump_path)] = origin_path[index + 5:]

        if 'app' in payload:
            app_path = payload['app']

            scp_from = app_path
            scp_to = PAYLOAD_PATH + '/'
            with SCPClient(ssh.get_transport(), progress=progress, socket_timeout=60) as scp:
                scp.get(scp_from, scp_to, recursive=True)

            chmod_dir = os.path.join(PAYLOAD_PATH, os.path.basename(app_path))
            chmod_args = ('chmod', '755', chmod_dir)
            try:
                subprocess.check_call(chmod_args)
            except subprocess.CalledProcessError as err:
                print(err)

            file_dict['app'] = os.path.basename(app_path)

        if 'done' in payload:
            finished.set()
    t.close()


def compare_applications(a, b):
    a_is_running = a.pid != 0
    b_is_running = b.pid != 0
    if a_is_running == b_is_running:
        if a.name > b.name:
            return 1
        elif a.name < b.name:
            return -1
        else:
            return 0
    elif a_is_running:
        return -1
    else:
        return 1


def cmp_to_key(mycmp):
    """Convert a cmp= function into a key= function"""

    class K:
        def __init__(self, obj):
            self.obj = obj

        def __lt__(self, other):
            return mycmp(self.obj, other.obj) < 0

        def __gt__(self, other):
            return mycmp(self.obj, other.obj) > 0

        def __eq__(self, other):
            return mycmp(self.obj, other.obj) == 0

        def __le__(self, other):
            return mycmp(self.obj, other.obj) <= 0

        def __ge__(self, other):
            return mycmp(self.obj, other.obj) >= 0

        def __ne__(self, other):
            return mycmp(self.obj, other.obj) != 0

    return K


def get_applications(device):
    try:
        applications = device.enumerate_applications()
    except Exception as e:
        sys.exit('Failed to enumerate applications: %s' % e)

    return applications


def list_applications(device):
    applications = get_applications(device)

    if len(applications) > 0:
        pid_column_width = max(
            map(lambda app: len('{}'.format(app.pid)), applications))
        name_column_width = max(map(lambda app: len(app.name), applications))
        identifier_column_width = max(
            map(lambda app: len(app.identifier), applications))
    else:
        pid_column_width = 0
        name_column_width = 0
        identifier_column_width = 0

    header_format = '%' + str(pid_column_width) + 's  ' + '%-' + str(name_column_width) + 's  ' + '%-' + str(
        identifier_column_width) + 's'
    print(header_format % ('PID', 'Name', 'Identifier'))
    print('%s  %s  %s' % (pid_column_width * '-',
          name_column_width * '-', identifier_column_width * '-'))
    line_format = '%' + str(pid_column_width) + 's  ' + '%-' + str(name_column_width) + 's  ' + '%-' + str(
        identifier_column_width) + 's'
    for application in sorted(applications, key=cmp_to_key(compare_applications)):
        if application.pid == 0:
            print(line_format % ('-', application.name, application.identifier))
        else:
            print(line_format %
                  (application.pid, application.name, application.identifier))


def load_js_file(session, filename):
    source = ''
    with codecs.open(filename, 'r', 'utf-8') as f:
        source = source + f.read()
    script = session.create_script(source)
    script.on('message', on_message)
    script.load()

    return script


def create_dir(path):
    path = path.strip()
    path = path.rstrip('\\')
    if os.path.exists(path):
        shutil.rmtree(path)
    try:
        os.makedirs(path)
    except os.error as err:
        print(err)


def open_target_app(device, name_or_bundleid):
    print('Start the target app {}'.format(name_or_bundleid))

    pid = ''
    session = None
    display_name = ''
    bundle_identifier = ''
    for application in get_applications(device):
        if name_or_bundleid == application.identifier or name_or_bundleid == application.name:
            pid = application.pid
            display_name = application.name
            bundle_identifier = application.identifier

    try:
        pid = device.spawn([bundle_identifier])
        session = device.attach(pid)
        device.resume(pid)
    except Exception as e:
        print(e)

    return session, display_name, bundle_identifier


def start_dump(session, ipa_name):
    print('Dumping {} to {}'.format(display_name, TEMP_DIR))

    script = load_js_file(session, DUMP_JS)
    script.post('dump')
    finished.wait()

    generate_ipa(PAYLOAD_PATH, ipa_name)

    if session:
        session.detach()


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="frida-ios-dump (by AloneMonkey v2.0, forked by omarykhan)",
    )

    parser.add_argument(
        "-A",
        "--frida-host",
        dest="fridaHost",
        help="Specify Frida listening address",
        required=False,
        default="127.0.0.1",
        type=str,
    )

    parser.add_argument(
        "-L",
        "--frida-port",
        dest="fridaPort",
        help="Specify Frida listening port",
        required=False,
        default=27042,
        type=int,
    )

    parser.add_argument(
        "-a",
        "--lhost",
        help="Specify forwarded address",
        required=False,
        default="127.0.0.1",
        type=str,
    )

    parser.add_argument(
        "-f",
        "--lport",
        help="Specify forwarded port",
        required=False,
        default=27042,
        type=int,
    )

    parser.add_argument(
        "-l",
        "--list",
        dest="list_applications",
        action="store_true",
        help="List the installed apps",
        required=False,
    )

    parser.add_argument(
        "-o",
        "--output",
        dest="output_ipa",
        help="Specify name of the decrypted IPA",
        required=False,
    )

    parser.add_argument(
        "-H",
        "--host",
        dest="ssh_host",
        help="Specify SSH hostname",
        required=True,
        type=str,
    )

    parser.add_argument(
        "-p",
        "--port",
        dest="ssh_port",
        help="Specify SSH port",
        required=False,
        default=22,
        type=int,
    )

    parser.add_argument(
        "-u",
        "--user",
        dest="ssh_user",
        help="Specify SSH username (must be root)",
        required=False,
        default="root",
        type=str,
    )

    parser.add_argument(
        "-P",
        "--password",
        dest="ssh_password",
        help="Specify SSH password",
        required=False,
    )

    parser.add_argument(
        "-K",
        "--key_filename",
        dest="ssh_key_filename",
        help="Specify SSH private key file path",
        required=False,
    )

    parser.add_argument(
        "target",
        nargs="?",
        help="Bundle identifier or display name of the target app",
    )

    args = parser.parse_args()

    exit_code = 0
    ssh = None

    Password = None

    KeyFileName = None

    forwardThread = None

    if not len(sys.argv[1:]):
        parser.print_help()
        sys.exit(exit_code)

    try:

        forwardedSocket = f"{args.lhost}:{args.lport}"

        # update ssh args

        Host = args.ssh_host

        Port = args.ssh_port

        User = args.ssh_user

        if args.ssh_password:
            Password = args.ssh_password
        if args.ssh_key_filename:
            KeyFileName = args.ssh_key_filename

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(Host, port=Port, username=User,
                    password=Password, key_filename=KeyFileName)

        print ("hide jailbreak in dopamine")
        time.sleep(10)

        forwardThread = threading.Thread(target=forward_tunnel, args=(
            args.lhost, args.lport, args.fridaHost, args.fridaPort, ssh.get_transport(),))

        forwardThread.start()

        device = get_ssh_iphone(forwardedSocket)

        if args.list_applications:
            list_applications(device)
        else:
            name_or_bundleid = args.target
            output_ipa = args.output_ipa

            create_dir(PAYLOAD_PATH)
            (session, display_name, bundle_identifier) = open_target_app(
                device, name_or_bundleid)
            if output_ipa is None:
                output_ipa = display_name
            output_ipa = re.sub('\.ipa$', '', output_ipa)
            if session:
                print ("unhide jailbreak now")
                time.sleep(10)
                start_dump(session, output_ipa)

    except paramiko.ssh_exception.NoValidConnectionsError as e:
        print(e)
        print('Try specifying -H/--hostname and/or -p/--port')
        exit_code = 1
    except paramiko.AuthenticationException as e:
        print(e)
        print('Try specifying -u/--username and/or -P/--password')
        exit_code = 1
    except Exception as e:
        print('*** Caught exception: %s: %s' % (e.__class__, e))
        traceback.print_exc()
        exit_code = 1

    exitLock.acquire()

    exitFlag = True

    exitLock.release()

    if forwardThread:

        forwardThread.join()

    if ssh:
        ssh.close()

    if os.path.exists(PAYLOAD_PATH):
        shutil.rmtree(PAYLOAD_PATH)

    sys.exit(exit_code)
