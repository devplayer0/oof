#!/usr/bin/env python
import time
import sys
import os
import signal
import argparse
from threading import Thread
import subprocess

import yaml

class colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
class ColoredProcessPipe(Thread):
    def __init__(self, proc, name, color):
        Thread.__init__(self, daemon=False)
        self.proc = proc
        self.name = name
        self.color = color

    def run(self):
        while self.proc.poll() is None:
            try:
                line = self.proc.stdout.readline()
                print('[{}{}{}] {}'.format(self.color, self.name, colors.ENDC, line), end='')
            except KeyboardInterrupt:
                break

    def stop(self):
        try:
            self.proc.terminate()
        except KeyboardInterrupt:
            pass
        self.join()
        if self.proc.poll() is None:
            self.proc.wait(timeout=5)

def get_cargo_path(executable):
    return os.path.join(os.path.dirname(sys.argv[0]), 'target', 'debug', executable)

def start_node(name, is_controller):
    if is_controller:
        t = 'controller'
        color = colors.OKGREEN
    else:
        t = 'router'
        color = colors.OKBLUE

    print('[{}infra{}] starting {} \'{}\''.format(colors.FAIL, colors.ENDC, t, name))
    proc = subprocess.Popen(['ip', 'netns', 'exec', name, get_cargo_path('oof-' + t)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
    thread = ColoredProcessPipe(proc, name, color)
    thread.start()
    return thread

def main():
    parser = argparse.ArgumentParser(description='start oof routing infrastructure (controller and routers)')
    parser.add_argument('configuration', help='YAML file containing networks and network nodes')

    args = parser.parse_args()
    with open(args.configuration) as conf_file:
        config = yaml.load(conf_file)

    controllers = []
    routers = []
    for name, node in config['nodes'].items():
        if 'is_controller' in node and node['is_controller']:
            if 'is_router' in node and node['is_router']:
                raise Exception("controller {} can't also be a router!".format(name))

            controllers.append(name)
        if 'is_router' in node and node['is_router']:
            if 'is_controller' in node and node['is_controller']:
                raise Exception("router {} can't also be a controller!".format(name))

            routers.append(name)

    threads = []
    try:
        for name in controllers:
            threads.append(start_node(name, True))
        time.sleep(1)

        for name in routers:
            threads.append(start_node(name, False))
    except Exception as ex:
        for thread in reversed(threads):
            thread.stop()

        raise ex

    signal.sigwait([signal.SIGINT, signal.SIGTERM])
    print('shutting down...')
    for thread in reversed(threads):
        try:
            thread.stop()
        except Exception as ex:
            print(ex)

if __name__ == "__main__":
    main()
