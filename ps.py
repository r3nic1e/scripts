#!/usr/bin/env

from __future__ import print_function
import argparse
import psutil
import os
import signal
from datetime import datetime
import grp
import pwd
import inspect
import subprocess
import re

SIGNALS = sorted(list(k for v, k in reversed(sorted(signal.__dict__.items()))
                      if v.startswith('SIG') and not v.startswith('SIG_')))

UID_CACHE = {}
GID_CACHE = {}


def main():
    matcher = parse_args()

    if matcher.kill:
        process_kill(matcher)
    elif matcher.proc_exec:
        process_exec(matcher)
    else:
        print_processes_info(matcher)


def parse_human_time(string):
    regex = re.compile(r'((?P<days>\d+?)d)?((?P<hours>\d+?)h)?((?P<minutes>\d+?)m)?((?P<seconds>\d+?)s?)?$')
    parts = regex.match(string).groupdict()

    for k in parts.iterkeys():
        if parts[k] is None:
            parts[k] = 0
        parts[k] = int(parts[k])

    seconds = (((parts['days'] * 24) + parts['hours']) * 60 + parts['minutes']) * 60 + parts['seconds']
    return seconds


def parse_args():
    """
    Parse command-line to arguments and create Matcher instance
    :return: Matcher
    """
    parser = argparse.ArgumentParser(description="Processes Snapshot")
    matcher = Matcher()

    parser.add_argument('cmd', nargs='?', type=str, help="CMD line to filter")
    parser.add_argument('-k', '--kill', type=int, choices=SIGNALS, help="Kill signal")
    parser.add_argument('-u', '--user', type=str, help="User to filter")
    parser.add_argument('-g', '--group', type=str, help="Group to filter")
    parser.add_argument('-p', '--pid', type=int, help="PID to find")
    parser.add_argument('--exe', type=str, help="EXE to find")
    parser.add_argument('-ppid', '--ppid', type=int, help="PPID to filter")
    parser.add_argument('-s', '--state', type=str, help="State to filter")
    parser.add_argument('-t', '--time', type=parse_human_time, help="Minimal working time to filter")
    parser.add_argument('--strict', action='store_true', default=False, help="Strict match CMD and EXE")
    parser.add_argument('--verbose', action='store_true', default=False, help="Be more verbose")
    parser.add_argument('--any', action='store_true', default=False, help="Match any of filters")
    parser.add_argument('--exec', dest='proc_exec', type=str, help="Run user-defined command on matching processes")
    parser.add_argument('--grep', dest='grep', action='append', default=[], help="more subsequent filters on CMD line")
    parser.add_argument('--grep-v', dest='grep_not', action='append', default=[], help="more subsequent negative filters on CMD line")

    parser.parse_args(namespace=matcher)

    if matcher.user:
        if matcher.user.isdigit():
            matcher.user = int(matcher.user)
        else:
            matcher.user = pwd.getpwnam(matcher.user).pw_uid

    if matcher.group:
        if matcher.group.isdigit():
            matcher.group = int(matcher.group)
        else:
            matcher.group = grp.getgrnam(matcher.group).gr_gid

    return matcher


def process_state(process):
    status = process.status()
    state = status[0].capitalize()

    if status == 'stopped':
        state = 'T'

    return state


def process_kill(matcher):
    """
    Kill matching processes
    :param matcher: Matcher
    :return: None
    """
    sig = matcher.kill
    for p in find_process(matcher):
        try:
            os.kill(p.pid, sig)
            msg = "Killed pid {} with signal {}".format(p.pid,sig)
            if matcher.verbose:
                msg += ": {}".format(ProcessFormatter(p).format_oneline())
            print(msg)
        except psutil.NoSuchProcess:
            print("Pid {} already exited".format(p.pid))
        except psutil.AccessDenied:
            print("Cannot kill pid {}".format(p.pid))


def process_exec(matcher):
    """
    Exec user command on matching processes
    :param matcher: Matcher
    :return: None
    """
    for p in find_process(matcher):
        try:
            subprocess.check_call(['bash', '-c', matcher.proc_exec.format(pid=p.pid)])
        except psutil.NoSuchProcess:
            print("Pid {} already exited".format(p.pid))
        except subprocess.CalledProcessError:
            print("Failed to run user command on pid {}".format(p.pid))
        except (psutil.AccessDenied, KeyboardInterrupt):
            print("Permission denied for pid {}".format(p.pid))


def print_processes_info(matcher):
    """
    Print `ps`-like matching processes list
    :param matcher: Matcher
    :return: None
    """
    for p in find_process(matcher):
        try:
            ProcessFormatter(p).print_oneline()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue


def find_process(matcher):
    """
    Filter full processlist according to filters in matcher
    :param matcher: Matcher
    :return: Processes iterator
    """
    for p in psutil.process_iter():
        try:
            if matcher.match(p):
                yield p
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue


class ProcessFormatter:
    def __init__(self, proc):
        """
        :param proc: Process
        """
        self.proc = proc

    def print_oneline(self):
        print(self.format_oneline())

    def format_oneline(self):
        """
        Print `ps`-like process line
        :return: None
        """
        ppid = self.proc.ppid()
        user = self.get_username()
        group = self.get_groupname()
        state = process_state(self.proc)
        stime = datetime.fromtimestamp(int(self.proc.create_time()))
        name = self.proc.exe()
        if not name:
            name = self.proc.name()
        cmd = ' '.join(self.proc.cmdline())

        string = "{:<6} {:<6} {:^30} {:^20} {} {} {:<40} {}".format(self.proc.pid, ppid, user, group, state, stime, name,
                                                                    cmd)
        return string

    def get_groupname(self):
        """
        Get group name by gid using cache
        :return: Groupname
        """
        gid = self.proc.gids().effective
        if gid not in GID_CACHE:
            try:
                GID_CACHE[gid] = grp.getgrgid(gid).gr_name
            except KeyError:
                GID_CACHE[gid] = ''
        return GID_CACHE[gid]

    def get_username(self):
        """
        Get user name by uid using cache
        :return: Username
        """
        uid = self.proc.uids().effective
        if uid not in UID_CACHE:
            try:
                UID_CACHE[uid] = pwd.getpwuid(uid).pw_name
            except KeyError:
                UID_CACHE[uid] = ''
        return UID_CACHE[uid]


class Matcher:
    def __init__(self):
        self._pid = os.getpid()

    def match(self, proc):
        """
        Match process according to defined filter variables
        :param proc: Process
        :return: Boolean
        """
        if proc.pid == self._pid:
            return False

        self.proc = proc

        if not hasattr(self, 'filter_functions'):
            self.filter_functions = []
            members = dict(inspect.getmembers(self))
            for name, func in members.iteritems():
                if not name.startswith('_match_'):
                    continue

                value_name = name.replace('_match_', '')
                if (value_name in members) and (members[value_name] is not None):
                    self.filter_functions.append(func)

        if len(self.filter_functions) == 0:
            return True

        results = [x() for x in self.filter_functions]

        if self.any:
            matched = any(results)
        else:
            matched = all(results)

        matched = matched and self._grep_cmd()

        return matched

    def _match_pid(self):
        """
        Check matching pid
        :return: Boolean
        """
        pid = self.proc.pid
        return self.pid == pid

    def _match_ppid(self):
        """
        Check matching ppid
        :return: Boolean
        """
        ppid = self.proc.ppid()
        return self.ppid == ppid

    def _match_user(self):
        """
        Check matching uid
        :return: Boolean
        """
        uid = self.proc.uids().effective
        return uid == self.user

    def _match_state(self):
        """
        Check matching state
        :return: Boolean
        """
        state = process_state(self.proc)
        return self.state.capitalize() == state

    def _match_time(self):
        """
        Check matching working time
        :return: Boolean
        """
        create_time = datetime.fromtimestamp(self.proc.create_time())
        return self.time <= (datetime.now() - create_time).total_seconds()

    def _grep_cmd(self):
        """
        Grep cmd
        :return: Boolean
        """
        cmd = ' '.join(self.proc.cmdline())
        name = self.proc.name()

        matched = True

        if hasattr(self, 'grep'):
            for grep in self.grep:
                matched = matched and (grep in cmd or grep in name)
                if not matched:
                    break

        if hasattr(self, 'grep_not'):
            for grep_not in self.grep_not:
                matched = matched and (grep_not not in cmd and grep_not not in name)
                if not matched:
                    break

        return matched

    def _match_cmd(self):
        """
        Check matching cmd
        :return: Boolean
        """
        cmd = ' '.join(self.proc.cmdline())
        name = self.proc.name()

        if self.strict:
            return self.cmd == cmd

        return self.cmd in cmd or self.cmd in name

    def _match_exe(self):
        """
        Check matching exe
        :return: Boolean
        """
        exe = self.proc.exe()
        if self.strict:
            return self.exe == exe

        return self.exe in exe

    def _match_group(self):
        """
        Check matching group
        :return: Boolean
        """
        gids = self.proc.gids()
        if self.strict:
            return self.group == gids.effective

        return self.group in gids


if __name__ == '__main__':
    main()
