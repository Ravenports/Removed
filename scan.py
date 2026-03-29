#!/raven/bin/python3
"""
This script scans the ravensource directory and builds up a tree
compromised of previously deleted ports.  If an argument in the
form of "YYYYMMDD" is provided, it stops when it reaches that date
(does not include that date).

If the file .last_commit exists in this directory (which contains
a 10-character commit hash), it starts from the next newest commit
otherwise it starts from the very first commit.
"""

import datetime
import os
import pathlib
import re
import subprocess
import sys
import yaml

def read_configuration():
    """
    Convert contents of config.yaml into a configuration
    """
    config_file = pathlib.Path(__file__).parent / "config.yaml"
    try:
        with open(config_file, "r") as fin:
            config = yaml.load(fin, Loader=yaml.FullLoader)
    except OSError as err:
        print("The config.yaml configuration file could not be opened for reading.")
        sys.exit(1)
    except yaml.YAMLError as err:
        print("The contents of config.yaml could not be understood.  Syntax error?")
        sys.exit(2)
    return config


def get_commit_order(repo_path):
    """
    Retrieves the entire ravensource commit history from the first commit to the
    latest one.
    """
    command = [
        "git", "-C", repo_path, "log", "--reverse", "--format=%h %aI", "--abbrev=10"
    ]
    with subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        text=True,
        bufsize=1  # Line-buffered for efficient streaming
    ) as proc:
        # proc.stdout is an iterable that yields one line (hash) at a time
        for line in proc.stdout:
            parts = line.strip().split(" ", 1)
            if len(parts) == 2:
                commit_hash, commit_date = parts
                yield commit_hash, commit_date


def read_last_commit():
    """
    If .last_commit exists, read it and verify a 10-character hexidecimal code
    exists inside.  If it does, pass it on, otherwise pass None
    """
    commit_file = pathlib.Path(__file__).parent / ".last_commit"
    if commit_file.is_file():
        with commit_file.open("r") as fin:
            line = fin.readline().strip()
            if re.fullmatch(r'[0-9a-fA-F]{10}', line):
                return line
    return None


def save_last_commit(commit_hash):
    """
    if commit_hash is a 10-character hexidecimal code, create or overwrite
    the .last_commit file in this directory.
    """
    commit_file = pathlib.Path(__file__).parent / ".last_commit"
    if not isinstance(commit_hash, str) or not re.fullmatch(r'[0-9a-fA-F]{10}', commit_hash):
        return
    with commit_file.open("w") as fout:
        fout.write(commit_hash)


def get_termination_date():
    """
    If there's an argument, it should be in the YYYY-MM-DD format.
    if it is, convert to unix epoch, otherwise return None
    """
    if len(sys.argv) < 2:
        return None

    try:
        dt = datetime.datetime.strptime(sys.argv[1], "%Y-%m-%d")
        return int(dt.timestamp())
    except ValueError:
        return None


def get_unix_epoch(commit_time):
    """
    Given a commit_time formated as an ISO 8601 date/time string, return
    """
    try:
        dt = datetime.datetime.fromisoformat(commit_time)
        return int(dt.timestamp())
    except (ValueError, TypeError):
        return None


def main():
    """
    This is the entry point of the script
    """
    config = read_configuration()
    termination_epoch = get_termination_date()
    previous_run = read_last_commit()
    previous_found = False

    try:
        for counter, (commit_hash, iso_date) in enumerate(
            get_commit_order(config["location"]["ravensource"]), 1
        ):
            if previous_run:
                if not previous_found:
                    if previous_run == commit_hash:
                        previous_found = True
                    continue

            if termination_epoch:
                current_epoch = get_unix_epoch(iso_date)
                if current_epoch > termination_epoch:
                     print(f"Reached termination date. Stopping at {commit_hash}.")
                     break

            print(f"Working on: {commit_hash} {iso_date} ({counter})")
            save_last_commit(commit_hash)
    except BrokenPipeError:
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        sys.exit(0)


if __name__ == "__main__":
    main()
