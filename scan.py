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
import glob
import hashlib
import os
import pathlib
import re
import shutil
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


def return_to_head(repo_path):
    """
    Moves the repository from an arbitrary commit back to the
    remote's default branch head (main/master).
    """
    try:
        # 'origin/HEAD' is a symbolic ref that points to the default branch
        subprocess.run(
            ["git", "-C", repo_path, "checkout", "origin/HEAD"],
            check=True,
            capture_output=True,
            text=True
        )
        print("Successfully returned to HEAD.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to return to HEAD: {e.stderr.strip()}")


def switch_to_commit(repo_path, commit_hash):
    """
    Switches the repository to a specific commit hash.
    Note: This puts the repo in 'detached HEAD' state.
    """
    try:
        subprocess.run(
            ["git", "-C", repo_path, "checkout", commit_hash],
            check=True,
            capture_output=True,
            text=True
        )
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error: Could not switch to {commit_hash}. {e.stderr.strip()}")
        return False


def get_bucket_subdirs(base_path):
    """
    Equivalent to: find bucket_?? -maxdepth 1 -mindepth 1 -type d
    Returns: ['bucket_00/libwebsockets', 'bucket_00/aspell-fo', ...]
    """
    base = pathlib.Path(base_path)
    return [
        str(p.relative_to(base))
        for p in base.glob("bucket_??/*")
        if p.is_dir()
    ]


def build_filter_from_conspiracy(conspiracy_path):
    """
    Read conspiracy_variants file and construct an array of ports from it.
    """
    results = set()
    variants = pathlib.Path(conspiracy_path) / "Mk" / "Misc" / "conspiracy_variants"
    if not variants.is_file():
        print("The conspiracy variants map cannot be found")
        sys.exit(1)

    with variants.open("r") as fin:
        for line in fin:
            parts = line.split()
            if len(parts) >= 2:
                bucket_id, portname, *_ = parts
                directory = f"bucket_{bucket_id}/{portname}"
                results.add(directory)
    return results


def reset_deleted_ports_tree():
    """
    Completely remove any existing tree and create an empty directory.
    This is done on the first run, or when the previous commit is not
    available.
    """
    tree_directory = pathlib.Path(__file__).parent / "deleted_ports"
    if tree_directory.exists():
        if tree_directory.is_dir():
            shutil.rmtree(tree_directory)
        else:
            tree_directory.unlink()
    tree_directory.mkdir(parents=True, exist_ok=True)
    history = pathlib.Path(__file__).parent / "history.md"
    if history.is_file():
        history.unlink()


def remaining_ports(filter, rsource):
    """
    The bucket directories of the current state of the ravensource
    repository is determined.  Any directories that are in the filter set
    are removed.  The port directories remaining are returned.
    """
    results = set()
    allports = get_bucket_subdirs(rsource)
    for port in allports:
        if port not in filter:
            portname = port.split("/")[-1]
            prefix = bucket(portname)
            calced = f"{prefix}/{portname}"
            if calced == port:
                results.add(port)
            else:
                print("SKIP MISPLACED {port}, should be located at ${calced}")
    return results


def write_out_index(deleted_ports):
    """
    deleted ports is a dictionary with "portname" as the key and a three
    element array as the value.  ELement 0 of the array is the "bucket" value,
    element 1 is the 10-character commit hash, and element 2 is the
    ISO 8601 timestamp that it was last seen.

    The file is written to <cwd>/history.md file.
    """
    history = pathlib.Path(__file__).parent / "history.md"
    with history.open("w") as fout:
        fout.write("# Last time deleted Ravenport was available\n\n")
        fout.write("```\n")
        fout.write("Directory  Commit      Date                       Portname\n")
        fout.write("```\n\n---\n\n```\n")
        #          "bucket_00  0123456789  2017-04-22T11:42:17-05:00  ravensys-uname
        for name, data in sorted(deleted_ports.items()):
            fout.write(f"{data[0]}  {data[1]}  {data[2]}  {name}\n")
        fout.write("```\n")


def read_existing_index():
    """
    If history.md exists, read it and return the deleted ports data.
    The first 9 lines are the header and can be ignore.
    The final line ("```") is also ignored.
    """
    results = {}
    history = pathlib.Path(__file__).parent / "history.md"
    if history.is_file():
        for counter, line in enumerate(history.read_text().splitlines()):
            if counter < 9 or line == "```":
                continue
            parts = line.split()
            if len(parts) >= 4:
                results[parts[3]] = parts[:3]
    return results


def update_deleted_ports(deleted_ports, purged, commit_hash, iso_date):
    """
    Iterates through purged ports and upserts them into deleted_ports
    """
    for port in purged:
        portname = port.split("/")[-1]
        prefix = bucket(portname)
        deleted_ports[portname] = [prefix, commit_hash, iso_date]


def sync_purged_ports(filter, rsource):
    """
    1. Obtain a list of remaining ports (ports not in the filter).
    2. If there is at least one, create an inclusion file for rsync
    3. run rsync
    """
    destination = pathlib.Path(__file__).parent / "deleted_ports"
    purged = remaining_ports(filter, rsource)
    if purged:
        with open("/tmp/folders.txt", "w") as fout:
            for path in purged:
                fout.write(f"{path}\n")
        slash_rsource = os.path.join(rsource, "")
        slash_destination = os.path.join(str(destination), "")
        # -r: Recursive (Must be explicit with --files-from)
        # -l: Preserve symlinks
        # -p: Preserve permissions
        # -t: Preserve modification times
        # -g: Preserve group
        # -o: Preserve owner
        # -D: Preserve devices/specials
        # -R: Relative (Preserves the bucket_XX/subdir/ structure)
        # -v: Verbose
        cmd = [
            "rsync", "-aR", "--delete",
            "--info=NAME",
            "--files-from=/tmp/folders.txt",
            "-r",   # <--- MANUALLY RE-ENABLE RECURSION
            slash_rsource, slash_destination
        ]
        # print(f"Executing: {' '.join(cmd)}")
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            transferred = result.stdout.strip()
            if transferred:
                print(transferred)
        except subprocess.CalledProcessError as e:
            print("Error during sync:\n", e.stderr)
    return purged


def bucket(portname):
    """
    Given the portname, return "bucket_" + first 2 characters of the sha1 hash of portname
    """
    portname_hash = hashlib.sha1(portname.encode())
    digest = portname_hash.hexdigest().upper()
    first2 = digest[:2]
    return f"bucket_{first2}"


def main():
    """
    This is the entry point of the script
    """
    config = read_configuration()
    rsource = config["location"]["ravensource"]
    csource = config["location"]["conspiracy"]
    termination_epoch = get_termination_date()
    previous_run = read_last_commit()
    previous_found = False

    filter = build_filter_from_conspiracy(csource)

    if not previous_run:
        reset_deleted_ports_tree()

    deleted_ports = read_existing_index()
    try:
        for counter, (commit_hash, iso_date) in enumerate(get_commit_order(rsource), 1):
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

            print(f"Switched to commit: {commit_hash} {iso_date} ({counter})")
            switch_to_commit(rsource, commit_hash)
            purged = sync_purged_ports(filter, rsource)
            update_deleted_ports(deleted_ports, purged, commit_hash, iso_date)
            save_last_commit(commit_hash)
    except KeyboardInterrupt:
        print("\nInterrupted by user (Ctrl+C). Cleaning up...")
    except BrokenPipeError:
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
    finally:
        write_out_index(deleted_ports)
        return_to_head(rsource)


if __name__ == "__main__":
    main()
