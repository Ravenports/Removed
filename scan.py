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

import pathlib
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


def main():
    """
    This is the entry point of the script
    """
    config = read_configuration()

if __name__ == "__main__":
    main()
