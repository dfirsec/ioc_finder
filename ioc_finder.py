import csv
import hashlib
import os
import socket
import sys
import time
from argparse import ArgumentParser
from datetime import datetime
from pathlib import Path, PurePath

from colorama import Fore
from colorama import init as color_init
from prettytable import PrettyTable
from tqdm import tqdm

__author__ = "DFIRSec (@pulsecode)"
__version__ = "v0.1.1"
__description__ = "Quick and dirty method to search for filenames that match IOCs if hashes are not yet available."


class Workers:
    """Returns number of matches found."""

    def __init__(self, count=None):
        self.count = count

    filepath = Path(__file__).parent
    results = filepath / "results"
    iocs = filepath / "iocs"
    hostname = socket.gethostname().upper()

    # Initialize colorama
    color_init()

    # Unicode Symbols and colors -  ref: http://www.fileformat.info/info/unicode/char/a.htm
    processing = f"{Fore.CYAN}>{Fore.RESET}"
    found = f"{Fore.GREEN}\u2714{Fore.RESET}"
    notfound = f"{Fore.YELLOW}\u00D8{Fore.RESET}"
    error = f"{Fore.RED}\u2718{Fore.RESET}"

    def iocs_file(self):
        return self.iocs / "known_iocs.txt"

    def save_iocs_csv(self):
        if not self.results.exists():
            self.results.mkdir(parents=True)
        timestr = time.strftime("%Y%m%d-%H%M%S")
        return self.results / f"{worker.hostname}_{timestr}.csv"

    @staticmethod
    def sha256(fname):
        hash_sha256 = hashlib.sha256()
        with open(fname, "rb") as _file:
            for chunk in iter(lambda: _file.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()

    def read_file(self):
        with open(self.iocs_file(), "r") as _file:
            # skip file header starting with '#'
            try:
                next(_file)
                data = [data.strip() for data in _file.readlines()]
            except StopIteration:
                pass
            else:
                return data
            return None


def ptable_to_term():
    # output latest csv file to terminal
    csv_files = Path(worker.results).glob("*.csv")
    latest_csv = max(csv_files, key=os.path.getctime)

    with open(latest_csv) as _file:
        rdr = csv.reader(_file, delimiter=",")
        try:
            ptable = PrettyTable(next(rdr))
        except StopIteration:
            pass
        else:
            for row in rdr:
                ptable.add_row(row)

            ptable.align = "l"
            print(ptable)


def remove_output():
    # Remove empty results - not the best method, but it works
    csv_files = Path(worker.results).glob("*.csv")
    files = [x for x in csv_files if x.is_file()]
    for _file in files:
        if os.stat(_file).st_size < 25:
            os.remove(_file)


def scantree(path):
    with os.scandir(path) as entries:
        for entry in entries:
            try:
                if not entry.name.startswith(".") and entry.is_dir(follow_symlinks=False):
                    yield from scantree(entry.path)
                else:
                    yield entry.path
            except PermissionError:
                continue


def main(drivepath, contains=None, ioc=None, infile=None):
    worker.count = 0

    if ioc:
        # Check if ioc contains spaces
        if [i for i in ioc[:-1] if "," not in str(i.split(","))]:
            sys.exit(f'Surround string with double quotes, e.g., {Fore.LIGHTMAGENTA_EX}"find me now.zip"{Fore.RESET}.')

        with open(worker.save_iocs_csv(), "w", newline="") as csvfile:
            fieldnames = ["Path", "Size", "Created", "Hash"]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            print(f"{worker.processing} Getting file count...", sep=" ", end=" ")
            filecounter = len(list(scantree(drivepath)))
            print(f"{filecounter:,} files")

            try:
                for filepath in tqdm(
                    scantree(drivepath),
                    total=filecounter,
                    desc=f"{worker.processing} Processing",
                    ncols=90,
                    unit=" files",
                ):
                    for item in ioc:
                        item = item.strip(",")
                        try:
                            if contains:
                                filematch = PurePath(filepath).match(r"*" + item + r"*")
                            else:
                                filematch = PurePath(filepath).match(item + r"*")
                            if filematch:
                                path = Path(filepath)
                                created = datetime.fromtimestamp(os.stat(path).st_ctime)
                                size = os.stat(path).st_size
                                writer.writerows(
                                    [
                                        {
                                            "Path": path,
                                            "Size": size,
                                            "Created": f"{created:%Y-%m-%d}",
                                            "Hash": worker.sha256(path),
                                        }
                                    ]
                                )
                                worker.count += 1
                        except (PermissionError, OSError):
                            continue
            except KeyboardInterrupt:
                csvfile.close()
                remove_output()
                sys.exit("\nAborted!")

    elif infile:
        # Check if IOC's file is empty
        if os.path.getsize(worker.iocs_file()) < 40:
            sys.exit(f"\n{worker.error} Missing IOCs -- The {worker.iocs_file()} file appears to be empty.\n")

        ioc_str = worker.read_file()

        with open(worker.save_iocs_csv(), "w", newline="") as csvfile:
            fieldnames = ["Path", "Size", "Created", "Hash"]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            try:
                for root, _, files in tqdm(
                    os.walk(drivepath),
                    ascii=True,
                    desc=f"{worker.processing} Searching for IOCs on {worker.hostname}",
                    ncols=80,
                    unit=" files",
                ):
                    for filename in files:
                        if filename.lower() in (name.lower() for name in ioc_str):
                            try:
                                path = os.path.join(root, filename)
                                created = datetime.fromtimestamp(os.stat(path).st_ctime)
                                size = os.stat(path).st_size
                                worker.count += 1
                                writer.writerows(
                                    [
                                        {
                                            "Path": path,
                                            "Size": size,
                                            "Created": f"{created:%Y-%m-%d}",
                                            "Hash": worker.sha256(path),
                                        }
                                    ]
                                )
                            except (PermissionError, OSError):
                                continue
            except KeyboardInterrupt:
                csvfile.close()
                remove_output()
                sys.exit("\nAborted!")

    if worker.count:
        print(f"\n{worker.found} Found {worker.count} IOCs on {worker.hostname}")
        print(f"    --> Results saved to {worker.save_iocs_csv()}\n")
        ptable_to_term()
    else:
        print(f"{worker.notfound} No matches for IOCs")
        remove_output()


if __name__ == "__main__":
    banner = fr"""
          ________  ______   _______           __
         /  _/ __ \/ ____/  / ____(_)___  ____/ /__  _____
         / // / / / /      / /_  / / __ \/ __  / _ \/ ___/
       _/ // /_/ / /___   / __/ / / / / / /_/ /  __/ /
      /___/\____/\____/  /_/   /_/_/ /_/\__,_/\___/_/
      
                                    {__version__}
                                    {__author__}
    """

    print(f"{Fore.CYAN}{banner}{Fore.RESET}")

    worker = Workers()
    parser = ArgumentParser()
    iocs_file = worker.iocs_file()

    # Check if python version is v3.7+
    if sys.version_info[0] == 3 and sys.version_info[1] <= 7:
        sys.exit(f"\n{worker.error} Please use python version 3.7 or higher.\n")

    parser.add_argument("path", type=Path, help="Path to search")
    parser.add_argument("-c", action="store_true", help="name contains string")

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-i", nargs="+", type=str, metavar="", help="single or list of IOCs (comma separated)")
    group.add_argument("-f", action="store_true", default=iocs_file, help="use known_iocs.txt file containing IOCs")

    args = parser.parse_args()

    if len(sys.argv[1:]) == 0:
        parser.print_help()
    else:
        main(args.path, args.c, args.i, args.f)
