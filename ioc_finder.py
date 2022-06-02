import csv
import hashlib
import itertools
import os
import platform
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
__version__ = "v0.1.2"
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
    notfound = f"{Fore.YELLOW}\u0058{Fore.RESET}"
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
        with open(self.iocs_file(), encoding="utf-8") as _file:
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
    """
    Opens the latest csv file in the results directory, and outputs it to the terminal using the
    PrettyTable module
    """
    # output latest csv file to terminal
    csv_files = Path(worker.results).glob("*.csv")
    latest_csv = max(csv_files, key=os.path.getctime)

    with open(latest_csv, encoding="utf-8") as _file:
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
    """
    If the file is less than 25 bytes, remove it
    """
    # Remove empty results - not the best method, but it works
    csv_files = Path(worker.results).glob("*.csv")
    files = [x for x in csv_files if x.is_file()]
    for _file in files:
        if os.stat(_file).st_size < 25:
            os.remove(_file)


def scantree(path):
    """
    Recursively scans a directory tree and returns a generator of all the files in the tree

    :param path: The path to the directory you want to scan
    """
    with os.scandir(path) as entries:
        for entry in entries:
            try:
                if not entry.name.startswith(".") and entry.is_dir(follow_symlinks=False):
                    yield from scantree(entry.path)
                else:
                    yield entry.path
            except (PermissionError, FileNotFoundError):
                continue


def ioc_processor(ioc, drivepath, contains):
    """
    Takes a list of IOCs, a drive path, and a boolean value (`contains`) and searches
    the drive path for the IOCs. If the IOC is found, the file path, size, creation date, and SHA256
    hash are written to a CSV file

    :param ioc: This is the list of IOCs that you want to search for
    :param drivepath: The path to the drive you want to scan
    :param contains: True or False
    """
    # Check if ioc contains spaces
    if [i for i in ioc[:-1] if "," not in str(i.split(","))]:
        sys.exit(f'Surround string with double quotes, e.g., {Fore.LIGHTMAGENTA_EX}"find me now.zip"{Fore.RESET}.')

    with open(worker.save_iocs_csv(), "w", newline="", encoding="utf-8") as csvfile:
        writer = write_to_csv(csvfile)
        print(f"{worker.processing} Getting file count...", sep=" ", end=" ")
        try:
            filecounter = len(list(scantree(drivepath)))
            print(f"{filecounter:,} files")
            for filepath, item in itertools.product(
                tqdm(
                    scantree(drivepath),
                    total=filecounter,
                    desc=f"{worker.processing} Processing",
                    ncols=90,
                    unit=" files",
                ),
                ioc,
            ):
                item = item.strip(",")
                try:
                    filematch = (
                        PurePath(filepath).match(f"*{item}*") if contains else PurePath(filepath).match(f"{item}*")
                    )

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
                except OSError:
                    continue
        except KeyboardInterrupt:
            abort_output(csvfile)


def infile_processor(drivepath):
    """
    Takes a drive path as an argument, reads the IOCs file, and then searches the drive for the IOCs.


    If it finds an IOC, it writes the path, size, created date, and SHA256 hash to a CSV file.

    If the IOCs file is empty, it exits.

    If the user presses Ctrl+C, it writes the results to the CSV file and exits.

    :param drivepath: The path to the drive you want to scan
    """
    # Check if IOC's file is empty
    if os.path.getsize(worker.iocs_file()) < 40:
        sys.exit(f"\n{worker.error} Missing IOCs -- The {worker.iocs_file()} file appears to be empty.\n")

    ioc_str = worker.read_file()

    with open(worker.save_iocs_csv(), "w", newline="", encoding="utf-8") as csvfile:
        writer = write_to_csv(csvfile)
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
                        except OSError:
                            continue
        except KeyboardInterrupt:
            abort_output(csvfile)


def main(drivepath, contains=None, ioc=None, infile=None):
    """
    Takes a drive path, an IOC, or an input file, and then searches the drive for the IOCs

    :param drivepath: The path to the drive you want to scan
    :param ioc: The IOC you want to search for
    :param infile: This is the file that contains the IOCs you want to search for
    """
    worker.count = 0
    if ioc:
        ioc_processor(ioc, drivepath, contains)
    elif infile:
        infile_processor(drivepath)

    if worker.count:
        print(f"\n{worker.found} Found {worker.count} IOCs on {worker.hostname}")
        print(f"    --> Results saved to {worker.save_iocs_csv()}\n")
        ptable_to_term()
    else:
        print(f"{worker.notfound} No matches for IOCs")
        remove_output()


def write_to_csv(csvfile):
    fieldnames = ["Path", "Size", "Created", "Hash"]
    result = csv.DictWriter(csvfile, fieldnames=fieldnames)
    result.writeheader()

    return result


def abort_output(csvfile):
    csvfile.close()
    remove_output()
    sys.exit("\nAborted!")


if __name__ == "__main__":
    banner = rf"""
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
    if platform.system() != "Windows":
        sys.exit("Sorry, script is optimized for Windows systems only.")
    else:
        main(args.path, args.c, args.i, args.f)
