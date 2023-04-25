"Quick and dirty method to search for filenames that match IOCs if hashes are not yet available."

import contextlib
import csv
import hashlib
import os
import platform
import socket
import sys
import time
from argparse import ArgumentParser
from datetime import datetime
from functools import partial
from pathlib import Path, PurePath
from typing import IO, Iterator, List

from colorama import Fore
from rich.console import Console
from rich.table import Table
from tqdm import tqdm

# Initialize rich console
console = Console()


class Workers(object):
    """Returns number of matches found."""

    def __init__(self):
        self.count = 0

    filepath = Path(__file__).parent
    output = filepath / "results"
    iocs = filepath / "iocs"
    hostname = socket.gethostname().upper()

    def iocs_file(self) -> Path:
        """
        Get the path to the file containing the known IOCs.

        Returns:
            Path: the path to the file containing the known IOCs.
        """
        return self.iocs / "known_iocs.txt"

    def save_iocs_csv(self) -> Path:
        """
        Creates a directory called `results` in the current working directory and CSV file.

        Returns:
            Path: The path to the file that will be created.
        """
        if not self.output.exists():
            self.output.mkdir(parents=True)
        timestr = time.strftime("%Y%m%d-%H%M%S")
        return self.output / f"{worker.hostname}_{timestr}.csv"

    def sha256(self, fname: str) -> str:
        """
        It reads the file in chunks of 4096 bytes and updates the hash object with each chunk.

        Args:
            fname (str): The file name of the file you want to hash.

        Returns:
            The hash of the file.
        """
        hash_sha256 = hashlib.sha256()
        chunk_size = 4096
        with open(fname, "rb") as fileobj:
            for chunk in iter(partial(fileobj.read, chunk_size), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()

    def read_file(self) -> List[str]:
        """
        Reads the file and returns the data.

        Returns:
            A list of strings.
        """
        with open(self.iocs_file(), encoding="utf-8") as fileobj:
            try:
                next(fileobj)  # skip file header starting with '#'
            except StopIteration:
                return []  # return an empty list in the case where the file is empty
            return [dataobj.strip() for dataobj in fileobj]  # Iterate directly over the fileobj


def ptable_to_term() -> None:
    """
    Output latest csv file to terminal.
    """
    csv_files = Path(worker.output).glob("*.csv")
    latest_csv = max(csv_files, key=os.path.getctime)
    table = Table(title="IOC Finder Results")

    with open(latest_csv, encoding="utf-8") as fileobj:
        reader = csv.reader(fileobj, delimiter=",")
        for column in next(reader):
            table.add_column(column, style="magenta")
        for row in reader:
            table.add_row(*row)

    console.print(table)


def remove_output() -> None:
    """
    If the file is less than 25 bytes, remove it.
    """
    # Remove empty results - not the best method, but it works
    csv_files = Path(worker.output).glob("*.csv")
    files = [csv for csv in csv_files if csv.is_file()]
    bytes_size = 25
    for filename in files:
        if os.stat(filename).st_size < bytes_size:
            os.remove(filename)


def scantree(path: str) -> Iterator[str]:
    """
    Recursively scans a directory tree and returns a generator of all the files in the tree

    path: The path to the directory you want to scan
    """
    with os.scandir(path) as entries:
        for entry in entries:
            with contextlib.suppress(PermissionError, FileNotFoundError):
                if not entry.name.startswith(".") and entry.is_dir(follow_symlinks=False):
                    yield from scantree(entry.path)
                else:
                    yield entry.path


def process_filepath(filepath: str, ioc: List[str], contains: bool, writer: csv.DictWriter) -> None:
    """
    Searches for matches between the IOCs and the file path.

    Args:
        filepath (str): A string representing the file path of the file being processed.
        ioc (List[str]): List of strings representing Indicators of Compromise (IOCs).
        contains (bool): Determines whether the file path should contain the IOC or start with it.
        writer (DictWriter): Used to write rows to a CSV file.
    """
    for line in ioc:
        line = line.strip(",")

        with contextlib.suppress(OSError):
            filematch = PurePath(filepath).match(f"*{line}*") if contains else PurePath(filepath).match(f"{line}*")

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
                            "Hash": worker.sha256(str(path)),
                        },
                    ],
                )
                worker.count += 1


def ioc_processor(ioc: List[str], drivepath: str, contains: bool) -> None:
    """
    Takes a list of IOCs, a drive path, and a boolean value (`contains`) and searches
    the drive path for the IOCs. If the IOC is found, the file path, size, creation date, and SHA256
    hash are written to a CSV file.

    Args:
        ioc: This is the list of IOCs that you want to search for
        drivepath: The path to the drive you want to scan
        contains (bool): True or False
    """
    # Check if ioc contains spaces
    if any("," not in str(line.split(",")) for line in ioc[:-1]):
        sys.exit(f'Surround string with double quotes, e.g., {Fore.LIGHTMAGENTA_EX}"find me now.zip"{Fore.RESET}.')

    with open(worker.save_iocs_csv(), "w", newline="", encoding="utf-8") as csvfile:
        writer = write_to_csv(csvfile)
        console.print("> Getting file count...", sep=" ", end=" ")
        try:
            file_count = len(list(scantree(drivepath)))
        except KeyboardInterrupt:
            abort_output(csvfile)
        else:
            console.print(f"{file_count:,} files")
            cols = 90
            for filepath in tqdm(
                scantree(drivepath),
                total=file_count,
                desc="> Processing",
                ncols=cols,
                unit=" files",
            ):
                process_filepath(filepath, ioc, contains, writer)


def infile_processor(drivepath: str) -> None:
    """
    Takes a drive path as an argument, reads the IOCs file, and then searches the drive for the IOCs.
    If it finds an IOC, it writes the path, size, created date, and SHA256 hash to a CSV file.
    If the IOCs file is empty, it exits.
    If the user presses Ctrl+C, it writes the results to the CSV file and exits.

    Args:
        drivepath (path): The path to the drive you want to scan
    """
    # Check if IOC's file is empty
    num_bytes = 40
    if os.path.getsize(worker.iocs_file()) < num_bytes:
        sys.exit(f"\n Missing IOCs -- The {worker.iocs_file()} file appears to be empty.\n")

    ioc_obj = worker.read_file()

    with open(worker.save_iocs_csv(), "w", newline="", encoding="utf-8") as csvfile:
        writer = write_to_csv(csvfile)
        try:
            cols = 80
            for root, _, files in tqdm(
                os.walk(drivepath),
                ascii=True,
                desc=f" Searching for IOCs on {worker.hostname}",
                ncols=cols,
                unit=" files",
            ):
                for filename in files:
                    if filename.lower() in (name.lower() for name in ioc_obj):
                        with contextlib.suppress(OSError):
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
                                    },
                                ],
                            )
        except KeyboardInterrupt:
            abort_output(csvfile)


def write_to_csv(csvfile: IO[str]) -> csv.DictWriter:
    """
    Creates the CSV file and writes the header row.

    Args:
        csvfile (IO[str]): The file object that you want to write to.

    Returns:
        A DictWriter object.
    """
    fieldnames = ["Path", "Size", "Created", "Hash"]
    output = csv.DictWriter(csvfile, fieldnames=fieldnames)
    output.writeheader()

    return output


def abort_output(csvfile: IO[str]) -> None:
    """
    Closes the CSV file, removes the CSV file, and exits the program.

    Args:
        csvfile (IO[str]): The file object that is being written to.
    """
    csvfile.close()
    remove_output()
    sys.exit("\nAborted!")


def main(drivepath: str, ioc: List[str], contains: bool = False, infile: bool = False) -> None:
    """
    Takes a drive path, an IOC, or an input file, and then searches the drive for the IOCs

    drivepath: The path to the drive you want to scan
    ioc: The IOC you want to search for
    infile: This is the file that contains the IOCs you want to search for
    """
    worker.count = 0
    if ioc:
        ioc_processor(ioc, drivepath, contains)
    elif infile:
        infile_processor(drivepath)

    if worker.count:
        console.print(f"\n Found {worker.count} IOCs on {worker.hostname}")
        console.print(f" --> Results saved to {worker.save_iocs_csv()}\n")
        ptable_to_term()
    else:
        console.print(" No matches for IOCs")
        remove_output()


if __name__ == "__main__":
    banner = r"""
          ________  ______   _______           __
         /  _/ __ \/ ____/  / ____(_)___  ____/ /__  _____
         / // / / / /      / /_  / / __ \/ __  / _ \/ ___/
       _/ // /_/ / /___   / __/ / / / / / /_/ /  __/ /
      /___/\____/\____/  /_/   /_/_/ /_/\__,_/\___/_/
    """

    console.print(f"[cyan]{banner}")

    # Check if Python version is 3.8 or higher
    if sys.version_info[:2] < (3, 8):
        sys.exit("\nPlease use Python version 3.8 or higher.\n")

    # Check if the platform is Windows
    if platform.system() != "Windows":
        sys.exit("Sorry, script is optimized for Windows systems only.")

    worker = Workers()
    iocs_file = worker.iocs_file()

    parser = ArgumentParser()

    parser.add_argument("path", type=Path, help="Path to search")
    parser.add_argument("-c", action="store_true", help="name contains string")

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-i", nargs="+", type=str, metavar="", help="single or list of IOCs (comma separated)")
    group.add_argument("-f", action="store_true", default=iocs_file, help="use known_iocs.txt file containing IOCs")

    args = parser.parse_args()

    main(drivepath=args.path, contains=args.c, ioc=args.i, infile=args.f)
