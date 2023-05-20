"""Quick and dirty method to search for filenames that match IOCs if hashes are not yet available."""

import contextlib
import csv
import hashlib
import os
import platform
import socket
import sys
from argparse import ArgumentParser
from collections.abc import Iterator
from datetime import datetime
from functools import partial
from pathlib import Path
from typing import IO
from zoneinfo import ZoneInfo

from colorama import Fore
from rich.console import Console
from rich.table import Table
from tqdm import tqdm

# Initialize rich console
console = Console()


class Workers:
    """Returns number of matches found."""

    def __init__(self: "Workers") -> None:
        """Initializes a count, filepath, output, IOCs file, and hostname."""
        self.count = 0
        self.filepath = Path(__file__).parent
        self.output = self.filepath / "results"
        self.iocs = self.filepath / "iocs"
        self.hostname = socket.gethostname().upper()

    def iocs_file(self: "Workers") -> Path:
        """Get the path to the file containing the known IOCs.

        Returns:
            Path: the path to the file containing the known IOCs.
        """
        return self.iocs / "known_iocs.txt"

    def check_iocs_file(self: "Workers") -> bool | None:
        """Check if the IOCs file contains IOCs."""
        first_line = "# ADD IOC FILENAMES BELOW THIS LINE"
        with open(self.iocs_file(), encoding="utf-8") as file:
            lines = file.readlines()

        # Check if line is present after first line
        return next(
            (
                any(next_line.strip() for next_line in lines[index + 1 :])
                for index, line in enumerate(lines)
                if first_line in line
            ),
            False,
        )

    def save_iocs_csv(self: "Workers") -> Path:
        """Creates the `results` folder and CSV file.

        Returns:
            Path: The path to the file that will be created.
        """
        self.output.mkdir(parents=True, exist_ok=True)
        timestr = datetime.now(ZoneInfo("UTC")).strftime("%Y%m%d-%H%M%S")
        return self.output / f"{self.hostname}_{timestr}.csv"

    def sha256(self: "Workers", fname: str) -> str:
        """Returns the SHA256 hash of a file.

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

    def read_file(self: "Workers") -> list[str]:
        """Reads the IOCs file.

        Returns:
            A list of strings represnting the IOCs.
        """
        with open(self.iocs_file(), encoding="utf-8") as fileobj:
            try:
                next(fileobj)  # skip file header starting with '#'
            except StopIteration:
                return []  # return an empty list in the case where the file is empty
            return [dataobj.strip() for dataobj in fileobj]  # Iterate directly over the fileobj


def ptable_to_term() -> None:
    """Output latest csv file to terminal."""
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
    """If the file is less than 25 bytes, remove it."""
    # Remove empty results - not the best method, but it works
    csv_files = Path(worker.output).glob("*.csv")
    files = [csv for csv in csv_files if csv.is_file()]
    bytes_size = 25
    for filename in files:
        if Path(filename).stat().st_size < bytes_size:
            Path(filename).unlink()


def scantree(path: str) -> Iterator[str]:
    """Recursively scans a directory tree and returns a generator of all the files in the tree.

    Args:
        path (str): The path to the directory you want to scan

    Yields:
         Iterator[str]: A generator of all the files in the tree.
    """
    with os.scandir(path) as entries:
        for entry in entries:
            with contextlib.suppress(PermissionError, FileNotFoundError):
                if not entry.name.startswith(".") and entry.is_dir(follow_symlinks=False):
                    yield from scantree(entry.path)
                else:
                    yield entry.path


def process_filepath(filepath: str, ioc: list[str], contains: bool, writer: csv.DictWriter) -> None:
    """Searches for matches between the IOCs and the file path.

    Args:
        filepath (str): Path of the file being processed.
        ioc (list[str]): List of strings representing Indicators of Compromise (IOCs).
        contains (bool): Determines whether the search for IOCs should match on partial or exact matches.
        writer (DictWriter): Used to write rows to the CSV file.
    """
    path = Path(filepath)
    for line in ioc:
        clean_line = line.strip(",")
        filematch = path.match(f"*{clean_line}*") if contains else path.match(f"{clean_line}*")
        if filematch:
            with contextlib.suppress(OSError):
                created = datetime.fromtimestamp(path.stat().st_ctime, ZoneInfo("UTC"))
                size = path.stat().st_size
                writer.writerow(
                    {
                        "Path": path,
                        "Size": size,
                        "Created": f"{created:%Y-%m-%d}",
                        "Hash": worker.sha256(str(path)),
                    },
                )

    worker.count += 1


def ioc_processor(ioc: list[str], drivepath: str, contains: bool) -> None:
    """Process the IOCs.

    Args:
        ioc (list[str]): List of IOCs to search for.
        drivepath (str): The path to the drive you want to scan.
        contains (bool): Determines whether the search for IOCs should match on partial or exact matches.
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


def process_filename(writer: csv.DictWriter, root: str, filename: str, ioc_obj_lower: set[str]) -> None:
    """Searches for matches between the IOCs and the file name.

    Args:
        writer (DictWriter): Used to write rows to the CSV file.
        root (str): The path to the directory you want to scan.
        filename (str): The name of the file being processed.
        ioc_obj_lower (set[str]): A set of strings representing Indicators of Compromise (IOCs).
    """
    filename_words = filename.lower().split()
    for word in filename_words:
        if word in ioc_obj_lower:
            with contextlib.suppress(OSError):
                path = Path(root) / filename
                stat = path.stat()
                created = datetime.fromtimestamp(stat.st_ctime, ZoneInfo("UTC"))
                size = stat.st_size
                worker.count += 1
                writer.writerow(
                    {
                        "Path": path,
                        "Size": size,
                        "Created": f"{created:%Y-%m-%d}",
                        "Hash": worker.sha256(str(path)),
                    },
                )


def ioc_file_processor(drivepath: str) -> None:
    """Process the IOCs file.

    Args:
        drivepath (str): The path to the drive you want to scan.
    """
    if not worker.check_iocs_file():
        sys.exit(f"\n Missing IOCs -- file appears to be empty: {worker.iocs_file()}\n")

    ioc_obj = worker.read_file()

    # Create a set of the IOCs in lowercase
    ioc_obj_lower = {name.lower() for name in ioc_obj}

    with open(worker.save_iocs_csv(), "w", newline="", encoding="utf-8") as csvfile:
        # Create the header row
        writer = csv.DictWriter(csvfile, fieldnames=["Path", "Size", "Created", "Hash"])
        writer.writeheader()

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
                    process_filename(writer, root, filename, ioc_obj_lower)

        except KeyboardInterrupt:
            abort_output(csvfile)

        finally:
            csvfile.close()


def write_to_csv(csvfile: IO[str]) -> csv.DictWriter:
    """Creates the CSV file and writes the header row.

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
    """Closes the CSV file, removes the CSV file, and exits the program.

    Args:
        csvfile (IO[str]): The file object that is being written to.
    """
    csvfile.close()
    remove_output()
    sys.exit("\nAborted!")


def main(drivepath: str, ioc: list[str], contains: bool = False, infile: bool = False) -> None:
    """Processes IOCs from a given drive path or file and saves the results to a CSV file.

    Args:
        drivepath (str): Path to the directory or file to be processed.
        ioc (list[str]): A list of strings representing Indicators of Compromise (IOCs) to search for.
        contains (bool): Determines whether the search for IOCs should match on partial or exact matches.
        infile (bool): Indicates whether the input file should be processed.
    """
    worker.count = 0
    if ioc:
        ioc_processor(ioc, drivepath, contains)
    elif infile:
        ioc_file_processor(drivepath)

    if worker.count:
        console.print(f"\n Found {worker.count} IOCs on {worker.hostname}")

        # Get the last CSV file in the results folder
        last_csv_file = max(Path("results").iterdir(), key=lambda x: x.stat().st_mtime)
        print(f" --> Results saved to {last_csv_file}\n")

        # Open the CSV file and print the contents to the terminal
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
    group.add_argument(
        "-i",
        nargs="+",
        type=str,
        metavar="",
        help="single or list of IOCs (comma separated)",
    )
    group.add_argument(
        "-f",
        action="store_true",
        default=iocs_file,
        help="use known_iocs.txt file containing IOCs",
    )

    args = parser.parse_args()

    main(drivepath=args.path, contains=args.c, ioc=args.i, infile=args.f)
