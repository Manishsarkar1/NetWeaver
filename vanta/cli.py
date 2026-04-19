import argparse
import sys


def _controller_path():
    import ultimate_mtd_controller

    return ultimate_mtd_controller.__file__


def run_controller():
    from ryu.cmd import manager

    controller_path = str(_controller_path())
    sys.argv = ["ryu-manager", controller_path]
    manager.main()


def print_paths():
    print(f"controller={_controller_path()}")


def main():
    parser = argparse.ArgumentParser(description="VANTA packaging entrypoint")
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("controller", help="Run the VANTA OpenFlow controller")
    subparsers.add_parser("paths", help="Print key packaged paths")

    args = parser.parse_args()
    command = args.command or "controller"

    if command == "paths":
        print_paths()
        return
    if command == "controller":
        run_controller()
        return
    parser.error(f"Unsupported command: {command}")
