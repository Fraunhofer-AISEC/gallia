from argparse import Namespace
from subprocess import run

from gallia.udscan.core import GalliaBase


def run_wrapper(cmd: list[str], sudo: bool = False) -> None:
    if sudo:
        run(cmd, check=True)
    else:
        run(["sudo"] + cmd, check=True)


def nft_enable_nat(*, sudo: bool = False) -> None:
    run_wrapper(["nft", "add table nat"], sudo)
    run_wrapper(
        ["nft", "add chain nat prerouting { type nat hook prerouting priority 0; }"],
        sudo,
    )
    run_wrapper(
        ["nft", "add chain nat postrouting { type nat hook postrouting priority 0; }"],
        sudo,
    )
    run_wrapper(["nft", "add rule nat postrouting oif $NAT_IFACE masquerade"], sudo)


def nft_flush_ruleset(*, sudo: bool = False) -> None:
    run_wrapper(["nft", "delete table nat"], sudo)


def sysctl_set_routing(enabled: bool, *, sudo: bool = False) -> None:
    bool_arg = "1" if enabled else "0"
    run_wrapper(["sysctl", f"net.ipv4.ip_forward={bool_arg}"], sudo)


def ip_add_address(iface: str, addr: str, *, sudo: bool = False) -> None:
    run_wrapper(["ip", "addr", "add", addr, "dev", iface], sudo)


def ip_del_address(iface: str, addr: str, *, sudo: bool = False) -> None:
    run_wrapper(["ip", "addr", "del", addr, "dev", iface], sudo)


def ip_enable_iface(iface: str, enabled: bool, *, sudo: bool = False) -> None:
    bool_arg = "up" if enabled else "down"
    run_wrapper(["ip", "link", "set", iface, bool_arg], sudo)


def nm_set_managed(iface: str, enabled: bool, *, sudo: bool = False) -> None:
    bool_arg = "yes" if enabled else "no"
    run_wrapper(["nmcli", "dev", "set", iface, "managed", bool_arg], sudo)


# TODO: Add a sync version of GalliaBase
class DHCPServer(GalliaBase):
    """This script spawns dnsmasq as a DHCP and DNS server.
    Routing and NAT is set up automatically.
    """

    def add_parser(self) -> None:
        dns_group = self.parser.add_mutually_exclusive_group()
        dns_group.add_argument(
            "-d",
            "--dns",
            help="announce a different DNS server",
        )
        dns_group.add_argument(
            "--log-dns",
            action="store_true",
            help="log DNS queries",
        )
        self.parser.add_argument(
            "-i",
            "--iface",
            required=True,
            help="run DHCP on this interface",
        )
        self.parser.add_argument(
            "-n",
            "--network-manager",
            action="store_true",
            help="notify networkmanager to ignore the interface",
        )
        self.parser.add_argument(
            "--log-dhcp",
            action="store_true",
            help="log DHCP traffic",
        )
        self.parser.add_argument(
            "-z",
            "--ethers",
            action="store_true",
            help="read /etc/ethers",
        )
        self.parser.add_argument(
            "-a",
            "--ip-address",
            default="192.168.100.1/24",
            help="IP address of the dhcp network interface",
        )
        self.parser.add_argument(
            "-r",
            "--range",
            default="192.168.100.50,192.168.100.100,12h",
            help="DHCP range; e.g. 192.168.100.50,192.168.100.100,12h",
        )
        self.parser.add_argument(
            "-o",
            "--outgoing",
            help="route traffic through this network interface",
        )
        self.parser.add_argument(
            "--skip-nat",
            action="store_true",
            help="dnsmasq only; skip NAT setup",
        )
        self.parser.add_argument(
            "--sudo",
            action="store_true",
            help="run all commands with sudo",
        )

    async def setup(self, args: Namespace) -> None:
        if args.skip_nat is False:
            sysctl_set_routing(True, sudo=args.sudo)
            nft_enable_nat(sudo=args.sudo)

        # Avoid that networkmanager re-configures this interface.
        if args.network_manager:
            nm_set_managed(args.iface, False, sudo=args.sudo)

        # Configure ethernet card
        ip_add_address(args.ip_address, args.iface, sudo=args.sudo)
        ip_enable_iface(args.iface, True, sudo=args.sudo)

    async def teardown(self, args: Namespace) -> None:
        if args.skip_nat is False:
            sysctl_set_routing(False, sudo=args.sudo)

            # TODO: Only remove NAT stuff. Do not flush everything.
            nft_flush_ruleset(sudo=args.sudo)

        ip_del_address(args.ip_address, args.iface, sudo=args.sudo)
        ip_enable_iface(args.iface, False, sudo=args.sudo)

        if args.network_manager:
            nm_set_managed(args.iface, True, sudo=args.sudo)

    async def main(self, args: Namespace) -> None:
        dnsmasq_args = [
            f"--interface={args.interface}",
            "--except-interface=lo",
            "--bind-interfaces",
            "--dhcp-authoritative",
            f"--dhcp-range={args.range}",
            "--no-daemon",
        ]

        if args.dns is not None:
            dnsmasq_args.append(f"--dhcp-option=6,{args.dns}")  # RFC 2132, DNS option
        if args.ethers:
            dnsmasq_args.append("--read-ethers")
        if args.log_dns:
            dnsmasq_args.append("--log-queries")
        if args.log_dhcp:
            dnsmasq_args.append("--log-dhcp")

        run_wrapper(["dnsmasq"] + dnsmasq_args)
