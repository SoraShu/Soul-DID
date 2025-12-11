#!/usr/bin/env python3
"""
Issuer CLI - Interactive command line tool for VC issuers
"""

import sys
import time
from prompt_toolkit import PromptSession, HTML
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.styles import Style
from prompt_toolkit.history import FileHistory
from web3 import Web3
from rich.panel import Panel
from rich.table import Table

import config
from utils import (
    get_web3,
    get_contracts,
    load_account,
    sign_message,
    format_timestamp,
    print_did_info,
    console,
)

style = Style.from_dict(
    {
        "prompt": "#ff8800 bold",
    }
)

COMMANDS = [
    "help",
    "exit",
    "quit",
    "status",
    "lookup",
    "sign-vc",
    "check",
    "list-vc-types",
]


class IssuerCLI:
    def __init__(self):
        self.w3 = None
        self.contracts = None
        self.account = None
        self.private_key = None
        self.session = PromptSession(
            history=FileHistory(".issuer_cli_history"),
            completer=WordCompleter(COMMANDS, ignore_case=True),
        )

    def start(self):
        """Start the interactive CLI"""
        self._print_banner()
        self._connect()
        self._login()
        self._main_loop()

    def _print_banner(self):
        console.print(
            Panel(
                "[bold yellow]VC Issuer CLI[/bold yellow]\n"
                "Sign and manage Verifiable Credentials",
                title="Welcome",
                border_style="yellow",
            )
        )

    def _connect(self):
        """Connect to blockchain"""
        try:
            self.w3 = get_web3()
            self.contracts = get_contracts(self.w3)
            console.print(f"[green]✓ Connected to {config.RPC_URL}[/green]")
        except Exception as e:
            console.print(f"[red]Failed to connect: {e}[/red]")
            sys.exit(1)

    def _login(self):
        """Prompt for issuer private key"""
        console.print("\n[yellow]Please enter your issuer wallet private key.[/yellow]")
        console.print("[dim]This key is used to sign VCs for DID holders.[/dim]\n")

        _, issuer_registry, _, _ = self.contracts

        while True:
            try:
                private_key = self.session.prompt(
                    HTML("<prompt>Enter Private Key: </prompt>"), is_password=True
                )

                if not private_key:
                    console.print("[red]Private key is required[/red]")
                    continue

                self.private_key = private_key
                self.account = load_account(private_key)
                balance = self.w3.eth.get_balance(self.account.address)

                console.print(
                    f"\n[green]✓ Logged in as:  {self.account.address}[/green]"
                )
                console.print(
                    f"[green]✓ Balance: {self.w3.from_wei(balance, 'ether')} ETH[/green]"
                )

                # Check if registered issuer
                is_valid = issuer_registry.functions.isValidIssuer(
                    self.account.address
                ).call()
                if is_valid:
                    info = issuer_registry.functions.getIssuerInfo(
                        self.account.address
                    ).call()
                    console.print(f"[green]✓ Registered Issuer: {info[0]}[/green]")
                else:
                    console.print("[red]✗ You are NOT a registered issuer![/red]")
                    console.print(
                        "[yellow]Contact the admin to get registered.[/yellow]"
                    )

                break

            except Exception as e:
                console.print(f"[red]Invalid private key: {e}[/red]")

    def _main_loop(self):
        """Main command loop"""
        console.print(
            "\n[cyan]Type 'help' for available commands, 'exit' to quit.[/cyan]\n"
        )

        while True:
            try:
                user_input = self.session.prompt(
                    HTML("<prompt>issuer> </prompt>"), style=style, is_password=False
                ).strip()

                if not user_input:
                    continue

                parts = user_input.split()
                command = parts[0].lower()
                args = parts[1:]

                if command in ["exit", "quit"]:
                    console.print("[yellow]Goodbye![/yellow]")
                    break
                elif command == "help":
                    self._show_help()
                elif command == "status":
                    self._show_status()
                elif command == "lookup":
                    self._lookup_did(args)
                elif command == "sign-vc":
                    self._sign_vc(args)
                elif command == "check":
                    self._check_verification(args)
                elif command == "list-vc-types":
                    self._list_vc_types()
                else:
                    console.print(f"[red]Unknown command:  {command}[/red]")

            except KeyboardInterrupt:
                continue
            except EOFError:
                break
            except Exception as e:
                console.print(f"[red]Error: {e}[/red]")

    def _show_help(self):
        """Show help message"""
        table = Table(title="Available Commands")
        table.add_column("Command", style="cyan")
        table.add_column("Description", style="green")

        commands = [
            ("help", "Show this help message"),
            ("exit / quit", "Exit the CLI"),
            ("", ""),
            ("status", "Check your issuer status"),
            ("lookup <address|token_id>", "Look up a DID"),
            ("sign-vc [token_id] [days]", "Sign an AgeOver18 VC"),
            ("check [token_id]", "Check verification status of a DID"),
            ("list-vc-types", "List all available VC types"),
        ]

        for cmd, desc in commands:
            table.add_row(cmd, desc)

        console.print(table)

    def _show_status(self):
        """Show issuer status"""
        _, issuer_registry, _, _ = self.contracts

        is_valid = issuer_registry.functions.isValidIssuer(self.account.address).call()

        if is_valid:
            info = issuer_registry.functions.getIssuerInfo(self.account.address).call()
            name, description, is_active, registered_at = info

            console.print(
                Panel(
                    f"[green]✓ You are a registered issuer[/green]\n\n"
                    f"Address: {self.account.address}\n"
                    f"Name:  {name}\n"
                    f"Description: {description}\n"
                    f"Status: {'[green]Active[/green]' if is_active else '[red]Inactive[/red]'}\n"
                    f"Registered:  {format_timestamp(registered_at)}",
                    title="Issuer Status",
                )
            )
        else:
            console.print(
                Panel(
                    f"[red]✗ You are NOT a registered issuer[/red]\n\n"
                    f"Address: {self.account.address}\n"
                    f"Contact the admin to get registered.",
                    title="Issuer Status",
                )
            )

    def _lookup_did(self, args):
        """Look up a DID"""
        did_contract = self.contracts[0]

        if not args:
            arg = self.session.prompt(
                HTML("<prompt>Enter address or token ID: </prompt>")
            ).strip()
        else:
            arg = args[0]

        if not arg:
            console.print("[red]Address or token ID is required[/red]")
            return

        try:
            if arg.startswith("0x") and len(arg) == 42:
                address = Web3.to_checksum_address(arg)
                token_id = did_contract.functions.getDIDByAddress(address).call()
                if token_id == 0:
                    console.print(
                        f"[yellow]No DID found for address: {address}[/yellow]"
                    )
                    return
            else:
                token_id = int(arg)

            did_info = did_contract.functions.getDIDInfo(token_id).call()
            print_did_info(did_info, token_id)

        except Exception as e:
            console.print(f"[red]Error:  {e}[/red]")

    def _sign_vc(self, args):
        """Sign an AgeOver18 VC"""
        _, issuer_registry, _, _ = self.contracts
        did_contract = self.contracts[0]

        # Check if issuer is valid
        is_valid = issuer_registry.functions.isValidIssuer(self.account.address).call()
        if not is_valid:
            console.print("[red]You are not a registered issuer![/red]")
            return

        # Get token ID
        if args:
            token_id = int(args[0])
        else:
            token_id_str = self.session.prompt(
                HTML("<prompt>Enter DID Token ID: </prompt>")
            ).strip()
            if not token_id_str:
                console.print("[red]Token ID is required[/red]")
                return
            token_id = int(token_id_str)

        # Get expiration days
        if len(args) >= 2:
            expires_days = int(args[1])
        else:
            expires_days_str = self.session.prompt(
                HTML("<prompt>Expiration days [365]: </prompt>")
            ).strip()
            expires_days = int(expires_days_str) if expires_days_str else 365
        
        # Get VC data
        if len(args) >= 3:
            vc_data = bytes(args[2], "utf-8")
        else:
            vc_data_str = self.session.prompt(
                HTML("<prompt>VC Data [default empty]: </prompt>")
            ).strip()
            vc_data = bytes(vc_data_str, "utf-8") if vc_data_str else b""

        # Check if DID exists
        try:
            did_info = did_contract.functions.getDIDInfo(token_id).call()
            did_owner = did_info[3]
            did_public_key = did_info[0]
        except Exception:
            console.print("[red]DID does not exist![/red]")
            return

        # Show DID info
        console.print(
            Panel(
                f"DID Token ID: {token_id}\n"
                f"DID Owner: {did_owner}\n"
                f"DID Public Key: 0x{did_public_key.hex()[:40]}...\n"
                f"VC Data: {vc_data.decode('utf-8', errors='ignore')}\n"
                f"Expiration: {expires_days} days",
                title="Signing VC for",
            )
        )

        # Confirm signing
        confirm = (
            self.session.prompt(HTML("<prompt>Confirm signing? (yes/no): </prompt>"))
            .strip()
            .lower()
        )

        if confirm != "yes":
            console.print("[yellow]Cancelled.[/yellow]")
            return

        # Calculate expiration
        expires_at = int(time.time()) + (expires_days * 24 * 60 * 60)

        # Get verifier address and VC type
        verifier_address = Web3.to_checksum_address(config.AGE_VERIFIER)
        vc_type = "AgeOver18"

        message_hash = Web3.solidity_keccak(
            ['address', 'string', 'uint256', 'address', 'uint256', 'bytes'],
            [
                verifier_address,
                vc_type,
                token_id,
                self.account.address,
                expires_at,
                vc_data
            ]
        )

        # Sign the message
        signature = sign_message(message_hash, self.private_key)

        console.print(
            Panel(
                f"[green]VC Signed Successfully![/green]\n\n"
                f"VC Type: AgeOver18\n"
                f"VC Data: {vc_data.decode('utf-8', errors='ignore')}\n"
                f"DID Token ID: {token_id}\n"
                f"DID Owner: {did_owner}\n"
                f"Issuer: {self.account.address}\n"
                f"Expires At: {format_timestamp(expires_at)}\n"
                f"Expires Timestamp: {expires_at}",
                title="Signed VC",
            )
        )

        console.print("\n[cyan]━━━ Send the following to the DID holder ━━━[/cyan]")
        console.print(f"Issuer: {self.account.address}")
        console.print(f"Expires:  {expires_at}")
        console.print(f"Signature: 0x{signature.hex()}")
        console.print("[cyan]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/cyan]")

        console.print("\n[dim]They can submit with command:[/dim]")
        console.print(
            f"  submit-vc {self.account.address} {expires_at} 0x{signature.hex()} {vc_data.decode('utf-8', errors='ignore')}"
        )

    def _check_verification(self, args):
        """Check verification status of a DID"""
        _, _, age_verifier, _ = self.contracts

        # Get token ID
        if args:
            token_id = int(args[0])
        else:
            token_id_str = self.session.prompt(
                HTML("<prompt>Enter DID Token ID: </prompt>")
            ).strip()
            if not token_id_str:
                console.print("[red]Token ID is required[/red]")
                return
            token_id = int(token_id_str)

        has_valid = age_verifier.functions.hasValidVerification(token_id).call()

        if has_valid:
            record = age_verifier.functions.getVerification(token_id).call()
            console.print(
                Panel(
                    f"[green]✓ DID has valid AgeOver18 verification[/green]\n\n"
                    f"Token ID: {record[0]}\n"
                    f"Issuer: {record[1]}\n"
                    f"Verified At: {format_timestamp(record[2])}\n"
                    f"Expires At: {format_timestamp(record[3])}\n"
                    f"Is Valid: {record[4]}",
                    title="Verification Status",
                )
            )
        else:
            console.print(
                Panel(
                    "[yellow]✗ DID does NOT have valid AgeOver18 verification[/yellow]",
                    title="Verification Status",
                )
            )

    def _list_vc_types(self):
        """List all available VC types"""
        _, _, _, verifier_registry = self.contracts

        vc_types = verifier_registry.functions.getAllVCTypes().call()

        table = Table(title="Available VC Types")
        table.add_column("VC Type", style="cyan")
        table.add_column("Description", style="green")

        for vc_type in vc_types:
            desc = "Verifies user is 18+ years old" if vc_type == "AgeOver18" else "N/A"
            table.add_row(vc_type, desc)

        console.print(table)


def main():
    cli = IssuerCLI()
    cli.start()


if __name__ == "__main__":
    main()
