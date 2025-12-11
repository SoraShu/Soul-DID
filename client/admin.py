#!/usr/bin/env python3
"""
Admin CLI - Interactive command line tool for DID system administrators
"""

import sys
from prompt_toolkit import PromptSession, HTML
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.styles import Style
from web3 import Web3
from rich.panel import Panel
from rich.table import Table

import config
from utils import (
    get_web3,
    get_contracts,
    load_account,
    format_timestamp,
    send_transaction,
    console,
)

style = Style.from_dict(
    {
        "prompt": "#ff0000 bold",
    }
)

COMMANDS = [
    "help",
    "exit",
    "quit",
    "system-info",
    "add-issuer",
    "remove-issuer",
    "activate-issuer",
    "list-issuers",
    "issuer-info",
    "lookup-user",
]


class AdminCLI:
    def __init__(self):
        self.w3 = None
        self.contracts = None
        self.account = None
        self.private_key = None
        self.session = PromptSession(
            # history=FileHistory(".admin_cli_history"),
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
                "[bold red]DID Admin CLI[/bold red]\n"
                "Manage the Decentralized Identity System",
                title="Welcome",
                border_style="red",
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
        """Prompt for admin private key"""
        console.print("\n[yellow]Please enter the admin wallet private key.[/yellow]")
        console.print("[dim]This key must have admin role on the contracts.[/dim]\n")

        while True:
            try:
                private_key = self.session.prompt(
                    HTML("<prompt>Enter Admin Private Key: </prompt>"), is_password=True
                )

                if not private_key:
                    console.print("[red]Private key is required[/red]")
                    continue

                self.private_key = private_key
                self.account = load_account(private_key)
                balance = self.w3.eth.get_balance(self.account.address)

                console.print(
                    f"\n[green]✓ Logged in as: {self.account.address}[/green]"
                )
                console.print(
                    f"[green]✓ Balance: {self.w3.from_wei(balance, 'ether')} ETH[/green]"
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
                    HTML("<prompt>admin> </prompt>"), style=style, is_password=False
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
                elif command == "system-info":
                    self._system_info()
                elif command == "add-issuer":
                    self._add_issuer(args)
                elif command == "remove-issuer":
                    self._remove_issuer(args)
                elif command == "activate-issuer":
                    self._activate_issuer(args)
                elif command == "list-issuers":
                    self._list_issuers()
                elif command == "issuer-info":
                    self._issuer_info(args)
                elif command == "lookup-user":
                    self._lookup_user(args)
                else:
                    console.print(
                        f"[red]Unknown command: {command}. Type 'help' for available commands.[/red]"
                    )

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
            ("[bold]System[/bold]", ""),
            ("system-info", "Show system contract info and statistics"),
            ("", ""),
            ("[bold]Issuer Management[/bold]", ""),
            ("add-issuer [address]", "Register a new trusted issuer"),
            ("remove-issuer [address]", "Deactivate an issuer"),
            ("activate-issuer [address]", "Reactivate an issuer"),
            ("list-issuers", "List all registered issuers"),
            ("issuer-info [address]", "Get detailed issuer info"),
            ("", ""),
            ("[bold]User Lookup[/bold]", ""),
            ("lookup-user [address]", "Look up a user's DID and verifications"),
        ]

        for cmd, desc in commands:
            table.add_row(cmd, desc)

        console.print(table)

    def _system_info(self):
        """Show system information"""
        _, issuer_registry, _, verifier_registry = self.contracts

        issuer_count = issuer_registry.functions.getIssuerCount().call()
        vc_types = verifier_registry.functions.getAllVCTypes().call()

        console.print(
            Panel(
                f"[cyan]Contract Addresses:[/cyan]\n"
                f"  DID Contract:       {config.DID_CONTRACT}\n"
                f"  Issuer Registry:    {config.ISSUER_REGISTRY}\n"
                f"  Verifier Registry:  {config.VERIFIER_REGISTRY}\n"
                f"  Age Verifier:       {config.AGE_VERIFIER}\n\n"
                f"[cyan]Network:[/cyan]\n"
                f"  RPC URL:            {config.RPC_URL}\n"
                f"  Chain ID:           {config.CHAIN_ID}\n"
                f"  Latest Block:       {self.w3.eth.block_number}\n\n"
                f"[cyan]Statistics:[/cyan]\n"
                f"  Registered Issuers: {issuer_count}\n"
                f"  VC Types:           {', '.join(vc_types)}",
                title="System Info",
            )
        )

    def _add_issuer(self, args):
        """Add a new issuer"""
        _, issuer_registry, _, _ = self.contracts

        console.print("\n[cyan]Register New Issuer[/cyan]")

        # Get issuer address
        if args:
            issuer_address = args[0]
        else:
            issuer_address = self.session.prompt(
                HTML("<prompt>Issuer Address: </prompt>")
            ).strip()

        if not issuer_address:
            console.print("[red]Address is required[/red]")
            return

        try:
            issuer_address = Web3.to_checksum_address(issuer_address)
        except Exception:
            console.print("[red]Invalid address format[/red]")
            return

        # Check if already registered
        try:
            info = issuer_registry.functions.getIssuerInfo(issuer_address).call()
            if info[3] > 0:  # registeredAt > 0
                if info[2]:  # isActive
                    console.print(
                        f"[yellow]Issuer {issuer_address} is already registered and active[/yellow]"
                    )
                else:
                    console.print(
                        f"[yellow]Issuer {issuer_address} is registered but inactive. Use 'activate-issuer'.[/yellow]"
                    )
                return
        except Exception:
            pass

        name = self.session.prompt(HTML("<prompt>Issuer Name: </prompt>")).strip()

        if not name:
            console.print("[red]Name is required[/red]")
            return

        description = self.session.prompt(
            HTML("<prompt>Description (optional): </prompt>")
        ).strip()

        console.print(
            Panel(
                f"Address: {issuer_address}\n"
                f"Name: {name}\n"
                f"Description: {description if description else 'N/A'}",
                title="New Issuer",
            )
        )

        confirm = (
            self.session.prompt(
                HTML("<prompt>Confirm registration? (yes/no): </prompt>")
            )
            .strip()
            .lower()
        )

        if confirm != "yes":
            console.print("[yellow]Cancelled.[/yellow]")
            return

        try:
            _ = send_transaction(
                self.w3,
                issuer_registry.functions.registerIssuer(
                    issuer_address, name, description
                ),
                self.account,
            )
            console.print("[green]Issuer registered successfully![/green]")

        except Exception as e:
            console.print(f"[red]Failed to register issuer: {e}[/red]")

    def _remove_issuer(self, args):
        """Deactivate an issuer"""
        _, issuer_registry, _, _ = self.contracts

        if args:
            issuer_address = args[0]
        else:
            issuer_address = self.session.prompt(
                HTML("<prompt>Issuer Address to deactivate: </prompt>")
            ).strip()

        if not issuer_address:
            console.print("[red]Address is required[/red]")
            return

        try:
            issuer_address = Web3.to_checksum_address(issuer_address)
        except Exception:
            console.print("[red]Invalid address format[/red]")
            return

        # Check if registered and active
        is_valid = issuer_registry.functions.isValidIssuer(issuer_address).call()
        if not is_valid:
            console.print(f"[yellow]Issuer {issuer_address} is not active[/yellow]")
            return

        # Get info
        info = issuer_registry.functions.getIssuerInfo(issuer_address).call()

        console.print(
            Panel(
                f"Address: {issuer_address}\nName: {info[0]}\nDescription: {info[1]}",
                title="Deactivating Issuer",
            )
        )

        confirm = (
            self.session.prompt(
                HTML("<prompt>Confirm deactivation? (yes/no): </prompt>")
            )
            .strip()
            .lower()
        )

        if confirm != "yes":
            console.print("[yellow]Cancelled.[/yellow]")
            return

        try:
            _ = send_transaction(
                self.w3,
                issuer_registry.functions.setIssuerStatus(issuer_address, False),
                self.account,
            )
            console.print("[green]Issuer deactivated successfully![/green]")

        except Exception as e:
            console.print(f"[red]Failed to deactivate issuer: {e}[/red]")

    def _activate_issuer(self, args):
        """Reactivate an issuer"""
        _, issuer_registry, _, _ = self.contracts

        if args:
            issuer_address = args[0]
        else:
            issuer_address = self.session.prompt(
                HTML("<prompt>Issuer Address to activate: </prompt>")
            ).strip()

        if not issuer_address:
            console.print("[red]Address is required[/red]")
            return

        try:
            issuer_address = Web3.to_checksum_address(issuer_address)
        except Exception:
            console.print("[red]Invalid address format[/red]")
            return

        # Check if registered
        try:
            info = issuer_registry.functions.getIssuerInfo(issuer_address).call()
            if info[3] == 0:  # registeredAt == 0
                console.print(
                    f"[yellow]Issuer {issuer_address} is not registered. Use 'add-issuer'.[/yellow]"
                )
                return
            if info[2]:  # isActive
                console.print(
                    f"[yellow]Issuer {issuer_address} is already active[/yellow]"
                )
                return
        except Exception as e:
            console.print(f"[red]Error checking issuer:  {e}[/red]")
            return

        console.print(
            Panel(
                f"Address: {issuer_address}\nName: {info[0]}\nDescription: {info[1]}",
                title="Activating Issuer",
            )
        )

        confirm = (
            self.session.prompt(HTML("<prompt>Confirm activation? (yes/no): </prompt>"))
            .strip()
            .lower()
        )

        if confirm != "yes":
            console.print("[yellow]Cancelled.[/yellow]")
            return

        try:
            _ = send_transaction(
                self.w3,
                issuer_registry.functions.setIssuerStatus(issuer_address, True),
                self.account,
            )
            console.print("[green]Issuer activated successfully![/green]")

        except Exception as e:
            console.print(f"[red]Failed to activate issuer: {e}[/red]")

    def _list_issuers(self):
        """List all issuers"""
        _, issuer_registry, _, _ = self.contracts

        count = issuer_registry.functions.getIssuerCount().call()

        if count == 0:
            console.print("[yellow]No issuers registered[/yellow]")
            return

        table = Table(title=f"Registered Issuers ({count} total)")
        table.add_column("#", style="dim")
        table.add_column("Address", style="cyan")
        table.add_column("Name", style="green")
        table.add_column("Status")
        table.add_column("Registered At")

        for i in range(count):
            try:
                issuer_address = issuer_registry.functions.getIssuerAt(i).call()
                info = issuer_registry.functions.getIssuerInfo(issuer_address).call()
                name, description, is_active, registered_at = info

                status = "[green]Active[/green]" if is_active else "[red]Inactive[/red]"
                table.add_row(
                    str(i + 1),
                    f"{issuer_address[:10]}...{issuer_address[-8:]}",
                    name,
                    status,
                    format_timestamp(registered_at),
                )
            except Exception:
                continue

        console.print(table)

    def _issuer_info(self, args):
        """Get detailed issuer info"""
        _, issuer_registry, _, _ = self.contracts

        if args:
            address = args[0]
        else:
            address = self.session.prompt(
                HTML("<prompt>Issuer Address: </prompt>")
            ).strip()

        if not address:
            console.print("[red]Address is required[/red]")
            return

        try:
            address = Web3.to_checksum_address(address)
        except Exception:
            console.print("[red]Invalid address format[/red]")
            return

        try:
            info = issuer_registry.functions.getIssuerInfo(address).call()
            name, description, is_active, registered_at = info

            if registered_at == 0:
                console.print(f"[yellow]Issuer {address} is not registered[/yellow]")
                return

            console.print(
                Panel(
                    f"Address: {address}\n"
                    f"Name: {name}\n"
                    f"Description: {description if description else 'N/A'}\n"
                    f"Status: {'[green]Active[/green]' if is_active else '[red]Inactive[/red]'}\n"
                    f"Registered At: {format_timestamp(registered_at)}",
                    title="Issuer Info",
                )
            )

        except Exception as e:
            console.print(f"[red]Error:  {e}[/red]")

    def _lookup_user(self, args):
        """Look up a user's DID and verifications"""
        did_contract, _, age_verifier, verifier_registry = self.contracts

        if args:
            address = args[0]
        else:
            address = self.session.prompt(
                HTML("<prompt>User Address: </prompt>")
            ).strip()

        if not address:
            console.print("[red]Address is required[/red]")
            return

        try:
            address = Web3.to_checksum_address(address)
        except Exception:
            console.print("[red]Invalid address format[/red]")
            return

        # Get DID
        token_id = did_contract.functions.getDIDByAddress(address).call()

        if token_id == 0:
            console.print(f"[yellow]No DID found for {address}[/yellow]")
            return

        # Get DID info
        try:
            did_info = did_contract.functions.getDIDInfo(token_id).call()
            public_key, created_at, did_document, owner = did_info

            console.print(
                Panel(
                    f"[cyan]DID Info:[/cyan]\n"
                    f"  Token ID:     {token_id}\n"
                    f"  Owner:        {owner}\n"
                    f"  Public Key:   0x{public_key.hex()[:40]}...\n"
                    f"  Created At:   {format_timestamp(created_at)}\n"
                    f"  DID Document: {did_document if did_document else 'N/A'}",
                    title=f"User Lookup:  {address}",
                )
            )
        except Exception as e:
            console.print(f"[red]Error getting DID info: {e}[/red]")
            return

        # Get verifications
        try:
            result = verifier_registry.functions.getVerificationsByAddress(
                address
            ).call()
            _, vc_types, has_verifications, records = result

            table = Table(title="Verifications")
            table.add_column("VC Type", style="cyan")
            table.add_column("Status")
            table.add_column("Issuer")
            table.add_column("Verified At")
            table.add_column("Expires At")

            for i, vc_type in enumerate(vc_types):
                if has_verifications[i]:
                    record = records[i]
                    table.add_row(
                        vc_type,
                        "[green]✓ Verified[/green]",
                        f"{record[1][:10]}...",
                        format_timestamp(record[2]),
                        format_timestamp(record[3]),
                    )
                else:
                    table.add_row(vc_type, "[red]✗ Not Verified[/red]", "-", "-", "-")

            console.print(table)

        except Exception as e:
            console.print(f"[red]Error getting verifications: {e}[/red]")


def main():
    cli = AdminCLI()
    cli.start()


if __name__ == "__main__":
    main()
