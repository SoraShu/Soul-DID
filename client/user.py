#!/usr/bin/env python3
"""
DID User CLI - Interactive command line tool for DID holders
"""

import sys
from prompt_toolkit import PromptSession, HTML
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.styles import Style
from prompt_toolkit.history import FileHistory
from web3 import Web3
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

import config
from utils import (
    get_web3, get_contracts, load_account, sign_message,
    generate_challenge, format_timestamp, print_did_info,
    print_verification_info, send_transaction, DIDKeyManager
)

console = Console()

style = Style.from_dict({
    'prompt': '#00aa00 bold',
})

COMMANDS = [
    'help', 'exit', 'quit',
    'mint', 'info', 'status',
    'generate-challenge', 'sign-challenge', 'verify-challenge',
    'submit-vc', 'check-vc',
    'generate-keys', 'show-keys', 'import-keys'
]


class UserCLI:
    def __init__(self):
        self.w3 = None
        self.contracts = None
        self.account = None
        self.private_key = None
        self.key_manager = DIDKeyManager()
        self.session = PromptSession(
            history=FileHistory('.user_cli_history'),
            completer=WordCompleter(COMMANDS, ignore_case=True)
        )

    def start(self):
        """Start the interactive CLI"""
        self._print_banner()
        self._connect()
        self._login()
        self._main_loop()

    def _print_banner(self):
        console.print(Panel(
            "[bold cyan]DID User CLI[/bold cyan]\n"
            "Manage your Decentralized Identity",
            title="Welcome",
            border_style="cyan"
        ))

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
        """Prompt for wallet private key"""
        console.print("\n[yellow]Please enter your wallet private key to login.[/yellow]")
        console.print("[dim]This is used to sign transactions (mint DID, submit VC, etc. )[/dim]")
        console.print("[dim]Your DID keys are separate and managed locally.[/dim]\n")

        while True: 
            try:
                # 私钥使用密码输入模式
                private_key = self.session.prompt(
                    HTML('<prompt>Enter Private Key: </prompt>'),
                    is_password=True
                )

                if not private_key:
                    console.print("[red]Private key is required[/red]")
                    continue

                self.private_key = private_key
                self.account = load_account(private_key)
                balance = self.w3.eth.get_balance(self.account.address)

                console.print(f"\n[green]✓ Logged in as:  {self.account.address}[/green]")
                console.print(f"[green]✓ Balance: {self.w3.from_wei(balance, 'ether')} ETH[/green]")

                # Check if has DID
                did_contract = self.contracts[0]
                token_id = did_contract.functions.getDIDByAddress(self.account.address).call()
                if token_id > 0:
                    console.print(f"[green]✓ DID Token ID: {token_id}[/green]")
                    # 显示 DID 公钥
                    did_info = did_contract.functions.getDIDInfo(token_id).call()
                    public_key = did_info[0]
                    console.print(f"[green]✓ DID Public Key: 0x{public_key.hex()[:40]}...[/green]")
                else:
                    console.print("[yellow]!  You don't have a DID yet. Use 'mint' to create one.[/yellow]")

                # Check if has local DID keys
                if self.key_manager.has_key_pair(self.account.address):
                    console.print("[green]✓ DID keys found locally[/green]")
                else:
                    console.print("[yellow]! No local DID keys. Use 'generate-keys' or 'import-keys'.[/yellow]")

                break

            except Exception as e: 
                console.print(f"[red]Invalid private key: {e}[/red]")

    def _main_loop(self):
        """Main command loop"""
        console.print("\n[cyan]Type 'help' for available commands, 'exit' to quit.[/cyan]\n")

        while True: 
            try: 
                user_input = self.session.prompt(
                    HTML('<prompt>user> </prompt>'),
                    style=style,
                    is_password=False
                ).strip()

                if not user_input:
                    continue

                parts = user_input.split()
                command = parts[0].lower()
                args = parts[1:]

                if command in ['exit', 'quit']:
                    console.print("[yellow]Goodbye![/yellow]")
                    break
                elif command == 'help': 
                    self._show_help()
                elif command == 'mint':
                    self._mint_did(args)
                elif command == 'info':
                    self._show_info(args)
                elif command == 'status':
                    self._show_status()
                elif command == 'generate-challenge': 
                    self._generate_challenge()
                elif command == 'sign-challenge':
                    self._sign_challenge(args)
                elif command == 'verify-challenge':
                    self._verify_challenge(args)
                elif command == 'submit-vc':
                    self._submit_vc(args)
                elif command == 'check-vc':
                    self._check_vc(args)
                elif command == 'generate-keys':
                    self._generate_keys()
                elif command == 'show-keys': 
                    self._show_keys()
                elif command == 'import-keys':
                    self._import_keys()
                else: 
                    console.print(f"[red]Unknown command: {command}. Type 'help' for available commands.[/red]")

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
            ("[bold]DID Key Management[/bold]", ""),
            ("generate-keys", "Generate new DID key pair"),
            ("import-keys", "Import existing DID private key"),
            ("show-keys", "Show your DID public key"),
            ("", ""),
            ("[bold]DID Management[/bold]", ""),
            ("mint [doc_uri]", "Mint a new DID NFT"),
            ("info [address|token_id]", "Get DID information"),
            ("status", "Show your complete DID status"),
            ("", ""),
            ("[bold]Challenge-Response[/bold]", ""),
            ("generate-challenge", "Generate a challenge for verification"),
            ("sign-challenge [hash]", "Sign a challenge (requires DID private key)"),
            ("verify-challenge <token_id> <hash> <sig>", "Verify a challenge signature"),
            ("", ""),
            ("[bold]VC Management[/bold]", ""),
            ("submit-vc <issuer> <expires> <sig>", "Submit a VC for verification"),
            ("check-vc [address|token_id]", "Check verification status"),
        ]

        for cmd, desc in commands:
            table.add_row(cmd, desc)

        console.print(table)

    def _generate_keys(self):
        """Generate new DID key pair"""
        if self.key_manager.has_key_pair(self.account.address):
            console.print("[yellow]You already have DID keys stored locally.[/yellow]")
            confirm = self.session.prompt(
                HTML('<prompt>Overwrite existing keys? (yes/no): </prompt>')
            ).strip().lower()
            if confirm != 'yes': 
                console.print("[yellow]Cancelled.[/yellow]")
                return

        console.print("[cyan]Generating new DID key pair...[/cyan]")

        private_key, public_key = self.key_manager.generate_key_pair()
        self.key_manager.save_key_pair(self.account.address, private_key, public_key)

        console.print(Panel(
            f"[green]DID Key Pair Generated![/green]\n\n"
            f"Public Key: 0x{public_key.hex()}\n\n"
            f"[yellow]Private key is stored locally in .did_keys/[/yellow]\n"
            f"[red]Keep your private key safe![/red]",
            title="New DID Keys"
        ))

    def _import_keys(self):
        """Import existing DID private key"""
        console.print("[cyan]Import existing DID private key[/cyan]")
        console.print("[dim]This will derive the public key from your private key.[/dim]\n")

        did_private_key_hex = self.session.prompt(
            HTML('<prompt>Enter DID Private Key (hex): </prompt>'),
            is_password=True
        ).strip()

        if not did_private_key_hex:
            console.print("[red]Private key is required[/red]")
            return

        try:
            # Remove 0x prefix if present
            if did_private_key_hex.startswith('0x'):
                did_private_key_hex = did_private_key_hex[2:]

            private_key_bytes = bytes.fromhex(did_private_key_hex)

            if len(private_key_bytes) != 32:
                console.print("[red]Invalid private key length. Expected 32 bytes.[/red]")
                return

            # Derive public key
            from cryptography.hazmat.primitives. asymmetric import ec
            from cryptography.hazmat.backends import default_backend
            from cryptography.hazmat.primitives import serialization

            private_key = ec.derive_private_key(
                int.from_bytes(private_key_bytes, 'big'),
                ec.SECP256K1(),
                default_backend()
            )
            public_key = private_key.public_key()
            public_key_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint
            )

            # Save keys
            self.key_manager.save_key_pair(self.account.address, private_key_bytes, public_key_bytes)

            console.print(Panel(
                f"[green]DID Keys Imported![/green]\n\n"
                f"Public Key: 0x{public_key_bytes.hex()}",
                title="Imported DID Keys"
            ))

        except Exception as e:
            console.print(f"[red]Failed to import keys: {e}[/red]")

    def _show_keys(self):
        """Show DID public key"""
        keys = self.key_manager.load_key_pair(self.account.address)
        if not keys:
            console.print("[yellow]No local DID keys found. Use 'generate-keys' or 'import-keys'.[/yellow]")
            return

        _, public_key = keys
        console.print(Panel(
            f"Wallet Address: {self.account.address}\n"
            f"DID Public Key: 0x{public_key.hex()}",
            title="Your DID Keys"
        ))

    def _mint_did(self, args):
        """Mint a new DID NFT"""
        did_contract = self.contracts[0]

        # Check if already has DID
        existing_did = did_contract.functions.getDIDByAddress(self.account.address).call()
        if existing_did != 0:
            console.print(f"[yellow]You already have a DID (Token ID: {existing_did})[/yellow]")
            return

        # Check if has DID keys
        keys = self.key_manager.load_key_pair(self.account.address)
        if not keys:
            console.print("[yellow]No DID keys found. Generating new key pair...[/yellow]")
            private_key, public_key = self.key_manager.generate_key_pair()
            self.key_manager.save_key_pair(self.account.address, private_key, public_key)
        else:
            _, public_key = keys

        # Get DID document URI
        did_document = args[0] if args else ""
        if not did_document:
            did_document = self.session.prompt(
                HTML('<prompt>DID Document URI (optional, press Enter to skip): </prompt>')
            ).strip()

        console.print(Panel(
            f"Wallet Address: {self.account.address}\n"
            f"DID Public Key: 0x{public_key.hex()[:40]}...\n"
            f"DID Document:  {did_document if did_document else 'N/A'}",
            title="Minting DID"
        ))

        confirm = self.session.prompt(
            HTML('<prompt>Confirm mint? (yes/no): </prompt>')
        ).strip().lower()

        if confirm != 'yes': 
            console.print("[yellow]Cancelled.[/yellow]")
            return

        try:
            _ = send_transaction(
                self.w3,
                did_contract.functions.mintDID(public_key, did_document),
                self.account
            )

            token_id = did_contract.functions.getDIDByAddress(self.account.address).call()
            console.print(f"[green]DID minted successfully!  Token ID: {token_id}[/green]")

        except Exception as e:
            console.print(f"[red]Failed to mint DID: {e}[/red]")

    def _show_info(self, args):
        """Show DID information"""
        did_contract = self.contracts[0]

        if args:
            arg = args[0]
            if arg.startswith('0x') and len(arg) == 42:
                address = Web3.to_checksum_address(arg)
                token_id = did_contract.functions.getDIDByAddress(address).call()
            else:
                token_id = int(arg)
        else:
            token_id = did_contract.functions.getDIDByAddress(self.account.address).call()

        if token_id == 0:
            console.print("[yellow]No DID found[/yellow]")
            return

        try:
            did_info = did_contract.functions.getDIDInfo(token_id).call()
            print_did_info(did_info, token_id)
        except Exception as e:
            console.print(f"[red]Error:  {e}[/red]")

    def _show_status(self):
        """Show complete DID status"""
        did_contract, _, age_verifier, verifier_registry = self.contracts

        console.print(Panel(f"Address: {self.account.address}", title="Your DID Status"))

        # Get DID info
        token_id = did_contract.functions.getDIDByAddress(self.account.address).call()

        if token_id == 0:
            console.print("[yellow]You don't have a DID yet. Use 'mint' to create one.[/yellow]")
            return

        did_info = did_contract.functions.getDIDInfo(token_id).call()
        print_did_info(did_info, token_id)

        # Check local keys
        if self.key_manager.has_key_pair(self.account.address):
            console.print("[green]✓ Local DID keys available[/green]")
        else:
            console.print("[yellow]! No local DID keys (use 'import-keys' if you have existing keys)[/yellow]")

        # Get verification status
        console.print("\n")
        result = verifier_registry.functions.getVerificationsByAddress(self.account.address).call()
        did_token_id, vc_types, has_verifications, records = result

        table = Table(title="Verification Status")
        table.add_column("VC Type", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("Issuer")
        table.add_column("Expires")

        for i, vc_type in enumerate(vc_types):
            if has_verifications[i]: 
                status = "[green]✓ Verified[/green]"
                issuer = records[i][1][: 10] + "..."
                expires = format_timestamp(records[i][3])
            else:
                status = "[red]✗ Not Verified[/red]"
                issuer = "-"
                expires = "-"
            table.add_row(vc_type, status, issuer, expires)

        console.print(table)

    def _generate_challenge(self):
        """Generate a challenge"""
        challenge_hash, challenge_str = generate_challenge()

        console.print(Panel(
            f"Challenge String: {challenge_str}\n"
            f"Challenge Hash: {challenge_hash.hex()}",
            title="Generated Challenge"
        ))

        console.print("\n[cyan]Send the challenge hash to the user you want to verify.[/cyan]")
        console.print("[cyan]They should use 'sign-challenge' and return the signature.[/cyan]")

    def _sign_challenge(self, args):
        """Sign a challenge - requires DID private key input"""
        did_contract = self.contracts[0]

        # Check if user has DID
        token_id = did_contract.functions.getDIDByAddress(self.account.address).call()
        if token_id == 0:
            console.print("[red]You don't have a DID. Use 'mint' first.[/red]")
            return

        # Get challenge hash
        if args:
            challenge_hash = args[0]
        else: 
            challenge_hash = self.session.prompt(
                HTML('<prompt>Enter challenge hash:  </prompt>')
            ).strip()

        if not challenge_hash:
            console.print("[red]Challenge hash is required[/red]")
            return

        # Ask for DID private key
        console.print("\n[yellow]To sign the challenge, you need your DID private key.[/yellow]")
        console.print("[dim]This is the private key associated with your DID, not your wallet key.[/dim]")

        # Check if we have local keys
        local_keys = self.key_manager.load_key_pair(self.account.address)

        use_local = False
        if local_keys: 
            # 普通输入
            use_local_input = self.session.prompt(
                HTML('<prompt>Use locally stored DID key? (yes/no): </prompt>')
            ).strip().lower()
            use_local = use_local_input == 'yes'

        if use_local and local_keys:
            console.print("[cyan]Using locally stored DID private key...[/cyan]")
        else:
            console.print("[cyan]The contract verifies that the signer is the DID owner.[/cyan]")
            console.print("[cyan]So you need to sign with your DID private key.[/cyan]")

        use_wallet_key = self.session.prompt(
            HTML('<prompt>Sign with current DID key? (yes/no): </prompt>')
        ).strip().lower()

        if use_wallet_key == 'yes':
            signing_key = self.private_key
        else:
            signing_key = self.session.prompt(
                HTML('<prompt>Enter private key for signing: </prompt>'),
                is_password=True
            ).strip()

            if not signing_key:
                console.print("[red]Private key is required for signing[/red]")
                return

        # Convert challenge hash
        try:
            if challenge_hash.startswith('0x'):
                challenge_bytes = bytes.fromhex(challenge_hash[2:])
            else:
                challenge_bytes = bytes.fromhex(challenge_hash)
        except Exception:
            console.print("[red]Invalid challenge hash format[/red]")
            return

        try:
            # Sign using wallet key (contract verifies owner)
            signature = sign_message(challenge_bytes, signing_key)

            signer = load_account(signing_key)

            console.print(Panel(
                f"DID Token ID: {token_id}\n"
                f"Signer: {signer.address}\n"
                f"Challenge:  {challenge_hash}\n"
                f"Signature: 0x{signature.hex()}",
                title="Challenge Signed"
            ))

            console.print("\n[cyan]Send this to the verifier:[/cyan]")
            console.print(f"  Token ID: {token_id}")
            console.print(f"  Signature: 0x{signature.hex()}")

        except Exception as e:
            console.print(f"[red]Failed to sign:  {e}[/red]")

    def _verify_challenge(self, args):
        """Verify a challenge signature"""
        did_contract = self.contracts[0]

        if len(args) >= 3:
            token_id = int(args[0])
            challenge_hash = args[1]
            signature = args[2]
        else: 
            token_id_str = self.session.prompt(
                HTML('<prompt>Enter DID Token ID: </prompt>')
            ).strip()
            token_id = int(token_id_str)

            challenge_hash = self.session.prompt(
                HTML('<prompt>Enter challenge hash: </prompt>')
            ).strip()

            signature = self.session.prompt(
                HTML('<prompt>Enter signature: </prompt>')
            ).strip()

        # Convert inputs
        try:
            if challenge_hash.startswith('0x'):
                challenge_bytes = bytes.fromhex(challenge_hash[2:])
            else:
                challenge_bytes = bytes.fromhex(challenge_hash)

            if signature.startswith('0x'):
                sig_bytes = bytes.fromhex(signature[2:])
            else:
                sig_bytes = bytes.fromhex(signature)
        except Exception:
            console.print("[red]Invalid input format[/red]")
            return

        try:
            # Verify on-chain
            is_valid = did_contract.functions.verifyChallenge(
                token_id,
                challenge_bytes,
                sig_bytes
            ).call()

            owner = did_contract.functions.ownerOf(token_id).call()

            if is_valid:
                console.print(Panel(
                    f"[green]✓ Signature is VALID[/green]\n\n"
                    f"DID Token ID: {token_id}\n"
                    f"DID Owner: {owner}\n"
                    f"The signer owns this DID.",
                    title="Verification Result"
                ))
            else:
                console.print(Panel(
                    f"[red]✗ Signature is INVALID[/red]\n\n"
                    f"DID Token ID: {token_id}\n"
                    f"DID Owner: {owner}\n"
                    f"The signer does NOT own this DID.",
                    title="Verification Result"
                ))
        except Exception as e:
            console.print(f"[red]Error:  {e}[/red]")

    def _submit_vc(self, args):
        """Submit a VC for on-chain verification"""
        did_contract, _, age_verifier, _ = self.contracts

        # Get user's DID token ID
        token_id = did_contract.functions.getDIDByAddress(self.account.address).call()
        if token_id == 0:
            console.print("[red]You don't have a DID. Use 'mint' first.[/red]")
            return

        if len(args) >= 3:
            issuer_address = args[0]
            expires_at = int(args[1])
            signature = args[2]
            vc_data = args[3] if len(args) >=4 else ""
        else:
            console.print("[cyan]Enter the VC details provided by the issuer:[/cyan]\n")

            issuer_address = self.session.prompt(
                HTML('<prompt>Issuer Address: </prompt>')
            ).strip()

            expires_at_str = self.session.prompt(
                HTML('<prompt>Expires At (timestamp): </prompt>')
            ).strip()
            expires_at = int(expires_at_str)

            signature = self.session.prompt(
                HTML('<prompt>Signature: </prompt>')
            ).strip()

            vc_data = self.session.prompt(
                HTML('<prompt>VC Data: </prompt>')
            ).strip()

        # Convert inputs
        try:
            issuer = Web3.to_checksum_address(issuer_address)

            if signature.startswith('0x'):
                sig_bytes = bytes.fromhex(signature[2:])
            else:
                sig_bytes = bytes.fromhex(signature)
        except Exception as e:
            console.print(f"[red]Invalid input format:  {e}[/red]")
            return

        console.print(Panel(
            f"DID Token ID: {token_id}\n"
            f"VC Data: {vc_data}\n"
            f"Issuer: {issuer}\n"
            f"Expires At: {format_timestamp(expires_at)}",
            title="Submitting VC"
        ))

        confirm = self.session.prompt(
            HTML('<prompt>Confirm submission? (yes/no): </prompt>')
        ).strip().lower()

        if confirm != 'yes':
            console.print("[yellow]Cancelled.[/yellow]")
            return

        try:
            _ = send_transaction(
                self.w3,
                age_verifier.functions.verifyAndRecord(
                    token_id,
                    issuer,
                    expires_at,
                    sig_bytes,
                    bytes(vc_data, "utf-8")
                ),
                self.account
            )

            has_valid = age_verifier.functions.hasValidVerification(token_id).call()
            if has_valid:
                console.print("[green]VC verified and recorded successfully![/green]")
            else:
                console.print("[red]VC verification failed![/red]")

        except Exception as e:
            console.print(f"[red]Error:  {e}[/red]")

    def _check_vc(self, args):
        """Check verification status"""
        did_contract, _, age_verifier, _ = self.contracts

        if args:
            arg = args[0]
            if arg.startswith('0x') and len(arg) == 42:
                address = Web3.to_checksum_address(arg)
                token_id = did_contract.functions.getDIDByAddress(address).call()
            else:
                token_id = int(arg)
        else:
            token_id = did_contract.functions.getDIDByAddress(self.account.address).call()

        if not token_id or token_id == 0:
            console.print("[yellow]No DID found[/yellow]")
            return

        has_valid = age_verifier.functions.hasValidVerification(token_id).call()

        console.print(Panel(
            f"DID Token ID: {token_id}\n"
            f"AgeOver18 Verified: {'[green]✓ Yes[/green]' if has_valid else '[red]✗ No[/red]'}",
            title="Verification Status"
        ))

        if has_valid:
            record = age_verifier.functions.getVerification(token_id).call()
            print_verification_info(record)


def main():
    cli = UserCLI()
    cli.start()


if __name__ == '__main__':
    main()