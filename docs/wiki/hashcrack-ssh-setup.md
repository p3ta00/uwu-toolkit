# Remote Hashcat Cracking Setup

UwU Toolkit can offload hash cracking to a remote machine with a GPU. This guide walks you through setting up SSH access from your Exegol container to your host machine.

## Prerequisites

- A host machine with:
  - hashcat installed
  - NVIDIA GPU with CUDA or OpenCL support
  - SSH server running (`sudo systemctl enable --now sshd`)
- Exegol container with UwU Toolkit

## Quick Setup

### Step 1: Run hashcrack_setup in Exegol

```
uwu> hashcrack_setup
```

The setup wizard will display your SSH public key with a ready-to-paste command:

```
  Hashcat Remote Cracking Setup
  ==================================================
  Configure SSH connection to a machine with hashcat/GPU

  ➜ Run this on your HOST to authorize this key:
  ────────────────────────────────────────────────────────────
  echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIxxxx...' >> ~/.ssh/authorized_keys
  ────────────────────────────────────────────────────────────
```

### Step 2: Add the key on your host

Copy the `echo '...' >> ~/.ssh/authorized_keys` command and run it on your host machine.

### Step 3: Complete the setup in Exegol

Continue with the prompts:

| Option | Description | Example |
|--------|-------------|---------|
| SSH Host | Your host's IP (use Docker gateway from containers) | `172.17.0.1` |
| SSH Port | SSH port | `22` |
| SSH User | Your username on the host | `username` |
| Wordlist | Path to wordlist on the host | `/home/username/wordlists/rockyou.txt` |
| Rules | Path to rules file (optional) | `/usr/share/hashcat/rules/OneRuleToRuleThemAll.rule` |

### Step 4: Verify connection

```
uwu> hashcrack_setup --test
```

You should see:
```
  [+] Connection successful!
  [+] Hashcat: /usr/bin/hashcat
  [+] Version: v7.1.2
```

## Commands Reference

| Command | Description |
|---------|-------------|
| `hashcrack_setup` | Interactive setup wizard |
| `hashcrack_setup --show` | Display current configuration |
| `hashcrack_setup --test` | Test SSH connection to cracking host |
| `hashcrack_setup --add-key` | Add SSH key (run on HOST side) |

## Troubleshooting

### "Permission denied (publickey)"

Your SSH key isn't authorized on the host. Run the `echo` command shown during setup on your host machine.

### "Host key verification failed"

First-time connection. The setup now auto-accepts new host keys, but if issues persist:
```bash
ssh-keyscan -H 172.17.0.1 >> ~/.ssh/known_hosts
```

### "Connection timed out"

- Verify SSH is running on host: `sudo systemctl status sshd`
- Check the IP is correct (use `172.17.0.1` for Docker gateway)
- Ensure no firewall blocking port 22

### hashcat not found

Install hashcat on your host:
```bash
sudo apt install hashcat
```

For CUDA support:
```bash
sudo apt install nvidia-cuda-toolkit
```

## Network Configuration

### From Exegol Container

The Docker gateway IP `172.17.0.1` typically reaches your host from inside containers. This IP is stable and doesn't change.

### Alternative: Use hostname

If mDNS/Avahi is configured, you can use `hostname.local`:
```
SSH Host: myhostname.local
```

## Recommended Wordlists & Rules

### Wordlists

| Wordlist | Size | Download |
|----------|------|----------|
| rockyou.txt | 140 MB | `wget https://download.weakpass.com/wordlists/90/rockyou.txt.gz` |

### Rules

| Rule | Description |
|------|-------------|
| `OneRuleToRuleThemAll.rule` | Optimized rule with 68% crack rate |
| `best66.rule` | Hashcat's built-in best rules |
| `dive.rule` | Comprehensive mutations |

Install OneRuleToRuleThemAll:
```bash
sudo curl -L -o /usr/share/hashcat/rules/OneRuleToRuleThemAll.rule \
  https://raw.githubusercontent.com/stealthsploit/Optimised-hashcat-Rule/master/OneRuleToRuleThemAll.rule
```

## How It Works

When modules like `ad_enumerate_all` capture hashes with `AUTO_CRACK=yes`:

1. Hashes are saved locally in Exegol
2. UwU Toolkit SSHs to your configured host
3. hashcat runs on the host GPU
4. Results are returned to Exegol

This gives you full GPU acceleration without needing GPU passthrough to containers.
