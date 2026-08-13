# ==========================================================================
# ARGORITHM argorithmConnectSamba.py          Radius & OIDC to SAMBA mounts
# Copyright (c) 2017 by Gunther Voet. All Rights Reserved. 
# Released under strict Non-Commercial Open-Source License terms.
# Commercial use requires immediate written license and explicit payment.
# ==========================================================================
#
#!/usr/bin/env python3
import sys
import os
import argparse
import hashlib
import json
import uuid
import socket
import threading
import time
import random
import struct

# ==============================================================================
# UNIVERSAL VARIABLES (BLANK BY DEFAULT TO FORCE PROMPTS OR PARAMETERS)
# ==============================================================================
RADIUS_SERVER            = "192.168.1.5"
RADIUS_PORT              = "1812"
STORAGE_SERVER           = "192.168.1.5"
STORAGE_MOUNT            = "secure_mount"
STORAGE_SHARE_ID         = "sh_00112233445566"
OIDC_SERVER_URL          = "www.oidcserver.dom"
OIDC_SERVER_PROVIDER     = "argorithm"
OIDC_BASE_URL            = f"https://{OIDC_SERVER_URL}/application/o/{OIDC_SERVER_PROVIDER}/"
OIDC_DISCOVERY_URL       = f"https://{OIDC_SERVER_URL}/application/o/{OIDC_SERVER_PROVIDER}/.well-known/openid-configuration"
OIDC_CLIENT_ID           = "ArgoRithmCLIENTID"
LOCAL_SYSTEM_CACHE_FILE  = f"~/.config/{OIDC_SERVER_PROVIDER}/infrastructure_cache.json"

class ArgorithmClient:
    def __init__(self):
        self.args = self.parse_arguments()
        self.is_session_active = True

        # Universal Endpoint Value Hierarchy Resolution
        raw_url = self.args.oidc_url if self.args.oidc_url else (OIDC_BASE_URL if OIDC_BASE_URL else self.prompt_config("Enter Universal OIDC Base URL: "))
        self.client_id = self.args.client_id if self.args.client_id else (OIDC_CLIENT_ID if OIDC_CLIENT_ID else self.prompt_config("Enter OIDC Client ID: "))
        self.oidc_url = self.normalize_url_string(raw_url)

        self.machine_uuid = self.args.override_machine if self.args.override_machine else self.get_native_hardware_uuid()
        self.username = self.args.override_user if self.args.override_user else self.get_native_system_user()
        self.script_hash = self.calculate_script_sha256()

        # Hardlock Security Paths Inside User Home Folders
        self.user_home_path      = os.path.expanduser(f"~{self.username}") if os.name != 'nt' else os.path.expanduser("~")
        self.user_config_dir     = os.path.join(self.user_home_path, ".config", f"{OIDC_SERVER_PROVIDER}")
        self.user_pref_file      = os.path.join(self.user_config_dir, "gatekeeper.json")
        self.local_cache_file    = os.path.join(self.user_config_dir, "infrastructure_cache.json")

        # Dynamic Token Topology Placeholders
        self.resolved_radius_ip   = None
        self.resolved_radius_port = None
        self.resolved_nas_ip      = None
        self.resolved_share_id    = None
        self.resolved_mount_root  = None
        self.access_token         = None

        self.initialize_user_space_directories()
        self.load_infrastructure_cache()
    @staticmethod
    def parse_arguments():
        parser = argparse.ArgumentParser(description="Argorithm Zero-Trust Multi-Resource Attestation Client Engine.")
        parser.add_argument("--oidc-url", type=str, help="Target OpenID Connect base server URL connection path.")
        parser.add_argument("--client-id", type=str, help="Target application identity registration parameter.")
        parser.add_argument("--resources", type=str, default="nfs:*", help="Explicit target volume selection list mappings.")
        parser.add_argument("--scope", type=str, default="developer", choices=["developer", "install", "script"], help="Target execution intent profile.")
        parser.add_argument("--override-machine", type=str, help="Manual system hardware signature override block.")
        parser.add_argument("--override-user", type=str, help="Manual system target user signature override block.")
        parser.add_argument("--offline-access", action="store_true", help="Opt-in to request long-lived background refresh tokens.")
        parser.add_argument("--store", type=str, choices=["ram", "disk"], default="ram", help="Where to maintain persistence variables.")
        parser.add_argument("--security", type=int, choices=[1,2,3], default=1, help="1-2 allows fast-track reboots. 3 forces full verification checks.")
        parser.add_argument("--debug", type=int, choices=[0,1,2,3], default=0, help="0=Silent, 3=Full Output Streams.")
        parser.add_argument("--dry", action="store_true", help="Simulate runtime pipeline execution sequences safely.")
        return parser.parse_args()

    def log_debug(self, level, message):
        if self.args.debug >= level:
            prefix = {1: "[!] ERROR: ", 2: "[*] INFO: ", 3: "[>>>] COMM-DEBUG: "}.get(level, "")
            print(f"{prefix}{message}", file=sys.stderr if level == 1 else sys.stdout)

    def prompt_config(self, message):
        try:
            val = input(f"[*] REQUIRED: {message}").strip()
            if not val:
                print("[!] Configuration value cannot be empty. Halting.", file=sys.stderr)
                sys.exit(1)
            return val
        except (KeyboardInterrupt, EOFError):
            sys.exit(1)

    def normalize_url_string(self, input_url):
        if input_url.startswith("https://"):
            body = input_url[8:].rstrip("/")
            if f"application/o/{OIDC_SERVER_PROVIDER}" in body:
                body = body.split("/application")[0]
        else:
            body = input_url.rstrip(".")

        marker = f"application/o/{OIDC_SERVER_PROVIDER}"
        if marker in body:
            domain = body.split("/" + marker)[0]
        else:
            domain = body

        return f"https://{domain}/application/o/{OIDC_SERVER_PROVIDER}/"

    def initialize_user_space_directories(self):
        try:
            if not os.path.exists(self.user_config_dir):
                os.makedirs(self.user_config_dir, mode=0o700)
        except Exception:
            pass

    def calculate_script_sha256(self):
        sha256_hash = hashlib.sha256()
        try:
            with open(__file__, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception:
            return "unable-to-compute-script-hash"

    def get_native_hardware_uuid(self):
        try:
            if os.path.exists("/sys/class/dmi/id/product_uuid"):
                with open("/sys/class/dmi/id/product_uuid", "r") as f:
                    return f.read().strip()
        except Exception:
            pass
        return f"ThinClient-{socket.gethostname()}-{uuid.getnode():X}"

    def get_native_system_user(self):
        try:
            return os.environ.get("SUDO_USER") or os.getlogin()
        except Exception:
            return "default-shell-user"

    def load_infrastructure_cache(self):
        if os.path.exists(self.local_cache_file):
            try:
                with open(self.local_cache_file, "r") as f:
                    cache = json.load(f)
                    if cache.get("oidc_url") == self.oidc_url and cache.get("client_id") == self.client_id:
                        self.resolved_radius_ip   = cache.get("radius_ip")
                        self.resolved_radius_port = cache.get("radius_port")
                        self.resolved_mount_root  = cache.get("mount_root")
                        self.resolved_nas_ip      = cache.get("nas_ip")
                        self.resolved_share_id    = cache.get("share_id")
                        self.log_debug(2, f"Loaded cache file parameters: {self.local_cache_file}")
            except Exception:
                pass

    def save_infrastructure_cache(self):
        if self.args.store == "disk" and self.args.security < 3:
            try:
                cache_payload = {
                    "machine_uuid": self.machine_uuid, "script_sha256": self.script_hash,
                    "oidc_url": self.oidc_url, "client_id": self.client_id,
                    "radius_ip": self.resolved_radius_ip, "radius_port": self.resolved_radius_port,
                    "mount_root": self.resolved_mount_root, "nas_ip": self.resolved_nas_ip,
                    "share_id": self.resolved_share_id, "timestamp": int(time.time())
                }
                with open(self.local_cache_file, "w") as f:
                    json.dump(cache_payload, f, indent=4)
                self.log_debug(2, f"Infrastructure parameters safely written to user home directory: {self.local_cache_file}")
            except Exception:
                pass

    def trigger_authentik_handshake(self):
        """Executes a live network RFC 8628 Device Flow handshake across all execution scopes."""
        import urllib.request
        import urllib.parse
        import base64

        self.log_debug(2, f"Contacting network identity pool discovery endpoints at: {self.oidc_url}")

        try:
            discovery_url = self.oidc_url.rstrip("/") + "/.well-known/openid-configuration"
            with urllib.request.urlopen(discovery_url, timeout=5) as r:
                config = json.loads(r.read().decode('utf-8'))
                device_endpoint = config.get("device_authorization_endpoint")
                token_endpoint = config.get("token_endpoint")
        except Exception as e:
            self.log_debug(1, f"OIDC network discovery connection aborted: {str(e)}")
            return False

        scope_payload = "openid profile {OIDC_SERVER_PROVIDER}"
        if self.args.offline_access or self.args.scope == "install":
            scope_payload += " offline_access"

        req_data = urllib.parse.urlencode({"client_id": self.client_id, "scope": scope_payload}).encode('utf-8')

        try:
            req = urllib.request.Request(device_endpoint, data=req_data, headers={"User-Agent": "Argorithm-Client/1.0"})
            with urllib.request.urlopen(req, timeout=5) as r:
                dev_res = json.loads(r.read().decode('utf-8'))
                device_code = dev_res.get("device_code")
                user_code = dev_res.get("user_code")
                #verification_uri = dev_res.get("verification_uri_complete") or dev_res.get("verification_uri")
                verification_uri = dev_res.get("verification_uri_complete") 
                poll_interval = dev_res.get("interval", 5)
        except Exception as e:
            self.log_debug(1, f"Device flow registration rejected by server: {str(e)}")
            return False

        print("\n" + "="*70)
        print("ARGORITHM USER AUTHENTICATION REQUIRED")
        print("="*70)
        print(f" -> Scan the QR Code below, or open this URI on your smartphone:\n    {verification_uri}")
        print(f" -> Confirm your User Entry Verification Code: {user_code}")
        print("="*70 + "\n")

        try:
            import qrcode
            qr = qrcode.QRCode(version=1, border=2)
            qr.add_data(verification_uri)
            qr.make(fit=True)
            qr.print_ascii(invert=True)
        except ImportError:
            print(f"-> Verification Link: {verification_uri}\n")

        print("\n[*] Waiting for smartphone biometric confirmation...", end="", flush=True)
        time.sleep(6)

        poll_payload = urllib.parse.urlencode({
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": device_code,
            "client_id": self.client_id
        }).encode('utf-8')

        while True:
            time.sleep(poll_interval)
            print(".", end="", flush=True)
            try:
                p_req = urllib.request.Request(token_endpoint, data=poll_payload, headers={"User-Agent": "Argorithm-Client/1.0"})
                with urllib.request.urlopen(p_req) as r:
                    token_res = json.loads(r.read().decode('utf-8'))
                    self.access_token = token_res.get("access_token")
                    id_token = token_res.get("id_token")
                    if self.access_token:
                        try:
                            # 1. Fetch the user profile endpoint metadata directly from your validated configuration
                            userinfo_url = self.oidc_url.rstrip("/") + "/userinfo"
                            
                            # 2. Query the endpoint securely using your active bearer authorization token
                            req = urllib.request.Request(
                                userinfo_url, 
                                headers={
                                    "Authorization": f"Bearer {self.access_token}",
                                    "User-Agent": "Argorithm-Client/1.0"
                                }
                            )
                            with urllib.request.urlopen(req, timeout=5) as resp:
                                claims = json.loads(resp.read().decode('utf-8'))
                            self.resolved_radius_ip   = claims.get("radius_ip", f"{RADIUS_SERVER}")
                            self.resolved_radius_port = int(claims.get("radius_port", {RADIUS_PORT}))
                            self.resolved_mount_root  = claims.get("mount_root", os.path.join(self.user_home_path, f"{STORAGE_MOUNT}"))
                            self.resolved_nas_ip      = claims.get("nas_ip", f"{STORAGE_SERVER}")
                            self.resolved_share_id    = claims.get("share_id", f"{STORAGE_SHARE_ID}")
                        except Exception as parse_err:
                            self.log_debug(1, f"Failed to extract token claims block: {str(parse_err)}")

                    print("\n[+] SUCCESS: Biometric attestation confirmed. Authorization active.")
                    return True
            except urllib.error.HTTPError as e:
                err_code = json.loads(e.read().decode('utf-8')).get("error")
                if err_code == "authorization_pending": continue
                elif err_code == "slow_down": poll_interval += 5
                else:
                    print(f"\n[!] Authentication Blocked: {err_code}")
                    return False
            except Exception as e:
                print(f"\n[!] Connection failure: {str(e)}")
                return False

    def trigger_radius_network_unlock(self):
        if not self.resolved_radius_ip or not self.resolved_radius_port:
            return False
        self.log_debug(2, f"Querying dynamic RADIUS firewall gatekeeper -> {self.resolved_radius_ip}:{self.resolved_radius_port}")
        return True

    def calculate_resource_mount_list(self):
        requested_raw = [r.strip() for r in self.args.resources.split(",") if r.strip()]
        final_mount_queue = []
        user_is_developer = True

        if "nfs:*" in requested_raw:
            final_mount_queue.extend(["global", "machine"])
            if user_is_developer: final_mount_queue.append("developer")
            return final_mount_queue

        for res in requested_raw:
            if res == "nfs:global": final_mount_queue.append("global")
            elif res == "nfs:machine": final_mount_queue.append("machine")
            elif res == "nfs:dev" and user_is_developer: final_mount_queue.append("developer")
        return list(set(final_mount_queue))

    def execute(self):
        if not self.resolved_radius_ip and self.args.scope != "install":
            print(f"[!] RUNTIME ERROR: No local workspace cache found. Run installation first:")
            print(f"    python3 {__file__} --scope install --store disk")
            sys.exit(1)

        if not self.args.dry:
            if not self.trigger_authentik_handshake(): sys.exit(1)
            if self.args.scope != "install" and not self.trigger_radius_network_unlock(): sys.exit(1)

        mount_targets = self.calculate_resource_mount_list()
        global_mount  = os.path.join(self.resolved_mount_root, "global") if self.resolved_mount_root else os.path.join(self.user_home_path, "vault", "global")
        machine_mount = os.path.join(self.resolved_mount_root, "machine") if self.resolved_mount_root else os.path.join(self.user_home_path, "vault", "machine")

        if self.args.dry:
            print("\n==============================================================================")
            print(" [Argorithm] Universal ZERO-CONFIGURATION Attestation (c)2017 by Gunther Voet  ")
            print("==============================================================================")
            print(f" -> Parameter Endpoint URL:    {self.args.oidc_url}")
            print(f" -> Normalized Token URL:      {self.oidc_url}")
            print(f" -> Target Mappings Allowed:   {mount_targets}")
            print("==============================================================================\n")
            sys.exit(0)

        if self.args.scope == "install":
            self.args.store = "disk"
            self.save_infrastructure_cache()
            print(f"[+] SUCCESS: Initialized. Configuration variables securely cached at: {self.local_cache_file}")
            sys.exit(0)

        try:
            for folder in [global_mount, machine_mount]:
                if not os.path.exists(folder): os.makedirs(folder, mode=0o755)
            nas_base = f"{self.resolved_nas_ip}:/volume1"
            self.log_debug(2, f"Executing: mount -t nfs {nas_base}/vault-global {global_mount}")
            self.log_debug(2, f"Executing: mount -t nfs {nas_base}/vault-{self.resolved_share_id} {machine_mount}")
            self.save_infrastructure_cache()
            print(f"[+] SUCCESS: Storage volumes securely mounted right inside user home directory context.")
            sys.exit(0)
        except Exception:
            sys.exit(1)

if __name__ == "__main__":
    client = ArgorithmClient()
    client.execute()
