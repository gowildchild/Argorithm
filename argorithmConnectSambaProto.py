# ==========================================================================
# ARGORITHM argorithmConnectSambaProto.py // Radius & OIDC to SAMBA mounts
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
# UNIVERSAL ARGORITHM VARIABLES (BLANK BY DEFAULT TO FORCE PROMPTS OR PARAMETERS)
# ==============================================================================
OIDC_SERVER_URL          = "www.oidcserver.dom"
OIDC_SERVER_PROVIDER     = "argorithm"
OIDC_BASE_URL            = f"https://{OIDC_SERVER_URL}/application/o/{OIDC_SERVER_PROVIDER}/"
OIDC_DISCOVERY_URL       = f"https://{OIDC_SERVER_URL}/application/o/{OIDC_SERVER_PROVIDER}/.well-known/openid-configuration"
OIDC_CLIENT_ID           = "ArgoRithmCLIENTID"
LOCAL_SYSTEM_CACHE_FILE  = "~/.config/argorithm/infrastructure_cache.json"

class ArgorithmClient:
    def __init__(self):
        self.args = self.parse_arguments()
        self.is_session_active = True

        # Universal Endpoint Value Hierarchy Resolution
        raw_url = self.args.oidc_url if self.args.oidc_url else (OIDC_BASE_URL if OIDC_BASE_URL else self.prompt_config("Enter Universal OIDC Base URL: "))
        self.client_id = self.args.client_id if self.args.client_id else (OIDC_CLIENT_ID if OIDC_CLIENT_ID else self.prompt_config("Enter OIDC Client ID: "))
        #self.oidc_url = self.normalize_url_string(raw_url)
        self.oidc_url = raw_url

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
        parser = argparse.ArgumentParser(description="Argorithm Zero-Trust Multi-Resource Attestation Prototype.")
        parser.add_argument("--oidc-url", type=str, help="Target OpenID Connect base server URL connection path.")
        parser.add_argument("--client-id", type=str, help="Target application identity registration parameter.")
        parser.add_argument("--resources", type=str, default="nfs:*", help="Explicit target volume selection list mappings.")
        parser.add_argument("--scope", type=str, default="developer", choices=["developer", "install", "script"], help="Target execution intent profile.")
        parser.add_argument("--override-machine", type=str, help="Manual system hardware signature override block.")
        parser.add_argument("--override-user", type=str, help="Manual system target user signature override block.")
        parser.add_argument("--offline-access", action="store_true", help="Opt-in to request long-lived background refresh tokens.")
        parser.add_argument("--store", type=str, choices=["ram", "disk"], default="ram", help="Where to maintain persistence variables.")
        parser.add_argument("--security", type=int, choices=[1, 2, 3], default=1, 
help="1-2 allows fast-track reboots. 3 forces full verification checks.")
        parser.add_argument("--debug", type=int, choices=[0, 1, 2, 3], default=0, help="0=Silent, 3=Full Output Streams.")
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
        if "https://" in input_url:
            cleaned = input_url.replace("https://", "https://")
            parts = cleaned.split(".")
            if "application" in parts and "o" in parts:
                idx_app = parts.index("application")
                domain = ".".join(parts[:idx_app])
                path_segments = parts[idx_app:]
                path_str = "/".join([p for p in path_segments if p])
                return f"{domain}/{path_str}/"
        return input_url

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
