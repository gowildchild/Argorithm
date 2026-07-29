# Argorithm - Open Source Specifications

**Modified:** 2026-06-24  
**Created:** 2026-06-23  
**Status:** Public Release / Version 0.2 Proof of Concept (PoC)  
**Author:** Gunther Voet

---

The name "Argorithm" is a portmanteau of Argos Panoptes, the mythological hundred-eyed guardian who never blinked because only a few eyes slept while the rest were watching the darkness. The Algorithm is that rigorous, deterministic code that loops driving the system while watching the darkness.

It signals an authentication protocol that evaluates every physical layer simultaneously, ensuring that an execution path cannot be forged, even when single environmental parameters are blind.

### Background & Context
The first loss was the theft of the hard disks in a hosting center in Amsterdam, which was totally overlooked and played with because of ableism. We had to close two companies for that, but a bit later I discovered they did not destroy the data, because the licensing daemon took contact with the homeserver a few times after the data theft. The IDP which I created fully in Perl had many options that are still unavailable at present time. This feature is merely 1/40th of what got stolen.

The second loss, however, cannot be on me or my family. We have been under continuous cyberattacks for about 5 years now and they want to steal more. This is not only a proof-of-concept, but an entire lifework was stolen with all working concepts like this one, just because ableism stops all help. I don't only help law enforcement in the Netherlands to get those criminals by offering them the details, but we don't get ANYTHING of help in return to stop this.

## 1. Summary

Traditional Zero-Trust Network Access (ZTNA) frameworks suffer from architectural bloat, resource overhead, and a fundamental flaw: they communicate failure loudly. When an endpoint fails a validation check, typical systems print explicit "Access Denied" errors, immediately alerting a malicious actor or a thief that they have hit a security perimeter.

Furthermore, most corporate platforms rely on heavy background software daemons and persistent connections to central cloud directories, making them highly fragile and complex to manage inside isolated environments like when operating on small factor/form architectures (e.g., thin clients).

The **Argorithm** is an elegant, stateless, low-overhead context-attestation protocol designed to eliminate these security vulnerabilities. It compresses dense, multi-layered identity, physical hardware, local network topology, external internet routing, and licensing states into a single, compact, 16-character uppercase hexadecimal status mask string (e.g., `OK:FFFFFFFFFF`).

## 2. The Core Philosophy: The Invisible Honey-Snare

The definitive strength of Argorithm lies in its complete subversion of the attacker's visibility. The protocol does not announce failure, but when it breaks character, it is closely looked at. If a single environmental, network, or identity parameter drops out of alignment, the server-side analysis engine shifts state silently. It lies within the creator's mind which of his code will be affected. It can be used to track malicious attempts of any kind at a low footprint.

Instead of locking the terminal prompt or throwing an error, the system returns an arbitrary-looking hexadecimal failure string to the client script. The local script handles this payload by hiding all secure data directories and network storage mounts, while displaying a completely normal, functional, and generic user terminal console screen.

To the thief or rogue actor, the system appears to have booted successfully into a bare, unconfigured environment. Behind the scenes, however, the script drops into a persistent, hidden background loop. This loop continuously retries its authentication packets over the network card, harvesting and streaming the intruder's real-time network metadata, local subnet layout, and rogue external public WAN IP addresses back to the centralized security logs without ever tipping off the actor.

## 3. Chained Injection Resistance and the 2+ Step Network Gate

To operate safely in environments where the terminal workstation or edge nodes cannot be fully trusted, Argorithm enforces a chained, two-step network gate that mathematically defeats packet injection, Man-in-the-Middle (MITM) replay loops, and local machine spoofing:

*   **Step 1: The Out-of-Band RADIUS Barrier:** The client machine initiates its boot cycle by communicating locally with an isolated RADIUS container. It passes raw hardware silicon serials over UDP port 1812. The RADIUS server cross-references its local accounting logs to ensure the machine has not been dark past your 48-hour inactivity window. If valid, RADIUS drops the first gate and issues a volatile, randomized, 64-second session challenge token.
*   **Step 2: The Biometric Gate:** The client catches that 64-second token and passes it to the central Authentik web API to trigger a Device Authorization Flow. The console prints a scannable text-based ANSI QR code on the screen. The user scans it with their mobile device, executing a hardware-bound WebAuthn/FIDO2 handshake via a physical YubiKey or (mobile) biometric touch. This could be implemented with any authentication platform or method which supports the current standards.

Because the final hash validation payload requires the exact, matching 64-second RADIUS challenge token combined with a real-time, live physical hardware touch, a network tap on the wire is useless. An attacker cannot record a successful `OK:FFFFFFFFFF` string and inject it later; the session timelines, sequence headers, and central server-side tracking clocks will mismatch instantly.

## 4. The Inbound Cryptographic Glue Matrix & Dumb-Client Overrides

To ensure that an intercepted network token or a compromised root environment on a local machine cannot be used to manipulate authentication states, Argorithm decouples payload execution from the endpoint. The client script operates purely as a zero-trust, dumb receiver. All sensitive environmental calculations, status validations, and access limits are processed and verified exclusively behind the secure perimeter of the RADIUS and Authentik gateways.

### 1. The Local Attestation Hash Vector
During the initial boot sequence, the client script queries its direct hardware layers and wire environments to construct a unique, temporary 32-bit localized integer hash.

$$
\text{Hash}_{\text{Local}} = \text{Hash}(\text{Motherboard UUID} + \text{LAN Gateway IP} + \text{External WAN IP})
$$

### 2. The Server-Side Oblivious Response Mask
When the user satisfies the Factor 4 biometric challenge via their mobile device or physical hardware key token, the central Authentik engine references its private, crypto-locked infrastructure registry. Instead of transmitting an inject-susceptible success string over the wire, the server executes a bitwise Exclusive-OR (XOR) operation using a rolling, short-lived session token mask against the expected target environment signature:

$$
\text{Payload}_{\text{Return}} = \text{Hash}_{\text{Expected}} \oplus \text{Session Mask}
$$

### 3. The Isolated RAM Verification
The client script catches the `Payload_Return` string and instantly evaluates it against its live, local environment hash inside a protected memory buffer:

$$
\text{Verification Key} = \text{Payload}_{\text{Return}} \oplus \text{Hash}_{\text{Local}}
$$



If the physical environment is perfectly pure, the bit alignments cancel out cleanly, revealing the precise runtime memory key required to trigger system mounts natively. If an adversary attempts to tap the network fiber, alter any script lines, or clone the drive parameters onto an unauthorized machine, the resulting mathematical key calculation yields corrupted garbage memory, keeping the file system totally empty and locked at rest.

### 4. Rolling Token Lifecycle Rotation
To prevent replay vectors on high-security recovery commands (such as `--scope not-stolen` or `--scope retry`), Argorithm enforces a rolling hash rotation. Upon the successful entry of an out-of-band 6-digit OTP code, the server automatically updates its master salt variables, rotates the expected XOR matrix signature, and securely instructs the client script to immediately overwrite its local hidden disk configuration file (`.vault_config`) with the fresh generation key.

### 5. Hierarchical Manual Maintenance Override Tunnels
To handle expected physical environment shifts safely without breaking the core bitmask or leaking structural profiles, the protocol routes adjustments through a dedicated, zero-trust parameter tree:

*   `--override-scope machine` : Re-scans raw silicon DMI table metrics after an authorized motherboard upgrade, prompting a secure validation loop to re-register the silicon fingerprint.
*   `--override-scope user` : Re-maps local account definitions and parent process POSIX UIDs.
*   `--override-scope network:lan` : Updates and anchors local subnet configurations, private static assignments, and gateway router parameters.
*   `--override-scope network:wan` : Safely updates external public modem IP signatures after an internet service provider gateway reset, re-anchoring the system without triggering a manual user lockout.
*   `--requires "[GROUP_NAME]"` : Direct pass-through variable. The client script never decides if a user role is valid; it passes the group string context upstream to Authentik. If the user lacks membership inside that target directory group, the user core bit falls to `0`, silently engaging the tracking loop.
*   `--security [1|2|3] --timeout [SECONDS]` :
    *   **Security 1** processes the baseline hardware/network XOR matrix.
    *   **Security 2** includes volatile process execution signatures.
    *   **Security 3 (Tight)** forces the script to generate a SHA-256 hash of its own code file and loaded libraries, passing it to the server; if a thief has modified a single file line to disable your traps, the hash fails and the system locks.
    *   Supports passing a `--timeout` flag to securely extend the lease length (e.g., up to 30 days / 2,592,000 seconds if approved by the central server registry database).

## 5. The Dictionary Map: Bit-by-Bit Breakdown

The dictionary map is a gatekeeper checking machine eligibility to grant access to a device. It consults the right resources to inspect the map; valid parameters lead to the destination.

Every bit of the core 40-bit layout (**Digits 1–10**) holds specific details critical to preventing system/source theft and granting resource access. A licensing system extension can affect or override bits. Removing the trusted environment revokes access and can activate a "demo" edition of the software.

### FACTOR 1: LOCAL USER & HARDWARE PARAMETERS (DIGITS 1–2)
Establishes what the machine contains in local storage and hardware chips regarding the user and node context at the exact millisecond of boot time. It tracks scenarios where data or hardware might be stolen.

#### Digit 1: The User Core
*   **Bit 0 (Value 1): User Name OK**
    *   *What it checks:* Validates that the local account calling the script matches a profile registered on the system.
    *   *Attack Vector Eliminated:* Prevents raw dictionary attacks or manual username guessing at the local terminal console.
    *   *Pro:* Blocks unauthorized local shell execution at the point of origin.
    *   *Con:* Brittle if local user account naming configurations change.
    *   *Solution:* Hardcoded string sanitization arrays inside the script initialization.
*   **Bit 1 (Value 2): User Group OK**
    *   *What it checks:* Verifies that the local user belongs strictly to the specialized administrative or development system groups.
    *   *Attack Vector Eliminated:* Prevents a secondary guest user or a lower-privilege service account on the machine from executing the gatekeeper.
    *   *Pro:* Prevents lateral local execution from system guests/lower-privilege daemons.
    *   *Con:* System updates can sometimes overwrite or reset local group policies.
    *   *Solution:* Script forces an explicit POSIX group ID validation check against the underlying system kernel.
*   **Bit 2 (Value 4): User ID OK**
    *   *What it checks:* Verifies the exact numerical User ID (UID) of the running process.
    *   *Attack Vector Eliminated:* Prevents privilege escalation tricks where an unauthorized user spins up a duplicate script named after the developer.
    *   *Pro:* Complete protection against simple script-renaming privilege escalation attacks.
    *   *Con:* Spawning processes from specialized docker containers can mask or alter runtime UIDs.
    *   *Solution:* Script forces a direct call to the core system kernel parameters to trace the parent execution process.
*   **Bit 3 (Value 8): User ID Role OK**
    *   *What it checks:* Validates that the active profile possesses verified Developer Clearance.
    *   *Attack Vector Eliminated:* Blocks secondary operators from triggering high-security commands or viewing private repository structures.
    *   *Pro:* Initial low-overhead administrative barrier before any network traffic is spun up.
    *   *Con:* Local account configuration files on the disk could be modified if an adversary achieves root storage privileges.
    *   *Solution:* This local layer is purely a baseline filter. If an attacker fakes this bit, they will still fail the uninjectable network-level factor gates later in the chain.

#### Digit 2: The Machine Core
*   **Bit 0 (Value 1): Machine Name OK**
    *   *What it checks:* Matches the system's local hostname against authorized machine names.
    *   *Attack Vector Eliminated:* Prevents an attacker from deploying the gatekeeper script configuration files onto a random computer with a generic hostname.
    *   *Pro:* Ensures basic configuration files cannot be dropped onto un-named baseline OS.
    *   *Con:* Hostname changes during system maintenance loops can lock out the script.
    *   *Solution:* Controlled through a focused `--scope machine` override string block.
*   **Bit 1 (Value 2): Machine Group / CPU ID / Motherboard UUID OK**
    *   *What it checks:* Reads raw hardware serial markers directly out of the motherboard DMI silicon chips (`/sys/class/dmi/id/product_uuid`) and maps the processor's hardware ID patterns.
    *   *Attack Vector Eliminated:* Absolute protection against Configuration Cloning. If an attacker copies the entire storage drive configuration onto an identical machine, the silicon signatures mismatch completely, flipping this bit to `0`.
    *   *Pro:* Completely destroys the utility of raw configuration drive cloning; when hard drives are physically stolen, they become useless on other hardware.
    *   *Con:* A legitimate hardware failure requiring a motherboard replacement will break this signature and completely brick access.
    *   *Solution:* Resolved cleanly by running an intentional, administrative `--override-scope machine` command flag to securely map the new silicon serials into the private inventory database.
*   **Bit 2 (Value 4): Machine ID OK**
    *   *What it checks:* Verifies the local unique machine ID stored inside the operating system core layers.
    *   *Attack Vector Eliminated:* Blocks unauthorized operating system re-installations or blind system-image swaps from mimicking a valid machine node.
    *   *Pro:* Protects the operating system image and blocks blind OS swaps.
    *   *Con:* Formatting or wiping the local OS partition destroys this identifier.
    *   *Solution:* Restored by executing the script's native `--scope install` mode flag to re-train the machine profile.
*   **Bit 3 (Value 8): Machine Role OK**
    *   *What it checks:* Validates that this specific node has permission to execute the requested command context (e.g., ensuring an edge outpost node cannot request an off-line mount meant strictly for the master machine).
    *   *Attack Vector Eliminated:* Prevents a compromised lower-priority machine on the network from executing broad lateral movement commands meant for high-security nodes.
    *   *Pro:* Enforces role-based perimeter isolation across the entire hardware farm.
    *   *Con:* Node network roles must be explicitly maintained across the network cluster.
    *   *Solution:* Hardcoded into the server-side architecture matrix rules.
### FACTOR 2: LOCAL PHYSICAL NETWORK PARAMETERS (DIGITS 3–4)
Analyzes direct network layer vectors, explicitly partitioning internal physical wires from external global internet routing paths.

#### Digit 3: The LAN Network (DOWNLINK)
*   **Bit 0 (Value 1): Machine IP OK**
    *   *What it checks:* Verifies that the machine network card is bound to its exact, authorized private static IP address.
    *   *Attack Vector Eliminated:* Blocks rogue devices that have intercepted the network from spoofing an endpoint over a dynamic DHCP address.
    *   *Pro:* Forces the device to occupy its exact re-allocated static network slot on the wire.
    *   *Con:* Local DHCP server crashes or router configuration resets can alter your IP assignment.
    *   *Solution:* Addressed cleanly by running `--override-scope network:lan` inside the local console session.
*   **Bit 1 (Value 2): Subnet Mask OK**
    *   *What it checks:* Validates the exact configuration of the local private network subnet mask boundaries.
    *   *Attack Vector Eliminated:* Prevents an attacker from isolating the machine inside a broad virtual subnet or a proxy network configuration to capture packet data.
    *   *Pro:* Detects deep network configuration anomalies or local router proxy redirections.
    *   *Con:* Changes to the internal network routing infrastructure can alter subnet boundaries.
    *   *Solution:* Handled through the `--override-scope network:lan` command loop.
*   **Bit 2 (Value 4): Gateway IP OK**
    *   *What it checks:* Verifies the exact local network IP address of the default gateway router interface.
    *   *Attack Vector Eliminated:* Blocks rogue router positioning or unauthorized router swaps. If a thief steals the computer and plugs it into their own home router, this bit drops instantly.
    *   *Pro:* The perimeter tripwire; when the machine is carried out of a datacenter and booted elsewhere, the default router gateway IP changes, breaking this bit instantly.
    *   *Con:* Replacing a dead home router will update this gateway profile and trigger a lockout.
    *   *Solution:* Fully resolved by executing the administrative `--override-scope network:lan` command flag to update the local network definitions.
*   **Bit 3 (Value 8): Cumulative LAN Anchor**
    *   *What it checks:* Master programmatic evaluation bit. It evaluates to binary `1` only if Bit 0, Bit 1, and Bit 2 of the LAN matrix are completely valid, allowing Digit 3 to compile as a clean hexadecimal `F`.
    *   *Attack Vector Eliminated:* Eliminates subtle race conditions or fragmented packet anomalies from passing through the security layers. If even one local LAN setting is wrong, the entire LAN matrix collapses instantly to `0`.
    *   *Pro:* Programmatic insurance policy which collapses the entire digit to `0` even if a single local network mask variable is manipulated.
    *   *Con:* Requires absolute synchronization of all local network properties.
    *   *Solution:* The script uses native bitwise logical math (`&`) to ensure these parameters evaluate as a single, unbreakable block.

#### Digit 4: The WAN Network (UPLINK)
*   **Bit 0 (Value 1): WAN IP OK**
    *   *What it checks:* Connects outbound to a secure network endpoint to pull and verify the external public IP routing signature.
    *   *Attack Vector Eliminated:* Absolute Perimeter Enclosure. If the machine leaves the physical residence, the external public IP shifts to an untrusted network gateway, instantly dropping this bit to `0`.
    *   *Pro:* Automatically tracks the external ISP routing footprint. When the machine is running on an outside internet gateway, the bit collapses.
    *   *Con:* If your internet provider resets the modem and assigns you a new dynamic external IP address, the script will instantly lock you out.
    *   *Solution:* Expected operational security behavior. Resolved easily by executing `--override-scope network:wan`, scanning the terminal QR block with the phone to prove physical safety at the machine to update the WAN signature.
*   **Bit 1 (Value 2): Subnet Mask OK**
    *   *What it checks:* Verifies the upstream provider's external subnet envelope structures.
    *   *Attack Vector Eliminated:* Prevents an attacker from using wide-area proxy loops or BGP routing traps to mask a foreign network location.
    *   *Pro:* Identifies complex wide-area proxy loops or BGP routing traps meant to spoof geographic locations.
    *   *Con:* Upstream ISP routing reconfigurations can alter these masks without notice.
    *   *Solution:* Restored automatically through the `--override-scope network:wan` handshake.
*   **Bit 2 (Value 4): Gateway IP OK**
    *   *What it checks:* Verifies the exact external gateway routing node utilized by your internet service provider.
    *   *Attack Vector Eliminated:* Blocks complex DNS hijacking or global traffic interception attempts.
    *   *Pro:* Validates the upstream provider node path, defending against high-level DNS hijacking.
    *   *Con:* External network routing nodes can fluctuate depending on your ISP's network load.
    *   *Solution:* Synced dynamically via the `--override-scope network:wan` loop.
*   **Bit 3 (Value 8): Cumulative WAN Anchor**
    *   *What it checks:* Master programmatic anchor for your global network layer. It evaluates to `1` only if Bit 0, Bit 1, and Bit 2 of the WAN core pass perfectly.
    *   *Attack Vector Eliminated:* Enforces a strict all-or-nothing boundary on your upstream internet connection, completely blocking sneaky, mixed network environments from faking a trusted state.
    *   *Pro:* Ensures the outbound global uplink is 100% structurally sound before exposing licensing or central servers to present the next step.
    *   *Con:* Highly sensitive to dynamic global routing changes.
    *   *Solution:* Utilizes fast bitwise operators to ensure the entire WAN profile acts as a single, absolute checkpoint.
### FACTOR 3: NETWORK LEVEL VALIDATION GATEWAY (DIGITS 5–6)
Validates the local hardware cluster context over the network wire before the machine is permitted to touch user databases.

#### Digit 5: The NETWORK Check - via an authentication daemon, like RADIUS (but can be any)
*   **Bit 0 (Value 1): RADIUS Server OK**
    *   *What it checks:* Confirms that the script can successfully open an active socket connection over the local network to a RADIUS server without throwing a `RADIUS_ERR_TIMEOUT`.
    *   *Attack Vector Eliminated:* Prevents an attacker from faking a successful backend authorization response by simulating or spoofing your core network servers.
    *   *Pro:* Verifies the physical presence and health of the OOB network verification nodes.
    *   *Con:* If the network cable is unplugged or the server container drops, this bit fails.
    *   *Solution:* Handled through the `--scope retry` loop to cleanly rebuild the socket interface.
*   **Bit 1 (Value 2): RADIUS ID OK**
    *   *What it checks:* Verifies that the container explicitly recognizes the incoming machine ID token and does not throw an `Access-Reject` payload.
    *   *Attack Vector Eliminated:* Blocks rogue, unknown hardware devices from attempting to probe your storage network.
    *   *Pro:* Restricts the backend RADIUS database from being probed by rogue, unregistered devices.
    *   *Con:* Corrupted local machine configurations can cause ID mismatches.
    *   *Solution:* Run the script with `--scope install` to securely re-register the client identity records.
*   **Bit 2 (Value 4): RADIUS Challenge OK**
    *   *What it checks:* Confirms that the connection does not throw an `Access-Challenge` state, meaning your 48-Hour Inactivity Clock is clean and your local cached tokens are valid.
    *   *Attack Vector Eliminated:* Thief Timeout Protection. If the computer has been powered down or disconnected for more than two days while being moved or hidden by a thief, this bit drops to `0`, locking the machine down automatically.
    *   *Pro:* Automatically closes the access window when the computer has been powered off or hidden inside a thief's vehicle for more than 48 hours.
    *   *Con:* If you go on an extended trip or turn off your servers for more than 2 days, your system will natively lock you out.
    *   *Solution:* Intended high-security behavior. Fixed easily by typing your manual `--scope retry` flag, which prompts your phone QR challenge loop to safely reset the 48-hour clock.
*   **Bit 3 (Value 8): RADIUS Auth OK**
    *   *What it checks:* Verifies that the RADIUS container hands back an absolute `Access-Accept` status flag, releasing a temporary, 64-second challenge token down to the script.
    *   *Attack Vector Eliminated:* Blocks unauthorized or partial network attachments from opening up resources, like file shares.
    *   *Pro:* Ensures a successful cryptographic network attachment before passing execution control to the identity layers.
    *   *Con:* Dependent on real-time server response times.
    *   *Solution:* Script uses optimized UDP timeouts to prevent processing bottlenecks.

#### Digit 6: The Network Check - Expansion Slot
*   **Bits 0 to 3:** This entire digit block is explicitly reserved for future multi-server unification loops or secondary backend daemons.
*   **Backward Compatibility:** When not actively in use, this digit evaluates to a clean, silent `F` (Value 15 / Binary `1111`), ensuring your core PoC functionality works perfectly without configuration bloat.
*   **Pro:** Total future-proofing, allowing stacking of secondary server daemons in the protocol without breaking the baseline client loop.

### FACTOR 4: USER LEVEL FACTOR AUTHENTICATION GATE (DIGITS 7–8)
Handles deep cryptographic identity gates, passing the connection token straight through phone biometric sensors or a physical desktop hardware token (e.g., YubiKey).

#### Digit 7: The BIOMETRICS Check (via Authentik - Block A)
*   **Bit 0 (Value 1): Authentik Server OK**
    *   *What it checks:* Confirms that the web API for Authentik is fully reachable (HTTP 200) and not throwing an internal server error or a 500 timeout.
    *   *Attack Vector Eliminated:* Blocks attempts to bypass authorization by flooding or knocking out the central identity server.
    *   *Pro:* Prevents a DoS or server-flood attack from mimicking a bypass validation state.
    *   *Con:* Internal Docker routing loops can sometimes cause temporary web dropouts.
    *   *Solution:* Automatic background reconnection limits managed by the `--scope retry` function.
*   **Bit 1 (Value 2): Authentik Client ID OK**
    *   *What it checks:* Verifies that Authentik recognizes the script's public client identifier and does not reject it with an `invalid_client` payload string.
    *   *Attack Vector Eliminated:* Blocks stolen or faked script configurations from attempting to query your user databases.
    *   *Pro:* Validates that the client application has explicit authorization cards inside the Authentik database.
    *   *Con:* If you delete or rebuild your Authentik application cards, the client ID changes.
    *   *Solution:* Easily corrected by running `--scope install` to re-sync the system parameters.
*   **Bit 2 (Value 4): Authentik Client Scope OK**
    *   *What it checks:* Verifies that the requested permission parameters match authorized system scopes, avoiding an `invalid_scope` error.
    *   *Attack Vector Eliminated:* Blocks an adversary from trying to escalate their permissions or access scopes using a stolen public ID.
    *   *Pro:* Eradicates scope-escalation attempts where a lower-tier script tries to read high-security data.
    *   *Con:* Requires exact string synchronization across files.
    *   *Solution:* Managed through standard, immutable configuration variables.
*   **Bit 3 (Value 8): Authentik Auth OK**
    *   *What it checks:* Confirms that Authentik's REST API establishes a successful, clean baseline handshake connection.
    *   *Attack Vector Eliminated:* Eliminates unexpected mid-session packet drops from mimicking a successful login.
    *   *Pro:* Confirms successful connection and validates that the session profile satisfies the server-side directory group constraints passed through the `--requires "[GROUP_NAME]"` argument.
    *   *Con:* Dependent on active web processing lines.
    *   *Solution:* Kept stateless in memory to avoid local cache corruption.

#### Digit 8: The BIOMETRICS Check (via Authentik - Block B)
*   **Bit 0 (Value 1): Authentik Endpoint OK**
    *   *What it checks:* Confirms that your script's background parsing loop is communicating cleanly without triggering a `slow_down` error.
    *   *Attack Vector Eliminated:* Blocks automated script exploits from trying to brute-force or hammer the identity tokens.
    *   *Pro:* Native anti-hammer throttling protection.
    *   *Con:* Network lag can trick the loop timing.
    *   *Solution:* Script automatically increases its internal sleep counters if this bit drops.
*   **Bit 1 (Value 2): Authentik Authorization OK**
    *   *What it checks:* Maps to the `authorization_pending` state. This bit natively starts at `0` during a cold boot, flipping to `1` only after you scan the QR code and tap your phone's biometric sensor.
    *   *Attack Vector Eliminated:* Complete protection against automated terminal entry. The system will stay locked until a real human physically interacts with an independent device.
    *   *Pro:* The human presence shield. Natively starts at `0`, making remote automated terminal entry impossible.
    *   *Con:* Deliberately breaks the `FFFFFFFFFF` target string until you perform the manual action.
    *   *Solution:* Primary defense loop. The script reads this initial `0`, treats it as an expected holding pattern, and generates the high-contrast ANSI text QR code right inside the SSH terminal.
*   **Bit 2 (Value 4): Authentik Expiration OK**
    *   *What it checks:* Monitors your active authentication session timeline, ensuring the connection does not throw an `expired_token` error code.
    *   *Attack Vector Eliminated:* Prevents a thief from sitting at your desk and trying to utilize an old, already-opened terminal token block from a previous session.
    *   *Pro:* Imposes a strict and short-lived 5-minute lifespan window on the terminal session challenge.
    *   *Con:* If you get distracted and take more than 5 minutes to scan the terminal QR code with your phone, this bit drops to `0`.
    *   *Solution:* Solved by running a targeted `--scope 2fa` flag to instantly pull down a fresh, clean challenge screen.
*   **Bit 3 (Value 8): Authentik Access OK**
    *   *What it checks:* Confirms that the login session has been granted absolute, clean permission clearance and has not been rejected with an `access_denied` JSON error string.
    *   *Attack Vector Eliminated:* Instantly catches if a user attempts to log into the terminal console using an unauthorized profile or a revoked credential token.
    *   *Pro:* Instantly tracks and locks out revoked, expired, or manually blacklisted user credentials.
    *   *Con:* Accidentally tapping "Deny" on your mobile phone screen will lock down the terminal.
    *   *Solution:* Simply enter `--scope 2fa` to restart the identity handshake loop.

### FACTOR 5: DYNAMIC CUSTOM LOGIC, TRIPLINES & CHECKSUMS (DIGITS 9-10+)
Houses private custom, exchangeable canary traps, background daemons, and mathematical protection checksums. If the checksum validates perfectly but environmental bits return an untrusted state (e.g., `OK:FF998FC800`), the application can run a "Poisoned/Demo instance". This functions normally to the thief but generates randomized fake outputs to corrupt their research, while using its backend licensing threads to silently ping the homeserver with all location metrics.

#### Digit 9: The Expansion & Canary Control
*   **The Blueprint Logic:** This digit block serves a dual purpose. In a standard home network setup, it houses your custom, exchangeable background green-light daemons and canary birds.
*   **The Canary Behavior:** Under trusted conditions inside your home, background canary checks succeed, keeping bits at `1`. When all bits pass, the digit evaluates to a clean, silent `F`. If a machine is moved or an integrity daemon drops its signal, the bit flips to `0`, dropping the digit below `F` and instantly triggering the silent telemetry snare.
*   **The Dynamic Switch Extension:** As designed, this digit also tells the script if extra infrastructure characters have been appended to the payload string, serving as your layout's scalability lock.
*   **Pro:** Dynamic scalability; allows the protocol to morph on the fly from a 10-character local mask into an enterprise-proof licensing system.

#### Digit 10+: The Cryptographic Checksum Gate
*   **The Blueprint Logic:** Sits at the absolute final character positions of the string. It computes a local mathematical verification total over the numeric integer values of every single character preceding it in the payload.
*   **Attack Vector Eliminated:** Complete Protection Against Man-in-the-Middle Packet Injection. If an attacker tries to hack the network interface or manipulate the bits in transit to trick resources into becoming available, the checksum breaks instantly, dropping the final digits below `F` and locking down the resource natively.
*   **Pro:** Absolute Invariant Protection. Ensures that an intercepted packet cannot be manipulated or modified by a MITM injection attack without corrupting the mathematical remainder, locking down systems automatically.

---

## 6. Token Expansion & Checksum Math

Argorithm leverages a Reverse Hexadecimal Bit Switch to smoothly scale the string from a local gatekeeper mask into a distributed cloud or enterprise licensing payload without breaking backward compatibility or altering the core client parsing loop.

### 1. The Reverse Hexadecimal Expansion Switch (Digit 9)
Digit 9 serves as the structural master gatekeeper for the payload's total length. Instead of hardcoding a fixed size or using overhead-heavy length delimiters, Argorithm reads the character in the 9th slot to dynamically determine how many infrastructure digits follow before the final checksum block.

The protocol evaluates the 4 bits of Digit 9 as a **Countdown Switch**:

| Digit 9 Value | Binary Mask | Expansion Result | Total String Length |
| :---: | :---: | :--- | :---: |
| **F** | 1111 | No Expansion (Standard Baseline) | 10 Char |
| **E** | 1110 | 2 Extra Digits Appended | 12 Char |
| **D** | 1101 | 4 Extra Digits Appended | 14 Char |
| **C** | 1100 | 6 Extra Digits Appended | 16 Char |
| **B** | 1011 | 10 Extra Digits Appended | 20 Char |

#### How the Client Parsing Loop Executes this Logic:
1.  The script captures the raw string payload from the network socket or API response (e.g., `OK:FFFFFFFFFF` or `OK:FFFFFFFFE00FF`).
2.  The script immediately reads the character sitting at array index position 9.
3.  If the value is `F`, the script knows it is running in standard local mode. It looks for a single check-character at index position 10 to execute its Modulo-16 Checksum.
4.  If the value drops to `E` or below, the script dynamically shifts its array parameters. It skips down the newly defined block size, reads the expanded infrastructure/canary variables, and looks for the final two characters at the absolute end of the string to execute its Modulo-256 Checksum.

---

### 2. The Multi-Tiered Checksum Verification Math

Argorithm handles its integrity checks using two distinct, optimized mathematical validation loops:

#### Tier A: Modulo-16 Sum Check (Standard Baseline Mode / 1 Hex Character / 4 Bits)
When Digit 9 evaluates to F, the protocol sits at its 10-character baseline. The final character (Digit 10) houses a lightweight Modulo-16 validation total.

$$
\text{Checksum} = \left( \sum_{n=1}^{9} \text{Integer Value}(\text{Digit}_n) \right) \pmod{16}
$$


##### Python Verification Implementation:
```python
def verify_modulo_16(status_string):
    # Strip 'OK:' prefix and isolate payload
    payload = status_string.split(":")[-1]
    
    # Isolate the data digits (1 through 9)
    data_digits = payload[:9]
    # Isolate the final checksum character
    received_checksum = payload[-1]
    
    # Calculate the sum of the hex integer values
    total_sum = sum(int(char, 16) for char in data_digits)
    # Compute the Modulo-16 remainder
    calculated_checksum = format(total_sum % 16, 'X')
    
    return calculated_checksum == received_checksum
```


#### Tier B: Modulo-256 Sum Check (Distributed Cloud Mode / 2 Hex Characters / 8 Bits)
When Digit 9 drops to E or below, the protocol expands. To prevent hash collisions over a longer data string, the protocol automatically drops the Modulo-16 check and enforces a full, 1-byte Modulo-256 Sum Check using the final two characters of the string.

$$
\text{Checksum} = \left( \sum_{n=1}^{\text{End}-2} \text{Integer Value}(\text{Digit}_n) \right) \pmod{256}
$$



##### Python Verification Implementation:
```python
def verify_modulo_256(status_string):
    payload = status_string.split(":")[-1]
    
    # Isolate the final 2-digit checksum block
    received_checksum = payload[-2:]
    # Isolate all data digits preceding the checksum block
    data_digits = payload[:-2]
    
    # Convert every hex character to its integer value and sum them up
    total_sum = sum(int(char, 16) for char in data_digits)
    # Compute the Modulo-256 remainder formatted as a 2-digit uppercase hex 
    calculated_checksum = format(total_sum % 256, '02X')
    
    return calculated_checksum == received_checksum
```

---

### 3. Absolute Mathematical Proof Against Tampering

This dual-tier layout ensures that an adversary cannot manually flip an environment or hardware bit to manipulate the status code. If a thief boots a stolen machine, causing the WAN Network (Digit 4) to drop from `F` to `9`, the cumulative integer total of the string changes.

In a standard, naive protocol, an attacker could attempt to manipulate a trailing canary bit to "balance out" the sum. In Argorithm, because the final digits must match a precise remainder calculation based on your private, customized bit layout, any un-synchronized alteration breaks the checksum loop completely.

The verification engine immediately drops the payload below `FFFF`, completely blocks access to resources, and drops the machine into a hidden, silent telemetry snare to expose the unauthorized activity transparently.

---

**Copyright (C) 2026 Gunther Voet. All Rights Reserved.**  
*Codenamed: Argorithm (Context-Attestation Protocol / Version 0.2 PoC)*

This documentation and the underlying reference code are free software: you can redistribute them and/or modify them under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This architecture is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
