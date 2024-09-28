This module was created to check for CVE-2024-47176 vulnerabilities against remote hosts. It works by opening a TCP port in a LISTEN state, sending a specific UDP payload to the target on UDP/631 (default) and then checking to see if the TCP socket receives any data. If it does, the host is considered potentially vulnerable. You must specify the RHOST and the LADDR for this to work. In addition, any firewalls (host or network) in the way preventing UDP/631 reaching the target and/or preventing any TCP traffic to the specified LPORT (TCP/8080 by default) will cause this module to not detect anything as both of these network streams are required.
