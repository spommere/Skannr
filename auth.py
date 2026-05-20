"""Reserved for future remote-access authentication.

Skannr currently serves plain HTTP and leaves access control to localhost,
trusted networks, VPNs, SSH tunnels, or a reverse proxy. Keep this module empty
until the app grows real remote-login support; importing it should not change
the security model by accident.
"""

# This module is a placeholder on purpose. Do not add "quick" password checks
# here unless the rest of the request handling and deployment model is also
# changed; partial authentication would be misleading for remote use.
