"""
SSH orchestration layer.

This wraps Paramiko so the rest of the app never has to think about
transports/channels directly. One SSHManager instance == one logical
"hop chain": jump server -> (optional trusted superuser hop) -> destination.

No password or OTP is ever written to disk or logged. Callers should
discard the plaintext credentials as soon as they're used.
"""

import shlex
import socket
import paramiko


class SSHConnectionError(Exception):
    """Raised whenever a hop in the chain fails to authenticate or connect."""


class SSHManager:
    def __init__(self):
        self._transport = None   # active paramiko.Transport for the current hop
        self._client = None      # paramiko.SSHClient wrapping _transport, for exec_command
        self._transport_stack = []  # transports for every earlier hop, so go_back() can undo one

    # ------------------------------------------------------------------
    # Hop 1: jump server, keyboard-interactive (First Factor / Second Factor)
    # ------------------------------------------------------------------
    def connect_jump_keyboard_interactive(self, host, username, first_factor,
                                           second_factor, port=22, timeout=15):
        def handler(title, instructions, prompt_list):
            responses = []
            for prompt, _echo in prompt_list:
                label = prompt.strip().lower().rstrip(":").strip()
                if "first factor" in label:
                    responses.append(first_factor)
                elif "second factor" in label:
                    responses.append(second_factor)
                else:
                    # Unknown prompt: fail closed rather than guessing.
                    responses.append("")
            return responses

        transport = paramiko.Transport((host, port))
        try:
            transport.start_client(timeout=timeout)
            transport.auth_interactive(username, handler)
        except (paramiko.SSHException, socket.error) as exc:
            transport.close()
            raise SSHConnectionError(f"Could not connect to {host}: {exc}") from exc

        if not transport.is_authenticated():
            transport.close()
            raise SSHConnectionError("Access denied")

        self._set_active(transport)
        return True

    # ------------------------------------------------------------------
    # Direct connect with a plain password (used for the trusted superuser
    # hop, e.g. informix@10.11.56.185, and for simple direct connections)
    # ------------------------------------------------------------------
    def connect_password(self, host, username, password, port=22, timeout=15):
        transport = paramiko.Transport((host, port))
        try:
            transport.start_client(timeout=timeout)
            transport.auth_password(username, password)
        except (paramiko.SSHException, socket.error) as exc:
            transport.close()
            raise SSHConnectionError(f"Could not connect to {host}: {exc}") from exc

        if not transport.is_authenticated():
            transport.close()
            raise SSHConnectionError("Authentication failed")

        self._set_active(transport)
        return True

    # ------------------------------------------------------------------
    # Multi-hop: tunnel a new SSH session through the currently active
    # transport to reach a further host (e.g. jump -> destination, or
    # superuser host -> a same-VLAN trusted host).
    # ------------------------------------------------------------------
    def hop_password(self, host, username, password, port=22, timeout=15):
        if not self._transport:
            raise SSHConnectionError("No active session to hop from")

        try:
            channel = self._transport.open_channel(
                "direct-tcpip", (host, port), ("127.0.0.1", 0), timeout=timeout
            )
        except paramiko.SSHException as exc:
            msg = str(exc)
            if "Administratively prohibited" in msg:
                return self._hop_via_remote_tcp_proxy(host, username, password, port=port, timeout=timeout)
            raise SSHConnectionError(f"Could not open tunnel to {host}: {msg}") from exc

        next_transport = paramiko.Transport(channel)
        try:
            next_transport.start_client(timeout=timeout)
            next_transport.auth_password(username, password)
        except (paramiko.SSHException, socket.error) as exc:
            next_transport.close()
            raise SSHConnectionError(f"Could not connect to {host}: {exc}") from exc

        if not next_transport.is_authenticated():
            next_transport.close()
            raise SSHConnectionError(f"Authentication to {host} failed")

        # Keep the previous transport around so the channel it owns stays
        # open (closing it would kill the tunnel underneath next_transport).
        self._transport_stack.append(self._transport)
        self._set_active(next_transport)
        return True

    def hop_trusted(self, host, username, port=22, timeout=15, pkey=None):
        """
        Hop to a same-VLAN trusted host without a password, using a
        service key already trusted there (i.e. this backend's public
        key is in ~/.ssh/authorized_keys on the destination for
        `username`). `pkey` must be a loaded paramiko PKey object -
        pass None and this raises immediately with a clear message
        rather than attempting SSH's "none" auth method, which is not
        a real login mechanism (it exists so a client can ask which
        auth types a server allows) and will not succeed against a
        properly configured sshd.
        """
        if not self._transport:
            raise SSHConnectionError("No active session to hop from")
        if pkey is None:
            raise SSHConnectionError(
                "No service key configured for trusted hops. Set "
                "TRUSTED_HOP_PRIVATE_KEY_PATH in settings (and make sure "
                "this backend's matching public key is in "
                "~/.ssh/authorized_keys on the destination host), or use "
                "a password hop instead."
            )

        try:
            channel = self._transport.open_channel(
                "direct-tcpip", (host, port), ("127.0.0.1", 0), timeout=timeout
            )
        except paramiko.SSHException as exc:
            msg = str(exc)
            if "Administratively prohibited" in msg:
                return self._hop_via_remote_tcp_proxy(host, username, password=None, port=port, timeout=timeout, pkey=pkey)
            raise SSHConnectionError(f"Could not open tunnel to {host}: {msg}") from exc

        next_transport = paramiko.Transport(channel)
        try:
            next_transport.start_client(timeout=timeout)
            next_transport.auth_publickey(username, pkey)
        except (paramiko.SSHException, socket.error) as exc:
            next_transport.close()
            raise SSHConnectionError(f"Trusted hop to {host} failed: {exc}") from exc

        if not next_transport.is_authenticated():
            next_transport.close()
            raise SSHConnectionError(f"Trusted hop to {host} failed authentication")

        self._transport_stack.append(self._transport)
        self._set_active(next_transport)
        return True

    def _open_remote_tcp_proxy_channel(self, host, port=22, timeout=15):
        if not self._transport:
            raise SSHConnectionError("No active session to hop from")

        remote_host = shlex.quote(host)
        remote_port = shlex.quote(str(port))
        proxy_command = (
            f"sh -c 'exec nc {remote_host} {remote_port} 2>/dev/null || "
            f"exec socat STDIO TCP:{remote_host}:{remote_port}'"
        )

        channel = self._transport.open_session()
        try:
            channel.exec_command(proxy_command)
        except paramiko.SSHException as exc:
            channel.close()
            raise SSHConnectionError(
                f"Could not open remote proxy to {host}: {exc}"
            ) from exc
        return channel

    def _hop_via_remote_tcp_proxy(self, host, username, password=None, port=22,
                                   timeout=15, pkey=None):
        channel = self._open_remote_tcp_proxy_channel(host, port, timeout)
        next_transport = paramiko.Transport(channel)
        try:
            next_transport.start_client(timeout=timeout)
            if pkey is not None:
                next_transport.auth_publickey(username, pkey)
            else:
                next_transport.auth_password(username, password or "")
        except (paramiko.SSHException, socket.error) as exc:
            next_transport.close()
            raise SSHConnectionError(
                f"Could not hop to {host} via remote proxy: {exc}"
            ) from exc

        if not next_transport.is_authenticated():
            next_transport.close()
            raise SSHConnectionError(f"Authentication to {host} failed")

        self._transport_stack.append(self._transport)
        self._set_active(next_transport)
        return True

    # ------------------------------------------------------------------
    def run(self, command, timeout=30):
        """
        Run one shell command on the currently active (innermost) host.
        Each call is a fresh shell, so anything that needs the sourced
        environment (e.g. `. /mcp_qasi`) must be chained in the same
        command string:

            manager.run(". /mcp_qasi && echo \"select ...\" | dbaccess sysmaster -")
        """
        if not self._client:
            raise SSHConnectionError("No active SSH session")

        stdin, stdout, stderr = self._client.exec_command(command, timeout=timeout)
        out = stdout.read().decode(errors="replace")
        err = stderr.read().decode(errors="replace")
        exit_code = stdout.channel.recv_exit_status()
        return {"stdout": out, "stderr": err, "exit_code": exit_code}

    def close(self):
        if self._client:
            self._client.close()
        for transport in reversed(self._transport_stack):
            try:
                transport.close()
            except Exception:
                pass
        self._transport_stack = []

    # ------------------------------------------------------------------
    def can_go_back(self):
        """Whether there's an earlier hop to undo."""
        return bool(self._transport_stack)

    def go_back(self):
        """Undo the most recent hop: close the current (innermost) transport
        and reactivate whichever one was active immediately before it.
        Everything further back in the chain stays open and untouched."""
        if not self._transport_stack:
            raise SSHConnectionError("No previous host to go back to")
        previous_transport = self._transport_stack.pop()
        if self._client:
            self._client.close()
        self._set_active(previous_transport)
        return True

    # ------------------------------------------------------------------
    def _set_active(self, transport):
        self._transport = transport
        client = paramiko.SSHClient()
        client._transport = transport  # noqa: SLF001 - intentional, paramiko has no public setter
        self._client = client
