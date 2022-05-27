"""
Pass Renderer for Salt
======================

pass_ is an encrypted on-disk password store.

.. _pass: https://www.passwordstore.org/

.. versionadded:: 2017.7.0

Setup
-----

*Note*: ``<user>`` needs to be replaced with the user salt-master will be
running as.

Have private gpg loaded into ``user``'s gpg keyring

.. code-block:: yaml

    load_private_gpg_key:
      cmd.run:
        - name: gpg --import <location_of_private_gpg_key>
        - unless: gpg --list-keys '<gpg_name>'

Said private key's public key should have been used when encrypting pass entries
that are of interest for pillar data.

Fetch and keep local pass git repo up-to-date

.. code-block:: yaml

        update_pass:
          git.latest:
            - force_reset: True
            - name: <git_repo>
            - target: /<user>/.password-store
            - identity: <location_of_ssh_private_key>
            - require:
              - cmd: load_private_gpg_key

Install pass binary

.. code-block:: yaml

        pass:
          pkg.installed

Configuration options

.. code-block:: yaml

        # If the prefix is set, only the prefixed template variables are
        # considered for fetching secrets from Pass. The default behavior
        # is that *all* variables are considered.
        # When the prefix matching is on, You may also consider
        # setting the `renderer: jinja|yaml|pass` config option.
        # recommended value: 'pass:'
        pass_variable_prefix: 'pass:'

        # If set to 'true', error out when Pass is unable to fetch a secret
        # for a template variable. Must be used with `pass_variable_prefix`.
        pass_strict_fetch: true

        # set GNUPGHOME env for Pass
        # defaults to ~/.gnupg
        pass_gnupghome: <path>

        # set PASSWORD_STORE_DIR env for Pass
        # defaults to ~/.password-store
        pass_path: <path>
"""


import logging
import os
from os.path import expanduser
from subprocess import PIPE, Popen

import salt.utils.path
from salt.exceptions import SaltRenderError

log = logging.getLogger(__name__)


def _get_pass_exec():
    """
    Return the pass executable or raise an error
    """
    pass_exec = salt.utils.path.which("pass")
    if pass_exec:
        return pass_exec
    else:
        raise SaltRenderError("pass unavailable")


def _fetch_secret(pass_path):
    """
    Fetch secret from pass based on pass_path. If there is
    any error, return back the original pass_path value
    """

    # Remove the optional prefix from pass path
    pass_prefix = __opts__.get("pass_variable_prefix", None)
    if pass_prefix:
        # If we do not see our prefix we do not want to process this variable
        if not pass_path.startswith(pass_prefix):
            return pass_path

        # strip the prefix from the start of the string
        pass_path = pass_path[len(pass_prefix):]

    # The pass_strict_fetch option must be used with pass_variable_prefix
    pass_strict_fetch = __opts__.get("pass_strict_fetch", False)
    if pass_strict_fetch and not pass_prefix:
        msg = "The 'pass_strict_fetch' option requires 'pass_variable_prefix' option enabled"
        raise SaltConfigurationError(msg)

    # Remove whitespaces from the pass_path
    pass_path = pass_path.strip()

    cmd = ["pass", "show", pass_path]
    log.debug("Fetching secret: %s", " ".join(cmd))

    # Make sure environment variable HOME is set, since Pass looks for the
    # password-store under ~/.password-store.
    env = os.environ.copy()
    env["HOME"] = expanduser("~")

    if "pass_dir" in __opts__:
        env["PASSWORD_STORE_DIR"] = __opts__["pass_dir"]

    if "pass_gnupghome" in __opts__:
        env["GNUPGHOME"] = __opts__["pass_gnupghome"]

    proc = Popen(cmd, stdout=PIPE, stderr=PIPE, env=env)
    pass_data, pass_error = proc.communicate()

    # The version of pass used during development sent output to
    # stdout instead of stderr even though its returncode was non zero.
    if proc.returncode or not pass_data:
        msg = "Could not fetch secret '{}' from the password store: {}".format(pass_path, pass_error)
        if pass_strict_fetch:
            raise SaltRenderError(msg)
        else:
            log.warning(msg)
        log.warning("Could not fetch secret: %s %s", pass_data, pass_error)
        pass_data = pass_path
    return pass_data.rstrip("\r\n")


def _decrypt_object(obj):
    """
    Recursively try to find a pass path (string) that can be handed off to pass
    """
    if isinstance(obj, str):
        return _fetch_secret(obj)
    elif isinstance(obj, dict):
        for pass_key, pass_path in obj.items():
            obj[pass_key] = _decrypt_object(pass_path)
    elif isinstance(obj, list):
        for pass_key, pass_path in enumerate(obj):
            obj[pass_key] = _decrypt_object(pass_path)
    return obj


def render(pass_info, saltenv="base", sls="", argline="", **kwargs):
    """
    Fetch secret from pass based on pass_path
    """
    _get_pass_exec()
    return _decrypt_object(pass_info)
