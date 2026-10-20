"""Bubblewrap sandbox CLI (`bk`)."""

from __future__ import annotations

import json
import logging
import os
import pwd
import re
import sys
import tomllib
from collections.abc import Mapping, Sequence
from pathlib import Path

import click

log = logging.getLogger(__name__)

RUN_HELP = """Run a command inside a bubblewrap sandbox.

Pass the executable and its arguments after any wrapper options. They are run
inside the sandbox. Wrapper options are --debug, feature toggles, network
controls, and dbus-proxy filters; everything else is forwarded as the
sandboxed command.

With no command, a login shell is started inside the sandbox so the environment
can be inspected.


# Features

Optional permission sets are grouped by topic (user, cursor, python, ssh, ...).
Only ``user`` is on by default; other built-ins are opt-in. Features are
registered via the buddelkiste.features entry-point group (third-party packages
can add more). Toggle with --feature / --no-feature, or in config. Define
pure-TOML features under [feature.<name>]. Use `bk list-features` to print the
catalog (includes module paths).

Config may set features globally and per executable. The command may be a
bare name or an absolute path; matching uses only the file name, not the
directory. A list selects exactly those features;
a table applies true/false overrides. Per-executable config may also set
network and args (extra arguments appended to the command).

For each configured executable, `bk shims install` can place a PATH wrapper
in $XDG_DATA_HOME/buddelkiste/shims that runs the real binary via `bk run`.
Install also writes a POSIX snippet and sources it from existing ~/.bashrc
and ~/.zshrc so interactive shells prepend that directory and run
`bk shims check --quiet`. Use `bk shims check` to detect originals that
shadow those shims on PATH. `bk shims list` prints each shim and the
host binary it would run.


# Network

Modes: filter (default; private netns via pasta or slirp4netns with
in-namespace nftables IP/CIDR allow/deny), host (share host network), none
(no connectivity). Filter mode needs no root and no reserved host subnets.
Default policy is allow: public egress is accepted. The ``internal`` and
``localhost`` deny presets reject private ranges (RFC1918/ULA) and loopback.
Host loopback is additionally blocked by pasta/slirp. policy deny rejects every
destination that is not listed in allow. The chain policy stays drop because a
base chain cannot use reject as its policy.

In filter mode, a resolv.conf that is only a loopback stub is relayed to that
stub from the host netns, so systemd-resolved keeps split-DNS and chooses the
uplinks. Other nameserver IPs from /etc/resolv.conf are auto-allowed so DNS
keeps working under policy deny. Rules may be IP/CIDR literals or hostnames
(exact or *.suffix); hostnames use a DNS proxy that publishes resolved
A/AAAA addresses into dynamic nft sets. Named presets (internal, private,
localhost, linklocal, metadata, plus custom names under [network.presets])
expand to IP/CIDR or hostname rules. Pass them with --net-allow-preset or
--net-deny-preset; see `bk list-net-presets`.


# D-Bus proxy

The dbus-proxy feature exposes the session bus through xdg-dbus-proxy instead
of the host socket (it conflicts with dbus). With no filter rules the proxy is
unfiltered. Set any of see, talk, own, call, or broadcast — in [dbus_proxy],
under executables.<name>.dbus_proxy, or with --dbus-see / --dbus-talk /
--dbus-own / --dbus-call / --dbus-broadcast — to pass --filter and only those
rules. CLI values append to the configured list for that key. An explicit
empty list turns filtering on without rules of that kind.

Names are well-known bus names; a .* suffix matches that name and its children
(org.freedesktop.portal.* matches org.freedesktop.portal and
org.freedesktop.portal.Desktop, not org.freedesktop.portalextra). talk implies
see for that name; own implies talk and see. call and broadcast values are
NAME=RULE, where RULE is [METHOD][@PATH]. METHOD is *, an interface,
interface.*, or interface.member. PATH is an object path with an optional /*
suffix.


# Configuration

Configuration is read from ~/.config/buddelkiste/config.toml. The file
supports the following top-level keys:

features: Global feature selection. Either a list of feature names (allowlist)
or a table of feature name = true/false overrides.

feature: Table of custom feature definitions under [feature.<name>]. Each may
set description, default, env (allowlisted variable names), binds (list of
source-or-glob/target/mode tables), and conflicts_with (other feature names that must
not be enabled at the same time). Bind paths may use $VAR or ${VAR}. Packages
may also register features via the buddelkiste.features entry-point group.
Before starting, bk refuses launches with conflicting mounts, conflicting
--setenv values (host-forwarded or setup-defined), or mutually exclusive
features.

executables: Table keyed by executable file name. A path key is matched by its
file name only, so the same entry applies to a bare command or any absolute
path to that file. When several keys share a file name, the first one wins.
Each entry may contain a features list or table, a network table, an args list
of extra arguments appended to the command, and/or a shim boolean (override
the global shims toggle), applied when that executable is started.

projects: List of tables (``[[projects]]``) with a mandatory path. The most
specific path that covers the current working directory is active: that tree
is always bound read-write, and an optional features list or table is applied
after the executable's features. Nested keys such as network.mode stay on the
same array element. Feature defaults → global features →
executables.<name>.features → project features → --feature / --no-feature.
`bk info [EXECUTABLE]` prints that merged view (plus resolved network and
dbus-proxy) as TOML for the current directory.

shims: Global boolean (default true). When true, `bk shims install` creates
PATH wrappers for configured executables; set false to disable unless an
entry sets shim = true. Per-executable shim overrides this default.

network: Global network settings (mode, policy, allow, deny, allow_presets,
deny_presets). Optional [network.presets] defines custom named lists used by
either allow_presets or deny_presets. See example.

binds: List of additional bind mounts for the sandbox. Each table has either
"source" (one host path) or "glob" (a shell-style pattern matching files and
directories), plus optional "target" and "mode". A "glob" entry binds every
match with the same settings. "nullglob" (boolean, default false) allows a
glob to match nothing; otherwise an empty match is an error. The "target"
key is optional: with "source" it is the mountpoint (default: the host path);
with "glob" it is a directory and each match is mounted at target/<basename>.
The "mode" key defaults to "ro" (read-only). Other modes: "rw" (read-write
bind), "tmp-overlay" (writable via ephemeral overlayfs; host source unchanged),
"overlay" (writable via overlayfs with a persistent upper under
$XDG_CACHE_HOME/buddelkiste/overlays/<hash-of-source>), or
"overlay:<path>" (explicit persistent upper; <path> may use $VAR / ${VAR}).
Bind paths and glob patterns may use $VAR or ${VAR}.

envvars: List of additional environment variables for the sandbox. The mandatory
"name" key gives the name of the variable. The value can be specified in the
"value" key. If no value is given, it is taken from the process environment.

dbus_proxy: Optional table used by the dbus-proxy feature. Keys see, talk, own,
call, and broadcast are lists of xdg-dbus-proxy rules. see/talk/own are
well-known names (optional .* suffix). call and broadcast entries are
NAME=RULE. Any key that is present enables --filter; CLI --dbus-* flags append.
Per-executable executables.<name>.dbus_proxy overrides the same keys. With no
rules the proxy is unfiltered.

docker_proxy: Optional table used by the docker-proxy feature. Declares allowlisted
images (and related policy) for the project. Host enforcement lives under
~/.config/buddelkiste/docker-proxy/; use `bk docker-policy apply` to promote the
declaration. Unknown images hold until `bk docker-policy approve` /
`deny` when approval.on_unknown_image is "session" (the default). Mutually
exclusive with the raw docker and docker-instance features.

docker_instance: Optional table for the docker-instance feature (project-local
rootless dockerd). Keys: data_root (default under XDG_DATA_HOME), fs
(host|project|data), fs_allow, net (host|userspace|none), proxy (default true),
remove_data_on_teardown (default false; wipe data_root when the sandbox exits),
storage_driver (auto|overlay2|fuse-overlayfs|vfs; auto omits dockerd's flag),
and nested [docker_instance.policy] (same shape as docker_proxy, with instance
defaults that allow build and images=["*"]). `bk docker-instance list` shows
per-project store sizes; `bk docker-instance prune` deletes them. Mutually
exclusive with docker and docker-proxy. Override remove_data_on_teardown for one
run with --docker-instance-remove-data / --keep-docker-instance-data, and the
storage driver with --docker-instance-storage-driver. Switching drivers on a
non-empty data_root needs prune first.

## Example for a ~/.config/buddelkiste/config.toml configuration

\b
  # Global allowlist (exactly these features)
  features = ["git", "ssh", "python", "rust"]

\b
  [network]
  mode = "filter"
  # Default is "allow" (public egress; private and loopback stay denied).
  policy = "deny"
  allow = ["1.1.1.1/32", "api.github.com", "*.pypi.org"]
  deny = ["203.0.113.0/24"]
  deny_presets = ["metadata", "linklocal", "corp"]
  # allow_presets = ["metadata"]  # same names as deny_presets, added to allow

\b
  [dbus_proxy]
  talk = ["org.freedesktop.Notifications", "org.freedesktop.portal.*"]
  call = ["org.freedesktop.portal.*=*"]
  broadcast = ["org.freedesktop.portal.*=@/org/freedesktop/portal/*"]

\b
  [executables.cursor-agent.dbus_proxy]
  own = ["org.example.MyApp"]

\b
  [network.presets]
  corp = ["10.50.0.0/16", "*.internal.example.com"]

\b
  [executables.cursor-agent]
  features = ["cursor", "git", "ssh", "gui"]
  args = ["--force"]

\b
  [executables.cursor-agent.network]
  mode = "filter"
  policy = "deny"
  allow = ["1.1.1.1/32"]

\b
  [executables.python]
  features = ["python", "git"]
  shim = false

\b
  [[projects]]
  path = "/home/me/src/myapp"
  features = { python = true, rust = true }
  network.mode = "filter"

\b
  # shims = false  # disable PATH shims globally (per-entry shim=true still wins)

\b
  [[binds]]
  source = "/path/to/directory"  # path is whitelisted for the sandbox
  mode = "ro"  # or "rw", "tmp-overlay", "overlay", "overlay:$XDG_CACHE_HOME/bk-upper"

\b
  [[binds]]
  glob = "${HOME}/.config/git*"
  mode = "ro"

\b
  [[binds]]
  glob = "${HOME}/.ssh/id_*"
  nullglob = true
  mode = "ro"

\b
  [[envvars]]
  name = "MYENVVAR"
  value = "example value"  # delete this line to use the value from the environment


# Working directory

The current working directory must be visible inside the sandbox. If it is not
covered by any bind, the script asks yes (this run), always (persist a
[[projects]] entry), or no (abort), then which features to enable.
Non-interactively it exits with an error instead.
"""

from buddelkiste.binds import ROBindConfig, RWBindConfig, bind_config, get_bind_args
from buddelkiste.conflicts import check_launch_conflicts
from buddelkiste.docker_instance import STORAGE_DRIVERS
from buddelkiste.features import (
    FEATURES,
    binds_from_spec,
    check_feature_requirements,
    feature_binds,
    feature_env_var_names,
    feature_names,
    feature_setup,
    format_features_help,
    load_feature_registry,
    lookup_executable_config,
    lookup_project_config,
    resolve_features,
)
from buddelkiste.network import (
    format_deny_presets_help,
    load_deny_preset_registry,
    resolve_network,
    run_bwrap,
)
from buddelkiste.shims import (
    check_shims,
    global_shims_enabled,
    install_shim_hook,
    install_shims_from_config,
    list_shim_names,
    list_shims,
    shim_decisions_from_config,
    shim_dir,
    shim_dir_on_path,
    shim_names_from_config,
)

env = os.getenv

CONFIG_PATH = Path("~/.config/buddelkiste/config.toml")


@click.group(help=__doc__)
def cli() -> None:
    """Bubblewrap sandbox CLI."""


@cli.command(
    "run",
    help=RUN_HELP,
    context_settings={
        "ignore_unknown_options": True,
        "help_option_names": [],
    },
)
@click.option(
    "--debug",
    help="Enable debug logging",
    is_flag=True,
    default=False,
)
@click.option(
    "--feature",
    "-f",
    "enable_features",
    multiple=True,
    help="Enable a feature (repeatable). See `bk list-features`.",
)
@click.option(
    "--no-feature",
    "disable_features",
    multiple=True,
    help="Disable a feature (repeatable). See `bk list-features`.",
)
@click.option(
    "--network",
    "network_mode",
    type=click.Choice(["host", "none", "filter"], case_sensitive=False),
    default=None,
    help="Network mode: filter (default), host, or none. Filter is also implied "
    "by allow/deny/policy options when mode is omitted.",
)
@click.option(
    "--net-policy",
    type=click.Choice(["allow", "deny"], case_sensitive=False),
    default=None,
    help="Default verdict for filter mode (allow or deny). Implies --network filter.",
)
@click.option(
    "--net-allow",
    multiple=True,
    help="Allow an IP/CIDR or hostname (implies --network filter; repeatable).",
)
@click.option(
    "--net-deny",
    multiple=True,
    help="Deny an IP/CIDR or hostname (implies --network filter; repeatable).",
)
@click.option(
    "--net-allow-preset",
    multiple=True,
    help="Allow a named preset (built-in or from [network.presets]). "
    "Implies --network filter. Repeatable. See `bk list-net-presets`.",
)
@click.option(
    "--net-deny-preset",
    multiple=True,
    help="Deny a named preset (built-in or from [network.presets]). "
    "Implies --network filter. Repeatable. See `bk list-net-presets`.",
)
@click.option(
    "--docker-instance-remove-data/--keep-docker-instance-data",
    "docker_instance_remove_data",
    default=None,
    help="Delete this project's docker-instance data_root when the sandbox "
    "exits. Default keeps the store, unless [docker_instance] "
    "remove_data_on_teardown is true.",
)
@click.option(
    "--docker-instance-storage-driver",
    type=click.Choice(sorted(STORAGE_DRIVERS), case_sensitive=False),
    default=None,
    help="dockerd --storage-driver for docker-instance. auto (default) leaves "
    "the choice to dockerd. Overlay2 and fuse-overlayfs cannot share a "
    "data_root; prune before switching.",
)
@click.option(
    "--dbus-see",
    multiple=True,
    metavar="NAME",
    help="D-Bus name the sandbox may see (repeatable). Well-known name, "
    "optional .* suffix. Enables dbus-proxy filtering.",
)
@click.option(
    "--dbus-talk",
    multiple=True,
    metavar="NAME",
    help="D-Bus name the sandbox may talk to (repeatable). Implies see for "
    "that name. Enables dbus-proxy filtering.",
)
@click.option(
    "--dbus-own",
    multiple=True,
    metavar="NAME",
    help="D-Bus name the sandbox may own (repeatable). Implies talk and see. "
    "Enables dbus-proxy filtering.",
)
@click.option(
    "--dbus-call",
    multiple=True,
    metavar="NAME=RULE",
    help="Allow method calls matching NAME=RULE (repeatable). RULE is "
    "[METHOD][@PATH]. Enables dbus-proxy filtering.",
)
@click.option(
    "--dbus-broadcast",
    multiple=True,
    metavar="NAME=RULE",
    help="Allow broadcast signals matching NAME=RULE (repeatable). RULE is "
    "[METHOD][@PATH]. Enables dbus-proxy filtering.",
)
@click.argument(
    "args",
    nargs=-1,
    callback=lambda ctx, arg, value: list(value),
)
def run(
    debug: bool,
    enable_features: tuple[str, ...],
    disable_features: tuple[str, ...],
    network_mode: str | None,
    net_policy: str | None,
    net_allow: tuple[str, ...],
    net_deny: tuple[str, ...],
    net_allow_preset: tuple[str, ...],
    net_deny_preset: tuple[str, ...],
    docker_instance_remove_data: bool | None,
    docker_instance_storage_driver: str | None,
    dbus_see: tuple[str, ...],
    dbus_talk: tuple[str, ...],
    dbus_own: tuple[str, ...],
    dbus_call: tuple[str, ...],
    dbus_broadcast: tuple[str, ...],
    args: list[str],
) -> None:
    logging.basicConfig(level="DEBUG" if debug else "WARNING")

    config = load_config()
    command = resolve_launch_command(args)
    executable = command_executable(command, args)
    command = append_executable_args(command, config, executable)
    config = ensure_cwd_project(
        config,
        executable=executable,
        enable=enable_features,
        disable=disable_features,
    )
    enabled = resolve_features(
        config,
        executable=executable,
        enable=enable_features,
        disable=disable_features,
    )
    check_feature_requirements(enabled, config)
    net = resolve_network(
        config,
        executable=executable,
        mode=network_mode,
        policy=net_policy,
        allow=net_allow,
        deny=net_deny,
        allow_presets=net_allow_preset,
        deny_presets=net_deny_preset,
    )
    binds = get_binds(config, enabled)
    env_args = get_env_args(config, enabled)

    bind_args = get_bind_args(binds)

    from buddelkiste.dbus_proxy import dbus_proxy_cli_context
    from buddelkiste.docker_instance import instance_cli_overrides

    with (
        instance_cli_overrides(
            remove_data_on_teardown=docker_instance_remove_data,
            storage_driver=docker_instance_storage_driver,
        ),
        dbus_proxy_cli_context(
            executable=executable,
            see=dbus_see,
            talk=dbus_talk,
            own=dbus_own,
            call=dbus_call,
            broadcast=dbus_broadcast,
        ),
        feature_setup(enabled, config) as setup_parts,
    ):
        setup_args = [arg for _name, part in setup_parts for arg in part]
        check_launch_conflicts(
            enabled=enabled,
            config=config,
            binds=binds,
            setup_parts=setup_parts,
        )
        bwrap_args = [
            "bwrap",
            "--unshare-all",
            "--clearenv",
            "--die-with-parent",
            "--chdir",
            str(Path.cwd()),
            *bind_args,
            *env_args,
            *setup_args,
            "--",
            *command,
        ]

        if debug:
            log_cmdline(bwrap_args)
            log.debug(
                "network mode=%s policy=%s allow=%s deny=%s allow_hosts=%s deny_hosts=%s",
                net.mode,
                net.policy,
                net.allow,
                net.deny,
                net.allow_hosts,
                net.deny_hosts,
            )
            log.debug(
                "network wildcards allow=%s deny=%s",
                [host for host in net.allow_hosts if host.startswith("*.")],
                [host for host in net.deny_hosts if host.startswith("*.")],
            )
            os.environ["BUDDELKISTE_DEBUG"] = "1"

        exit_code = run_bwrap(bwrap_args, net)

    sys.exit(exit_code)


@cli.command("list-features")
def list_features() -> None:
    """List available features and their origins."""
    click.echo(format_features_help(load_config()))


@cli.command("list-net-presets")
def list_net_presets() -> None:
    """List built-in and config network presets."""
    click.echo(format_deny_presets_help(load_deny_preset_registry(load_config())))


@cli.command("info")
@click.argument("executable", required=False)
def info(executable: str | None) -> None:
    """Print the merged config for this directory and optional executable.

    Applies feature defaults, then global ``features``, then
    ``executables.<name>.features``, then the active ``[[projects]]`` entry.
    Network and dbus-proxy use the same global → executable order. Output is
    TOML of the effective tables (not the stacked source lists).
    """
    config = load_config()
    cwd = Path.cwd()
    click.echo(
        format_effective_config(config, executable=executable, cwd=cwd),
        nl=False,
    )


@cli.group("docker-policy")
def docker_policy_group() -> None:
    """Show and apply host-side docker-proxy allowlists."""


@docker_policy_group.command("path")
def docker_policy_path() -> None:
    """Print the host policy file path for the current project."""
    from buddelkiste.docker_proxy import host_policy_path, project_policy_key

    key = project_policy_key()
    click.echo(host_policy_path(key))


@docker_policy_group.command("show")
def docker_policy_show() -> None:
    """Show the effective docker-proxy policy for the current project."""
    from buddelkiste.docker_proxy import load_effective_policy, project_policy_key

    policy = load_effective_policy(config=load_config())
    click.echo(f"project: {project_policy_key()}")
    click.echo(f"on_unknown_image: {policy.on_unknown_image}")
    click.echo(f"images ({len(policy.images)}):")
    if not policy.images:
        click.echo("  (none)")
    for ref in policy.images:
        click.echo(f"  - {ref}")


@docker_policy_group.command("apply")
@click.option(
    "--dry-run",
    is_flag=True,
    help="Show what would be written without changing the host policy file.",
)
def docker_policy_apply(dry_run: bool) -> None:
    """Write ``[docker_proxy]`` from config into the host enforcement store."""
    from buddelkiste.docker_proxy import (
        declaration_from_config,
        host_policy_path,
        project_policy_key,
        write_policy_file,
    )

    config = load_config()
    declaration = declaration_from_config(config)
    if declaration is None:
        raise click.ClickException(
            "No [docker_proxy] table in config; add images there first"
        )
    key = project_policy_key()
    path = host_policy_path(key)
    if dry_run:
        click.echo(f"Would write {len(declaration.images)} image(s) to {path}")
        for ref in declaration.images:
            click.echo(f"  - {ref}")
        return
    write_policy_file(path, declaration)
    click.echo(f"Wrote {len(declaration.images)} image(s) to {path}")


@docker_policy_group.command("pending")
def docker_policy_pending() -> None:
    """List image approvals currently held by a live docker-proxy.

    Run this on the host (outside the sandbox); the control socket is not
    exposed inside the bubblewrap environment.
    """
    from buddelkiste.docker_proxy import control_request

    resp = control_request({"op": "list"})
    if not resp.get("ok"):
        raise click.ClickException(str(resp.get("error") or "list failed"))
    pending = resp.get("pending") or []
    if not pending:
        click.echo("No pending image approvals.")
        return
    for item in pending:
        click.echo(f"{item.get('id')}\t{item.get('image')}")


@docker_policy_group.command("approve")
@click.argument("target", required=False)
def docker_policy_approve(target: str | None) -> None:
    """Allow a held image for this session (unblocks the waiting Docker client).

    TARGET is a pending id or image reference. When omitted and exactly one
    request is held, that request is approved. Run on the host (outside the
    sandbox).
    """
    from buddelkiste.docker_proxy import control_request

    req: dict = {"op": "approve"}
    if target is not None:
        req["target"] = target
    resp = control_request(req)
    if not resp.get("ok"):
        raise click.ClickException(str(resp.get("error") or "approve failed"))
    click.echo(f"Approved {resp.get('image')} (id={resp.get('id')}) for this session")


@docker_policy_group.command("deny")
@click.argument("target", required=False)
def docker_policy_deny(target: str | None) -> None:
    """Deny a held image request (unblocks the waiting Docker client with 403).

    TARGET is a pending id or image reference. When omitted and exactly one
    request is held, that request is denied. Run on the host (outside the
    sandbox).
    """
    from buddelkiste.docker_proxy import control_request

    req: dict = {"op": "deny"}
    if target is not None:
        req["target"] = target
    resp = control_request(req)
    if not resp.get("ok"):
        raise click.ClickException(str(resp.get("error") or "deny failed"))
    click.echo(f"Denied {resp.get('image')} (id={resp.get('id')})")


@cli.group("docker-instance")
def docker_instance_group() -> None:
    """List and prune project-local docker-instance image stores."""


@docker_instance_group.command("list")
def docker_instance_list() -> None:
    """Print per-project docker-instance store sizes.

    Scans ``$XDG_DATA_HOME/buddelkiste/docker-instance/`` and also includes the
    current project's ``data_root`` when it lives elsewhere. The current store
    is marked with ``*``.
    """
    from buddelkiste.docker_instance import format_bytes, list_instance_stores

    stores = list_instance_stores(config=load_config())
    if not stores:
        click.echo("No docker-instance stores.")
        return
    for store in stores:
        mark = "*" if store.current else " "
        click.echo(
            f"{format_bytes(store.size):>8}  {mark} {store.name}\t{store.path}"
        )


@docker_instance_group.command("prune")
@click.argument("names", nargs=-1)
@click.option(
    "--all",
    "all_stores",
    is_flag=True,
    help="Remove every store under the default docker-instance data home.",
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="Print paths that would be removed without deleting them.",
)
@click.option(
    "--yes",
    "-y",
    is_flag=True,
    help="Do not prompt for confirmation.",
)
def docker_instance_prune(
    names: tuple[str, ...],
    all_stores: bool,
    dry_run: bool,
    yes: bool,
) -> None:
    """Remove docker-instance data_roots (overlay leftovers included).

    With no NAMES, prune the current project's store (config data_root or the
    default path). NAMES are directory names under the default data home.
    Uses a chmod+unlink walk so kernel overlay work dirs (mode 000) go away.
    """
    from buddelkiste.docker_instance import prune_instance_stores, resolve_prune_targets

    targets = resolve_prune_targets(
        names, all_stores=all_stores, config=load_config()
    )
    existing = [path for path in targets if path.exists()]
    if not existing:
        click.echo("Nothing to prune.")
        return
    for path in existing:
        click.echo(str(path))
    if dry_run:
        click.echo(f"Would remove {len(existing)} store(s).")
        return
    if not yes and not click.confirm(
        f"Remove {len(existing)} docker-instance store(s)?", default=False
    ):
        raise click.Abort()
    removed = prune_instance_stores(existing)
    click.echo(f"Removed {len(removed)} store(s).")


@cli.group("shims")
def shims_group() -> None:
    """Install and verify PATH shims for configured executables.

    For each key under ``[executables.<name>]`` with shimming enabled, a small
    ``sh`` wrapper is placed in ``$XDG_DATA_HOME/buddelkiste/shims`` (default
    ``~/.local/share/buddelkiste/shims``) that runs ``bk run <real-binary>``
    with the caller's arguments. ``install`` also writes a POSIX snippet and
    sources it from existing ``~/.bashrc`` / ``~/.zshrc`` so interactive
    shells prepend that directory and run ``bk shims check --quiet``.
    ``list`` prints each configured or leftover shim and the host binary it
    would exec. Control with top-level ``shims = true/false`` (default true)
    and per-entry ``shim = true/false``. Shims carry a
    ``# buddelkiste-shim:`` marker so ``install`` can refresh or remove our
    own files without clobbering unrelated binaries of the same name.
    """


@shims_group.command("install")
def shims_install() -> None:
    """Create or update PATH shims and the interactive shell hook."""
    config = load_config()
    decisions = shim_decisions_from_config(config)
    hook_results = install_shim_hook()
    wrapper_results = (
        install_shims_from_config(config, bin_dir=shim_dir()) if decisions else []
    )
    for result in (*hook_results, *wrapper_results):
        click.echo(f"{result.action:9} {result.path}")
    if not shim_dir_on_path():
        click.echo(
            "Open a new shell to activate the shims.",
            err=True,
        )
    if not decisions:
        click.echo("No [executables] entries in config; no wrappers to install.", err=True)
        return
    if not wrapper_results:
        click.echo("All configured executables have shimming disabled; nothing to do.")
        return
    skipped = [r for r in wrapper_results if r.action == "skipped"]
    if skipped:
        click.echo(
            f"Left {len(skipped)} existing non-shim file(s) untouched "
            "(remove or rename them, then re-run).",
            err=True,
        )


@shims_group.command("check")
@click.option(
    "-q",
    "--quiet",
    is_flag=True,
    help="Only print warnings; omit the success and empty-config lines.",
)
def shims_check(*, quiet: bool) -> None:
    """Warn if originals on PATH would bypass installed shims."""
    config = load_config()
    decisions = shim_decisions_from_config(config)
    if not decisions:
        if not quiet:
            click.echo("No [executables] entries in config; nothing to check.", err=True)
        return

    names = shim_names_from_config(config)
    if not names:
        if not quiet:
            click.echo("All configured executables have shimming disabled; nothing to check.")
        return

    issues = check_shims(names, bin_dir=shim_dir())
    if not issues:
        if not quiet:
            click.echo(f"OK: {len(names)} shim(s) intercept PATH correctly.")
        return

    for issue in issues:
        prefix = "warning" if issue.name == "*" else f"warning ({issue.name})"
        click.echo(f"{prefix}: {issue.message}", err=True)
    raise SystemExit(1)


@shims_group.command("list")
def shims_list() -> None:
    """Print each shim and the host binary it would run."""
    names = list_shim_names(load_config())
    if not names:
        click.echo("No shims.", err=True)
        return
    width = max(len(name) for name in names)
    for entry in list_shims(names):
        target = str(entry.target) if entry.target is not None else "-"
        click.echo(f"{entry.name:<{width}}  {target}")


def load_toml_file(path: Path) -> dict:
    with path.open("rb") as fobj:
        data = tomllib.load(fobj)
    if not isinstance(data, dict):
        raise click.ClickException(f"Config {path} must be a TOML table")
    return data


def _merge_network(base: dict, overlay: dict) -> dict:
    merged = dict(base)
    for key, value in overlay.items():
        if (
            key == "presets"
            and isinstance(value, dict)
            and isinstance(merged.get("presets"), dict)
        ):
            merged["presets"] = {**merged["presets"], **value}
        else:
            merged[key] = value
    return merged


def _merge_executables(base: dict, overlay: dict) -> dict:
    merged = dict(base)
    for name, data in overlay.items():
        existing = merged.get(name)
        if isinstance(data, dict) and isinstance(existing, dict):
            entry = dict(existing)
            for key, value in data.items():
                if (
                    key == "network"
                    and isinstance(value, dict)
                    and isinstance(entry.get("network"), dict)
                ):
                    entry["network"] = _merge_network(entry["network"], value)
                elif (
                    key == "dbus_proxy"
                    and isinstance(value, dict)
                    and isinstance(entry.get("dbus_proxy"), dict)
                ):
                    entry["dbus_proxy"] = {**entry["dbus_proxy"], **value}
                else:
                    entry[key] = value
            merged[name] = entry
        else:
            merged[name] = data
    return merged


def merge_config(base: dict, overlay: dict) -> dict:
    """Merge overlay config over base.

    ``binds`` / ``envvars`` / ``projects`` lists are concatenated. Nested
    ``feature``, ``executables``, ``network``, and ``dbus_proxy`` tables are
    merged (overlay wins on conflicts). Other keys are replaced by the overlay
    value.
    """
    result = dict(base)
    for key, value in overlay.items():
        if key in {"binds", "envvars", "projects"} and isinstance(value, list):
            result[key] = [*result.get(key, []), *value]
        elif key == "feature" and isinstance(value, dict):
            merged = dict(result.get("feature") or {})
            merged.update(value)
            result["feature"] = merged
        elif key == "executables" and isinstance(value, dict):
            existing = result.get("executables")
            result["executables"] = (
                _merge_executables(existing, value)
                if isinstance(existing, dict)
                else value
            )
        elif key == "network" and isinstance(value, dict):
            existing = result.get("network")
            result["network"] = (
                _merge_network(existing, value) if isinstance(existing, dict) else value
            )
        elif key == "dbus_proxy" and isinstance(value, dict):
            existing = result.get("dbus_proxy")
            result["dbus_proxy"] = (
                {**existing, **value} if isinstance(existing, dict) else value
            )
        else:
            result[key] = value
    return result


def load_config() -> dict:
    user_path = config_path()
    if user_path.is_file():
        return load_toml_file(user_path)
    return {}


_PASSTHROUGH_SKIP = frozenset(
    {"features", "network", "dbus_proxy", "executables", "projects"}
)
_TOML_BARE_KEY = re.compile(r"^[A-Za-z0-9_-]+$")


def effective_config(
    config: dict,
    *,
    executable: str | None = None,
    cwd: Path | None = None,
) -> dict:
    """Return the config tables after global / executable / project overlays.

    ``features`` is the resolved on/off table. ``network`` and ``dbus_proxy``
    are the values ``bk run`` would use for this executable (no CLI flags).
    ``executables`` and ``projects`` are omitted; they have already been applied.
    Other top-level keys are copied from ``config``.
    """
    from buddelkiste.dbus_proxy import resolve_dbus_proxy

    registry = load_feature_registry(config)
    enabled = resolve_features(config, executable=executable, cwd=cwd)
    net = resolve_network(config, executable=executable)
    dbus = resolve_dbus_proxy(config, executable=executable)

    network_table: dict[str, object] = {
        "mode": net.mode,
        "policy": net.policy,
        "allow": list(net.allow),
        "deny": list(net.deny),
        "allow_presets": list(net.allow_presets),
        "deny_presets": list(net.deny_presets),
        "allow_hosts": list(net.allow_hosts),
        "deny_hosts": list(net.deny_hosts),
    }
    network = config.get("network")
    if isinstance(network, dict) and isinstance(network.get("presets"), dict):
        network_table["presets"] = dict(network["presets"])

    merged: dict = {
        "shims": global_shims_enabled(config),
        "features": {name: bool(enabled.get(name)) for name in feature_names(registry)},
        "network": network_table,
    }

    if dbus.filtered:
        merged["dbus_proxy"] = {
            "see": list(dbus.see),
            "talk": list(dbus.talk),
            "own": list(dbus.own),
            "call": list(dbus.call),
            "broadcast": list(dbus.broadcast),
        }

    for key, value in config.items():
        if key in _PASSTHROUGH_SKIP or key == "shims":
            continue
        merged[key] = value
    return merged


def format_effective_config(
    config: dict,
    *,
    executable: str | None = None,
    cwd: Path | None = None,
) -> str:
    """TOML dump of the merged config with source comments."""
    here = (cwd if cwd is not None else Path.cwd()).resolve()
    project = lookup_project_config(config, cwd=here)
    comments = [
        f"config: {config_path()}",
        f"cwd: {here}",
        f"project: {project[0] if project is not None else '(none)'}",
        f"executable: {executable if executable else '(none)'}",
    ]
    return format_toml_document(
        effective_config(config, executable=executable, cwd=here),
        comments=comments,
    )


def format_toml_document(
    data: Mapping[str, object],
    *,
    comments: Sequence[str] = (),
) -> str:
    """Serialize a mapping to a TOML document (scalars, tables, array-of-tables)."""
    lines = [f"# {line}" for line in comments]
    if comments:
        lines.append("")
    _emit_toml_table(lines, data, header=())
    text = "\n".join(lines).rstrip()
    return text + "\n"


def _toml_key(key: str) -> str:
    if _TOML_BARE_KEY.match(key):
        return key
    return json.dumps(key)


def _toml_inline(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return repr(value)
    if isinstance(value, Path):
        return json.dumps(str(value))
    if isinstance(value, str):
        return json.dumps(value)
    if isinstance(value, Mapping):
        items = ", ".join(
            f"{_toml_key(str(key))} = {_toml_inline(item)}" for key, item in value.items()
        )
        return f"{{ {items} }}" if items else "{}"
    if isinstance(value, (list, tuple)):
        items = ", ".join(_toml_inline(item) for item in value)
        return f"[{items}]"
    raise TypeError(f"unsupported TOML value: {type(value).__name__}")


def _is_array_of_tables(value: object) -> bool:
    return (
        isinstance(value, list)
        and bool(value)
        and all(isinstance(item, Mapping) for item in value)
    )


def _emit_toml_table(
    lines: list[str],
    table: Mapping[str, object],
    *,
    header: tuple[str, ...],
) -> None:
    scalars: list[tuple[str, object]] = []
    nested: list[tuple[str, Mapping[str, object]]] = []
    arrays_of_tables: list[tuple[str, list]] = []
    for key, value in table.items():
        if value is None:
            continue
        if isinstance(value, list) and _is_array_of_tables(value):
            arrays_of_tables.append((key, value))
        elif isinstance(value, Mapping):
            nested.append((key, value))
        else:
            scalars.append((key, value))

    if header:
        if lines and lines[-1] != "":
            lines.append("")
        lines.append("[" + ".".join(_toml_key(part) for part in header) + "]")

    for key, value in scalars:
        lines.append(f"{_toml_key(key)} = {_toml_inline(value)}")

    for key, value in nested:
        _emit_toml_table(lines, value, header=(*header, key))

    dotted = ".".join(_toml_key(part) for part in header)
    for key, items in arrays_of_tables:
        name = f"{dotted}.{_toml_key(key)}" if dotted else _toml_key(key)
        for item in items:
            if not isinstance(item, Mapping):
                continue
            if lines and lines[-1] != "":
                lines.append("")
            lines.append(f"[[{name}]]")
            _emit_toml_table(lines, item, header=())


def get_binds(
    config: dict,
    enabled: dict[str, bool] | None = None,
    *,
    cwd: Path | None = None,
) -> list:
    if enabled is None:
        enabled = resolve_features(config, cwd=cwd)
    binds = feature_binds(enabled, config)
    for index, bind_params in enumerate(config.get("binds", ())):
        for bind in binds_from_spec(dict(bind_params), where=f"binds[{index}]"):
            if not Path(bind.source).exists():
                raise FileNotFoundError(bind.source)
            binds.append(bind)
    project = lookup_project_config(config, cwd=cwd)
    if project is not None:
        root, _table = project
        binds.append(bind_config(root, mode="rw"))
    return binds


def config_path() -> Path:
    return CONFIG_PATH.expanduser()


def is_interactive() -> bool:
    return sys.stdin.isatty() and sys.stderr.isatty()


def cwd_is_covered(binds: list, cwd: Path | None = None) -> bool:
    here = cwd if cwd is not None else Path.cwd()
    return any(hasattr(bind, "covers_path") and bind.covers_path(here) for bind in binds)


def ensure_cwd_project(
    config: dict,
    *,
    executable: str | None = None,
    enable: Sequence[str] = (),
    disable: Sequence[str] = (),
    cwd: Path | None = None,
) -> dict:
    """Ensure the working directory is a project (or already covered).

    If nothing covers cwd, interactively offer yes (this run), always (persist
    a ``[[projects]]`` entry), or no (abort), then which features to enable.
    """
    here = (cwd if cwd is not None else Path.cwd()).resolve()
    enabled = resolve_features(
        config, executable=executable, enable=enable, disable=disable, cwd=here
    )
    binds = get_binds(config, enabled, cwd=here)
    if cwd_is_covered(binds, here):
        return config

    if not is_interactive():
        raise click.ClickException(
            f"The current directory {here} is not available inside the sandbox.\n"
        )

    from buddelkiste.prompts import prompt_cwd_access, prompt_project_features

    click.echo(
        f"The current directory {here} is not available inside the sandbox.",
        err=True,
    )
    choice = prompt_cwd_access()
    if choice == "no":
        raise click.Abort()

    features = prompt_project_features(config)
    table: dict = {"path": str(here)}
    if features:
        table["features"] = features
    if choice == "always":
        add_project_to_config(here, features=features)
        click.echo(f"Added project {here} to {CONFIG_PATH}.", err=True)
        return load_config()
    return merge_config(config, {"projects": [table]})


def add_project_to_config(
    source: Path,
    *,
    features: dict[str, bool] | None = None,
) -> None:
    """Append a ``[[projects]]`` entry for ``source`` to the user config."""
    path = config_path()
    path.parent.mkdir(parents=True, exist_ok=True)

    prefix = ""
    if path.exists() and (content := path.read_bytes()):
        prefix = "\n" if content.endswith(b"\n") else "\n\n"

    lines = [
        "[[projects]]",
        f"path = {json.dumps(str(source.resolve()))}",
    ]
    if features:
        inner = ", ".join(
            f"{name} = {'true' if value else 'false'}" for name, value in features.items()
        )
        lines.append(f"features = {{ {inner} }}")

    with path.open("a") as fobj:
        fobj.write(prefix + "\n".join(lines) + "\n")


def add_bind_to_config(source: Path, *, mode: str = "ro") -> None:
    """Append a `[[binds]]` entry for `source` to the configuration file."""
    path = config_path()
    path.parent.mkdir(parents=True, exist_ok=True)

    # Separate the new entry from existing content with a blank line.
    prefix = ""
    if path.exists() and (content := path.read_bytes()):
        prefix = "\n" if content.endswith(b"\n") else "\n\n"

    # JSON string escaping is a subset of TOML basic string escaping.
    entry = [
        "[[binds]]",
        f"source = {json.dumps(str(source))}",
        f"mode = {json.dumps(mode)}",
    ]

    with path.open("a") as fobj:
        fobj.write(prefix + "\n".join(entry) + "\n")


def get_env_args(config: dict, enabled: dict[str, bool] | None = None) -> Sequence[str]:
    if enabled is None:
        enabled = resolve_features(config)

    res = []
    for var_name in feature_env_var_names(enabled, config):
        value = env(var_name)
        if value is not None:
            res.extend(("--setenv", var_name, value))

    for cfg in config.get("envvars", ()):
        var_name = cfg["name"]
        value = cfg.get("value")
        if value is None:
            value = env(var_name)
        if value is not None:
            res.extend(("--setenv", var_name, value))

    return res


def resolve_launch_command(args: list[str]) -> list[str]:
    """Return the command to run in the sandbox.

    Uses the command-line arguments as the executable and its args. If none are
    given, falls back to an interactive login shell.
    """
    if args in (["--help"], ["-h"]):
        click.echo(click.get_current_context().get_help())
        raise SystemExit(0)

    if args:
        return args

    pwent = pwd.getpwuid(os.getuid())
    return [pwent.pw_shell, "-si", "--"]


def command_executable(command: list[str], args: list[str]) -> str | None:
    """Executable used for per-command feature config, if the user provided one."""
    if not args:
        return None
    return command[0]


def append_executable_args(
    command: list[str],
    config: dict,
    executable: str | None,
) -> list[str]:
    """Append ``executables.<name>.args`` to the command, if configured."""
    exec_cfg = lookup_executable_config(config, executable)
    if not exec_cfg or "args" not in exec_cfg:
        return command

    extra = exec_cfg["args"]
    if not isinstance(extra, list) or not all(isinstance(arg, str) for arg in extra):
        raise click.ClickException(
            f"executables args for {executable!r} must be a list of strings"
        )
    return [*command, *extra]


def log_cmdline(cmdline):
    log.debug("Running:")
    group = [cmdline[0]]
    for arg in cmdline[1:]:
        if arg.startswith("-"):
            log.debug("  %s", " ".join(group))
            group.clear()
        group.append(arg)
    log.debug("  %s", " ".join(group))


# Re-export bind helpers for tests and callers that imported them from cli.
from buddelkiste.binds import (
    BasicBindConfig,
    DevBindConfig,
    OverlayBindConfig,
    Tmpfs,
    TmpOverlayBindConfig,
)
from buddelkiste.features import SshAgent, find_sandbox_ssh_key

__all__ = [
    "FEATURES",
    "BasicBindConfig",
    "DevBindConfig",
    "OverlayBindConfig",
    "ROBindConfig",
    "RWBindConfig",
    "SshAgent",
    "TmpOverlayBindConfig",
    "Tmpfs",
    "add_bind_to_config",
    "add_project_to_config",
    "append_executable_args",
    "bind_config",
    "cli",
    "cwd_is_covered",
    "effective_config",
    "ensure_cwd_project",
    "find_sandbox_ssh_key",
    "format_effective_config",
    "get_bind_args",
    "get_binds",
    "get_env_args",
    "info",
    "list_features",
    "list_net_presets",
    "load_config",
    "merge_config",
    "resolve_features",
    "resolve_launch_command",
    "resolve_network",
    "run",
]
