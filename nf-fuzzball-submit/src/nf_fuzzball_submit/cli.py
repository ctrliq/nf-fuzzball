"""Command line interface for nf-fuzzball-submit."""

import argparse
import os
import pathlib
import posixpath
import re
import textwrap
from collections.abc import Callable
from urllib.parse import urlparse

from .client import DATA_MOUNT


def valid_timelimit(value: str) -> str:
    """Validate timelimit string format.

    Accepts formats like: '120m', '8h', '1d8h30m', '30s', etc.
    Each component (days, hours, minutes, seconds) is optional but at least one must be present.

    Args:
        value: The timelimit string to validate.

    Returns:
        The validated timelimit string.

    Raises:
        argparse.ArgumentTypeError: If the format is invalid.
    """
    pattern = r"^(\d+d)?(\d+h)?(\d+m)?(\d+s)?$"
    if (m := re.match(pattern, value)) is None:
        raise argparse.ArgumentTypeError(
            f"Invalid timelimit format: '{value}'. Expected format: [Nd][Nh][Nm][Ns] (e.g., '8h', '1d8h30m', '120m')"
        )
    # Ensure at least one component is present and that they add up to more than 0
    # not calculating an actual duration with the units.
    s = sum(int(a[0:-1]) for a in m.groups() if a is not None)
    if s == 0:
        raise argparse.ArgumentTypeError(
            f"Invalid timelimit format: '{value}'. Must include at least one time component (d/h/m/s)"
        )
    return value


def valid_url(value: str) -> str:
    """Validate URL format.

    Accepts a valid URL.

    Args:
        value: The URL string to validate.

    Returns:
        The validated URL string.

    Raises:
        argparse.ArgumentTypeError: If the URL is invalid.
    """
    parsed = urlparse(value)
    if not parsed.scheme or not parsed.netloc:
        raise argparse.ArgumentTypeError(
            f"Invalid URL: '{value}'. Expected a valid URL with scheme and domain (e.g., 'https://example.com')"
        )
    return value


def valid_memory(value: str) -> str:
    """Validate memory string format.

    Accepts formats like: '4GB', '4GiB', '512MB', '1.5TiB', etc.
    Supports both metric (KB, MB, GB, TB, PB) and binary (KiB, MiB, GiB, TiB, PiB) units.
    Case insensitive.

    Args:
        value: The memory string to validate.

    Returns:
        The validated memory string.

    Raises:
        argparse.ArgumentTypeError: If the format is invalid.
    """
    pattern = r"^\s*(\d+(?:\.\d+)?)\s*([KMGTP]i?B)\s*$"
    match = re.match(pattern, value, re.IGNORECASE)
    if not match:
        raise argparse.ArgumentTypeError(
            f"Invalid memory format: '{value}'. "
            "Expected format: <number><unit> (e.g., '4GB', '4GiB', '512MB', '1.5TiB'). "
            "Supported units: KB/KiB, MB/MiB, GB/GiB, TB/TiB, PB/PiB"
        )
    try:
        mem = float(match[1])
    except ValueError:
        mem = 0.0
    if mem <= 0.0:
        raise argparse.ArgumentTypeError(f"Invalid memory format: '{value}'. Memory must be more than 0")
    return value


def valid_fuzzball_volume(value: str) -> str:
    """Validate fuzzball volume string format.

    Accepts a valid fuzzball volume reference.

    Args:
        value: The volume reference to validate.

    Returns:
        The validated volume reference.

    Raises:
        argparse.ArgumentTypeError: If the volume reference is invalid.
    """
    if not value.startswith("volume://"):
        raise argparse.ArgumentTypeError(
            f"Invalid Fuzzball volume string: {value}. Expected format: volume://SCOPE/STORAGE_CLASS[/CUSTOM_NAME]"
        )
    return value


def valid_fuzzball_secret(value: str) -> str:
    """Validate fuzzball secret string format.

    Accepts a valid fuzzball secret reference.

    Args:
        value: The secret reference to validate.

    Returns:
        The validated secret reference.

    Raises:
        argparse.ArgumentTypeError: If the secret reference is invalid.
    """
    if not value.startswith("secret://"):
        raise argparse.ArgumentTypeError(
            f"Invalid Fuzzball secret string: {value}. Expected format: secret://SCOPE/NAME"
        )
    return value


def valid_s3_uri(value: str) -> str:
    """Validate S3 URI format.

    Accepts a valid S3 URI starting with s3:// followed by a bucket name.

    Args:
        value: The S3 URI string to validate.

    Returns:
        The validated S3 URI string.

    Raises:
        argparse.ArgumentTypeError: If the URI is invalid.
    """
    if not value.startswith("s3://") or len(value) <= len("s3://"):
        raise argparse.ArgumentTypeError(
            f"Invalid S3 URI: '{value}'. Expected format: s3://BUCKET[/PREFIX] (e.g., 's3://my-bucket/results')"
        )
    return value


def valid_egress_source(value: str) -> str:
    """Validate that the egress source path is under the data mount.

    Args:
        value: The egress source path to validate.

    Returns:
        The normalized, validated egress source path.

    Raises:
        argparse.ArgumentTypeError: If the path is not under the data mount.
    """
    normalized = posixpath.normpath(value)
    if not normalized.startswith(f"{DATA_MOUNT}/"):
        raise argparse.ArgumentTypeError(
            f"Invalid egress source: '{value}'. Path must be under the data mount ({DATA_MOUNT}/)."
        )
    return normalized


def valid_queue_size(value: str) -> int:
    """Validate that the queue size is reasonable.

    Args:
        value: The queue size to validate.

    Returns:
        The validated queue size.

    Raises:
        argparse.ArgumentTypeError: If the queue size is invalid.
    """
    try:
        v = int(value)
    except ValueError:
        v = -1
    if v < 1 or v > 100:
        raise argparse.ArgumentTypeError(f"Invalid queue size: {value}. Expected an integer between 1 and 100.")
    return v


def _validate_env_defaults(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    """Validate args whose defaults come from environment variables.

    Argparse ``type`` functions only run when a value is explicitly provided on
    the command line.  Values sourced from environment variable defaults bypass
    that validation, so we re-run the relevant validators here.
    """
    checks: list[tuple[str, str, Callable[[str], str]]] = [
        ("api_url", "--api-url", valid_url),
        ("auth_url", "--auth-url", valid_url),
        ("egress_s3_aki", "--egress-s3-aki", valid_fuzzball_secret),
        ("egress_s3_sak", "--egress-s3-sak", valid_fuzzball_secret),
    ]
    for attr, flag, validator in checks:
        value = getattr(args, attr)
        if value is None:
            continue
        try:
            setattr(args, attr, validator(value))
        except argparse.ArgumentTypeError as e:
            parser.error(f"{flag}: {e}")


def valid_cores(value: str) -> int:
    """Validate that the number of cores is reasonable.

    Args:
        value: Core number to validate.

    Returns:
        The validated cores.

    Raises:
        argparse.ArgumentTypeError: If invalid.
    """
    try:
        v = int(value)
    except ValueError:
        v = -1
    if v < 1 or v > 10:
        raise argparse.ArgumentTypeError(f"Invalid number of cores: {value}. Expected an integer between 1 and 10.")
    return v


def parse_cli() -> argparse.Namespace:
    """Parse command line arguments for the Nextflow submission script.

    Returns:
        Parsed command line arguments as an argparse.Namespace object.

    Raises:
        SystemExit: If required arguments are missing or invalid.
    """
    parser = argparse.ArgumentParser(
        description="""
Submit a nextflow pipeline to Fuzzball.

Notes:
  - Requires a persistent data volume (mounted at /data) and an ephemeral volume (mounted
    at /scratch).
  - Paths for input, workdir, and output in your nextflow command should be absolute. For
    paths in persistent storate they should include the persistent storage mount point.
  - Any explicitly specified config and/or parameter files will be included in the
    fuzzball job but implicit files (i.e. $HOME/.nextflow/config and ./nextflow.config)
    will not.
  - Config and parameter files should be specified on the commandline directly rather than
    indirectly in a config file.
  - The nextflow command is specified after a `--` separator which follows the options
    for this submission script.
  - Include the fuzzball profile as one of your nextflow profiles.
  - If using a cluster with a self signed certificate the ca cert for the cluster
    needs to be specified to allow TLS certificate verification.
        """,
        usage="%(prog)s [options] -- <nextflow_cmd>",
        epilog=textwrap.dedent(
            """\
            Example:
              %(prog)s -- nextflow run -profile fuzzball \\
                  -with-report report.html \\
                  -with-trace \\
                  -with-timeline timeline.html \\
                  hello
            """,
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    auth_group = parser.add_argument_group("Fuzzball config based authentication")
    auth_group.add_argument(
        "-c",
        "--context",
        type=str,
        help="Name of the context to use from config.yaml.",
        default=None,
    )
    auth_group.add_argument(
        "--fuzzball-config",
        type=pathlib.Path,
        default=(
            pathlib.Path("~/.config/fuzzball/config.yaml").expanduser()
            if os.environ.get("XDG_CONFIG_HOME") is None
            else pathlib.Path(f"{os.environ['XDG_CONFIG_HOME']}/fuzzball/config.yaml").expanduser()
        ),
        help="Path to the fuzzball configuration file. [%(default)s]",
    )
    direct_login_group = parser.add_argument_group("Direct Login based authentication")
    direct_login_group.add_argument(
        "--api-url",
        type=valid_url,
        help="API URL of Fuzzball cluster (e.g., https://api.example.com) [$FUZZBALL_API_URL].",
        default=os.environ.get("FUZZBALL_API_URL", None),
    )
    direct_login_group.add_argument(
        "--auth-url",
        type=valid_url,
        help=(
            "Auth URL of Fuzzball cluster"
            " (e.g., https://auth.example.com/auth/realms/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)"
            " [$FUZZBALL_AUTH_URL]."
        ),
        default=os.environ.get("FUZZBALL_AUTH_URL", None),
    )
    direct_login_group.add_argument(
        "--user",
        type=str,
        help="Username/email for direct login [$FUZZBALL_USER].",
        default=os.environ.get("FUZZBALL_USER", None),
    )
    direct_login_group.add_argument(
        "--password",
        action="store_true",
        help="Prompt for password for direct login. Otherwise defaults to [$FUZZBALL_PASSWORD].",
    )
    direct_login_group.add_argument(
        "--account-id",
        type=str,
        help="Fuzzball account ID for direct login [$FUZZBALL_ACCOUNT_ID].",
        default=os.environ.get("FUZZBALL_ACCOUNT_ID", None),
    )

    egress_group = parser.add_argument_group("Optional egress of results")
    egress_group.add_argument(
        "--egress-source",
        type=valid_egress_source,
        help="Path to an output directory created by the nextflow run to be copied to S3.",
    )
    egress_group.add_argument(
        "--egress-s3-dest",
        type=valid_s3_uri,
        help="S3 URI the results should be copied to (e.g., s3://my-bucket/results).",
    )
    egress_group.add_argument(
        "--egress-s3-aki",
        type=valid_fuzzball_secret,
        default=os.environ.get("FUZZBALL_EGRESS_S3_AKI", None),
        help="Value secret containing an AWS access key id for result egress [$FUZZBALL_EGRESS_S3_AKI].",
    )
    egress_group.add_argument(
        "--egress-s3-sak",
        type=valid_fuzzball_secret,
        default=os.environ.get("FUZZBALL_EGRESS_S3_SAK", None),
        help="Value secret containing an AWS secret access key for result egress [$FUZZBALL_EGRESS_S3_SAK].",
    )
    egress_group.add_argument(
        "--egress-s3-region",
        type=str,
        default=os.environ.get("FUZZBALL_EGRESS_S3_REGION", os.environ.get("AWS_DEFAULT_REGION", None)),
        help="AWS region where bucket is located [$FUZZBALL_EGRESS_S3_REGION or $AWS_DEFAULT_REGION].",
    )
    egress_group.add_argument(
        "--egress-timelimit",
        type=valid_timelimit,
        default="4h",
        help="Timelimit for the egress job (e.g., '4h', '1d', '120m').",
    )

    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging.")
    parser.add_argument(
        "--ca-cert",
        type=str,
        help="Path to CA certificate file for SSL verification.",
    )
    parser.add_argument(
        "-n",
        "--dry-run",
        action="store_true",
        help="Print the workflow without submitting.",
    )
    parser.add_argument("--job-name", type=str, default="", help="Name of the Fuzzball workflow.")
    parser.add_argument(
        "--nextflow-work-base",
        type=str,
        default=f"{DATA_MOUNT}/nextflow/executions",
        help="Base directory for Nextflow execution.",
    )
    parser.add_argument(
        "--nf-fuzzball-version",
        type=str,
        default="0.2.0",
        help="nf-fuzzball plugin version.",
    )
    parser.add_argument(
        "--s3-secret",
        type=valid_fuzzball_secret,
        help="Fuzzball S3 secret for plugin download.",
    )
    parser.add_argument(
        "--plugin-base-uri",
        type=valid_url,
        default="https://github.com/ctrliq/nf-fuzzball/releases/download",
        help="Base URI for the nf-fuzzball plugin.",
    )
    parser.add_argument(
        "--nextflow-version",
        type=str,
        default="25.05.0-edge",
        help="Nextflow version.",
    )
    parser.add_argument(
        "--timelimit",
        type=valid_timelimit,
        default="8h",
        help="Timelimit for the pipeline job (e.g., '8h', '1d8h30m', '120m').",
    )
    parser.add_argument(
        "--memory",
        type=valid_memory,
        default="4GB",
        help="Memory allocated for the nextflow controller job (e.g., '4GB', '512MB').",
    )
    parser.add_argument(
        "--cores",
        type=valid_cores,
        default="1",
        help="Cores allocated for the nextflow controller job.",
    )
    parser.add_argument(
        "--scratch-volume",
        type=valid_fuzzball_volume,
        default="volume://user/ephemeral",
        help="Ephemeral scratch volume.",
    )
    parser.add_argument(
        "--data-volume",
        type=valid_fuzzball_volume,
        default="volume://user/persistent",
        help="Persistent data volume.",
    )
    parser.add_argument("--nf-core", action="store_true", help="Use nf-core conventions.")
    parser.add_argument(
        "--queue-size",
        type=valid_queue_size,
        default=20,
        help="Queue size for the Fuzzball executor.",
    )
    parser.add_argument("nextflow_cmd", nargs=argparse.REMAINDER, help="Nextflow command.")

    args = parser.parse_args()
    if not args.nextflow_cmd:
        parser.error("Nextflow command is required.")
    if args.nextflow_cmd[0] == "--":
        args.nextflow_cmd.pop(0)
    if args.nextflow_cmd[0] != "nextflow":
        parser.error("Nextflow command must start with 'nextflow'.")
    # Validate env-var-sourced defaults (argparse type= only runs for CLI-provided values)
    _validate_env_defaults(parser, args)

    if args.egress_source or args.egress_s3_dest:
        if not (args.egress_source and args.egress_s3_dest):
            parser.error("--egress-source and --egress-s3-dest must both be specified.")
        if not (args.egress_s3_aki and args.egress_s3_sak and args.egress_s3_region):
            parser.error(
                "S3 egress credentials are incomplete. Provide --egress-s3-aki, --egress-s3-sak,"
                " and --egress-s3-region via flags or environment variables"
                " ($FUZZBALL_EGRESS_S3_AKI, $FUZZBALL_EGRESS_S3_SAK,"
                " $FUZZBALL_EGRESS_S3_REGION/$AWS_DEFAULT_REGION)."
            )
    if args.plugin_base_uri.startswith("s3://") and not args.s3_secret:
        parser.error("--s3-secret is required when --plugin-base-uri is an S3 URI.")

    return args
