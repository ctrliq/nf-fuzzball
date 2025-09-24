"""Command line interface for nf-fuzzball-submit."""

import argparse
import os
import pathlib
import textwrap

from .client import DATA_MOUNT


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
            """
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
        type=str,
        help=("API URL of Fuzzball cluster [$FUZZBALL_API_URL]. e.g. https://api.example.com"),
        default=os.environ.get("FUZZBALL_API_URL", ""),
    )
    direct_login_group.add_argument(
        "--auth-url",
        type=str,
        help=(
            "AUTH URL of Fuzzball cluster [$FUZZBALL_AUTH_URL] "
            "e.g. https://auth.example.com/auth/realms/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
        ),
        default=os.environ.get("FUZZBALL_AUTH_URL", ""),
    )
    direct_login_group.add_argument(
        "--user",
        type=str,
        help="Username/email for direct login [$FUZZBALL_USER]",
        default=os.environ.get("FUZZBALL_USER", ""),
    )
    direct_login_group.add_argument(
        "--password",
        action="store_true",
        help=("Prompt for password for direct login. Otherwise defaults to [$FUZZBALL_PASSWORD]"),
    )
    direct_login_group.add_argument(
        "--account-id",
        type=str,
        help="Fuzzball account ID for direct login [$FUZZBALL_ACCOUNT_ID]",
        default=os.environ.get("FUZZBALL_ACCOUNT_ID", ""),
    )

    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging.")
    parser.add_argument(
        "--ca-cert", type=str, help="Path to CA certificate file for SSL verification."
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
        type=str,
        default="",
        help="Fuzzball S3 secret for plugin download.",
    )
    parser.add_argument(
        "--plugin-base-uri",
        type=str,
        default="https://github.com/ctrliq/nf-fuzzball/releases/download",
        help="Base URI for the nf-fuzzball plugin.",
    )
    parser.add_argument(
        "--nextflow-version", type=str, default="25.05.0-edge", help="Nextflow version."
    )
    parser.add_argument(
        "--timelimit", type=str, default="8h", help="Timelimit for the pipeline job."
    )
    parser.add_argument(
        "--scratch-volume",
        type=str,
        default="volume://user/ephemeral",
        help="Ephemeral scratch volume.",
    )
    parser.add_argument(
        "--data-volume",
        type=str,
        default="volume://user/persistent",
        help="Persistent data volume.",
    )
    parser.add_argument("--nf-core", action="store_true", help="Use nf-core conventions.")
    parser.add_argument(
        "--queue-size",
        type=int,
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

    if args.plugin_base_uri.startswith("s3://") and not args.s3_secret:
        parser.error("--s3-secret is required when --plugin-base-uri is an S3 URI.")

    return args
