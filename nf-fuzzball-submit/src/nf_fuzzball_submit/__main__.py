"""Main entry point for nf-fuzzball-submit."""

import getpass
import logging
import os
import sys

from .cli import parse_cli
from .client import create_fuzzball_client
from .utils import die

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)
logging.getLogger("urllib3").setLevel(logging.WARNING)


def main() -> None:
    """Main function that parses arguments and submits the Nextflow job.

    Raises:
        SystemExit: On any error or user interruption.
    """
    try:
        args = parse_cli()

        if args.verbose or args.dry_run:
            logging.getLogger().setLevel(logging.DEBUG)

        password = None
        if args.user:
            if args.password:
                password = getpass.getpass("Enter Fuzzball password: ")
            else:
                password = os.environ.get("FUZZBALL_PASSWORD")
            if not password:
                die(
                    "Password is required for direct login. Use --password or set FUZZBALL_PASSWORD."
                )

        fb_client = create_fuzzball_client(
            args.fuzzball_config.expanduser(),
            args.context,
            args.ca_cert,
            args.api_url,
            args.auth_url,
            args.user,
            password,
            args.account_id,
        )

        if fb_client:
            try:
                fb_client.submit_nextflow_job(args)
            except Exception as e:
                die(f"Failed to submit Nextflow job: {e}")

    except KeyboardInterrupt:
        logger.info("Operation interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
