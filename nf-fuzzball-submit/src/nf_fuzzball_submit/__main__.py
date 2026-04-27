"""Main entry point for nf-fuzzball-submit."""

import getpass
import os
import sys
from importlib.metadata import PackageNotFoundError

from .auth import ConfigFileAuthenticator
from .cli import parse_cli
from .client import create_fuzzball_client
from .utils import setup_logging


def main() -> None:
    """Main function that parses arguments and submits the Nextflow job."""
    verbose = False
    logger = setup_logging(verbose)

    try:
        try:
            args = parse_cli()
        except SystemExit:
            raise
        except PackageNotFoundError:
            logger.error("Package metadata could not be determined. Is nf-fuzzball-submit installed?")
            sys.exit(1)

        if args.verbose or args.dry_run:
            verbose = True
            logger = setup_logging(verbose=verbose)

        if args.device:
            logger.info("Using device based authentication via the browser.")
        elif args.user:
            logger.info("Username provided. Using direct authentication.")
        else:
            logger.info(f"Obtaining fuzzball auth information from config file '{args.fuzzball_config}'.")

        # For direct/device login, fill in any unset connection params from the
        # config file as the lowest-precedence fallback (CLI > env var > config file).
        if (args.user or args.device) and any(v is None for v in [args.api_url, args.auth_url, args.account_id]):
            defaults = ConfigFileAuthenticator.connection_defaults(args.fuzzball_config.expanduser(), args.context)
            args.api_url = args.api_url or defaults.get("api_url", None)
            args.auth_url = args.auth_url or defaults.get("auth_url", None)
            args.account_id = args.account_id or defaults.get("account_id", None)
            # are we still missing values?
            if any(v is None for v in [args.api_url, args.auth_url, args.account_id]):
                logger.error("For direct or device authentication, api url, auth url, and account_id are required.")
                logger.error(f"api url:  {args.api_url}")
                logger.error(f"auth url: {args.auth_url}")
                logger.error(f"account:  {args.account_id}")
                sys.exit(1)

        password = None
        if args.user:
            if args.password:
                password = getpass.getpass("Enter Fuzzball password: ")
            else:
                password = os.environ.get("FUZZBALL_PASSWORD")
            if not password:
                logger.error("Password is required for direct login. Use --password or set FUZZBALL_PASSWORD.")
                sys.exit(1)

        try:
            fb_client = create_fuzzball_client(
                config_path=args.fuzzball_config.expanduser(),
                context=args.context,
                ca_cert_file=args.ca_cert,
                api_url=args.api_url,
                auth_url=args.auth_url,
                user=args.user,
                password=password,
                account_id=args.account_id,
                device_login=args.device,
                fb_version=args.fb_version,
            )
        except Exception as e:
            logger.error(f"Failed to create the Fuzzball API client: {e}", exc_info=verbose)
            sys.exit(1)

        try:
            fb_client.submit_nextflow_job(args)
        except Exception as e:
            logger.error(f"Failed to submit Nextflow job: {e}", exc_info=verbose)
            sys.exit(1)

    except KeyboardInterrupt:
        logger.warning("Interrupted.")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=verbose)
        sys.exit(1)


if __name__ == "__main__":
    main()
