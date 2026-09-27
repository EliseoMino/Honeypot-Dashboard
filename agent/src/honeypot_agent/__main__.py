"""Command line entry point of the ingestion agent."""

from __future__ import annotations

import argparse
import logging
import signal
import sys

from honeypot_agent.config import AgentSettings, get_agent_settings
from honeypot_agent.pipeline import IngestPipeline


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="honeypot-agent",
        description="Tail Cowrie cowrie.json and ship the events to the backend over TLS 1.3.",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="read what is available, deliver at most one batch and exit",
    )
    parser.add_argument(
        "--log-level",
        default=None,
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="override the configured log level",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    settings = _load_settings(args.log_level)
    logging.basicConfig(
        level=settings.log_level.upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    pipeline = IngestPipeline(settings)

    if args.once:
        sent = pipeline.run_once()
        pipeline.shutdown()
        return 0 if sent or not pipeline.stats.delivery_failures else 1

    def _handle_signal(signum: int, _frame: object) -> None:
        logging.getLogger(__name__).info("received signal %s, stopping", signum)
        pipeline.request_stop()

    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, _handle_signal)

    pipeline.run_forever()
    return 0


def _load_settings(log_level: str | None) -> AgentSettings:
    if log_level is None:
        return get_agent_settings()
    return AgentSettings(log_level=log_level)


if __name__ == "__main__":
    sys.exit(main())
