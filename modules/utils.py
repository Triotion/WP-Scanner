#!/usr/bin/env python3
"""Shared utilities for WP-Scanner: banner, logging, printing, user agents."""

from __future__ import annotations

import logging
import os
import random
import sys
import time
from datetime import datetime
from functools import wraps
from typing import Any, Callable, TypeVar

from colorama import Fore, Style

F = TypeVar("F", bound=Callable[..., Any])

USER_AGENTS: list[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36",
]


def banner() -> None:
    """Display the tool banner."""
    banner_text = f"""
{Fore.GREEN}██╗    ██╗██████╗       ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗
██║    ██║██╔══██╗      ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
██║ █╗ ██║██████╔╝█████╗███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
██║███╗██║██╔═══╝ ╚════╝╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
╚███╔███╔╝██║           ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
 ╚══╝╚══╝ ╚═╝           ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝{Style.RESET_ALL}
                        {Fore.CYAN}WordPress Vulnerability Scanner & Exploitation Tool{Style.RESET_ALL}
                                        {Fore.YELLOW}Version 3.0.0{Style.RESET_ALL}
"""
    print(banner_text)


def create_directory(directory: str) -> bool:
    """Create directory if it doesn't exist. Returns True if created."""
    if not os.path.exists(directory):
        os.makedirs(directory, exist_ok=True)
        return True
    return False


def print_info(message: str) -> None:
    print(f"{Fore.BLUE}[*]{Style.RESET_ALL} {message}")


def print_success(message: str) -> None:
    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {message}")


def print_warning(message: str) -> None:
    print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {message}")


def print_error(message: str) -> None:
    print(f"{Fore.RED}[-]{Style.RESET_ALL} {message}")


def print_verbose(message: str, verbose: bool = False) -> None:
    """Print verbose message. Callers must pass verbose=True to display."""
    if verbose:
        print(f"{Fore.MAGENTA}[v]{Style.RESET_ALL} {message}")


def get_random_user_agent() -> str:
    """Return a random modern user agent string."""
    return random.choice(USER_AGENTS)


def rate_limit(delay: float = 1.0) -> Callable[[F], F]:
    """Decorator to rate-limit function calls."""

    def decorator(func: F) -> F:
        last_called = [0.0]

        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            elapsed = time.time() - last_called[0]
            if elapsed < delay:
                time.sleep(delay - elapsed)
            result = func(*args, **kwargs)
            last_called[0] = time.time()
            return result

        return wrapper  # type: ignore[return-value]

    return decorator


class Logger:
    """File logger backed by Python's logging module."""

    def __init__(self, log_file: str) -> None:
        self.log_file = log_file
        log_dir = os.path.dirname(log_file)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)

        self._logger = logging.getLogger(f"wp_scanner_{id(self)}")
        self._logger.setLevel(logging.DEBUG)
        self._logger.handlers.clear()

        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fmt = logging.Formatter("[%(asctime)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
        fh.setFormatter(fmt)
        self._logger.addHandler(fh)

        self._logger.info(
            "=== WP-Scanner Log - %s ===\n",
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )

    def log(self, message: str) -> None:
        """Append message to log file with timestamp."""
        self._logger.info(message)
