#!/usr/bin/env python3

import os
import sys
import time
from datetime import datetime
from colorama import Fore, Style
import random

def banner():
    """Display the tool banner"""
    banner_text = f"""
{Fore.GREEN}██╗    ██╗██████╗       ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
██║    ██║██╔══██╗      ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
██║ █╗ ██║██████╔╝█████╗███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
██║███╗██║██╔═══╝ ╚════╝╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
╚███╔███╔╝██║           ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
 ╚══╝╚══╝ ╚═╝           ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝{Style.RESET_ALL}
                        {Fore.CYAN}WordPress Vulnerability Scanner & Exploitation Tool{Style.RESET_ALL}
                                        {Fore.YELLOW}Version 2.0{Style.RESET_ALL}
"""
    print(banner_text)

def create_directory(directory):
    """Create directory if it doesn't exist"""
    if not os.path.exists(directory):
        os.makedirs(directory, exist_ok=True)
        return True
    return False

def print_info(message):
    """Print info message"""
    print(f"{Fore.BLUE}[*]{Style.RESET_ALL} {message}")

def print_success(message):
    """Print success message"""
    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {message}")

def print_warning(message):
    """Print warning message"""
    print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {message}")

def print_error(message):
    """Print error message"""
    print(f"{Fore.RED}[-]{Style.RESET_ALL} {message}")

def print_verbose(message, verbose=False):
    """Print verbose message if verbose mode is enabled"""
    if verbose:
        print(f"{Fore.MAGENTA}[v]{Style.RESET_ALL} {message}")

class Logger:
    """Simple logging class"""
    def __init__(self, log_file):
        self.log_file = log_file
        

        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
            

        with open(self.log_file, 'w') as f:
            f.write(f"=== WP-Scanner Log - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===\n\n")
    
    def log(self, message):
        """Append message to log file with timestamp"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with open(self.log_file, 'a') as f:
            f.write(f"[{timestamp}] {message}\n")


        
def get_random_user_agent():
    """Return a random user agent string"""
    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36 Edg/90.0.818.66'
    ]
    return random.choice(user_agents)

def rate_limit(delay=1.0):
    """Simple decorator to rate limit function calls"""
    def decorator(func):
        last_time_called = [0.0]
        def wrapper(*args, **kwargs):
            elapsed = time.time() - last_time_called[0]
            if elapsed < delay:
                time.sleep(delay - elapsed)
            result = func(*args, **kwargs)
            last_time_called[0] = time.time()
            return result
        return wrapper
    return decorator 