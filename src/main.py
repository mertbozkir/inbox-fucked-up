#!/usr/bin/env python3

import mailbox
import email
from email import utils
import re
import os
from collections import Counter, defaultdict
from email.header import decode_header
import argparse
from datetime import datetime, timedelta
import sys
from typing import Dict, List, Tuple, Optional, Set
import csv
from pathlib import Path
import time
import hashlib


def decode_str(s):
    """Decode encoded email header strings."""
    if s is None:
        return ""
    decoded_parts = decode_header(s)
    result = ""
    for part, encoding in decoded_parts:
        if isinstance(part, bytes):
            try:
                if encoding:
                    result += part.decode(encoding)
                else:
                    result += part.decode('utf-8', errors='replace')
            except Exception:
                result += part.decode('utf-8', errors='replace')
        else:
            result += str(part)
    return result


def extract_sender_email(from_header: str) -> str:
    """Extract email address from the From header."""
    if not from_header:
        return ""
    
    # Try to match email pattern
    email_match = re.search(r'[\w\.-]+@[\w\.-]+', from_header)
    if email_match:
        return email_match.group(0).lower()
    return ""


def extract_sender_domain(email_address: str) -> str:
    """Extract domain from email address, handling special cases.
    
    Examples:
        - interrupt@langchain.dev -> langchain.dev
        - notifications@pytorch1.discoursemail.com -> discoursemail.com
    """
    if not email_address or '@' not in email_address:
        return ""
        
    # Get the domain part after @
    domain = email_address.split('@')[1].lower()
    
    # Special case handling for common email services with subdomains
    domain_parts = domain.split('.')
    
    # Handle special cases
    if len(domain_parts) > 2:
        # Check for common email services with numbered subdomains
        if any(part.isdigit() or (part[:-1].isdigit() and part[-1].isalpha()) for part in domain_parts[:-2]):
            # For cases like pytorch1.discoursemail.com -> discoursemail.com
            # Find the first part that's not a number or number+letter
            for i, part in enumerate(domain_parts[:-2]):
                if not (part.isdigit() or (part[:-1].isdigit() and part[-1].isalpha())):
                    return '.'.join(domain_parts[i:])
            # If all parts are numbers, return the main domain
            return '.'.join(domain_parts[-2:])
            
        # Special case for common email services
        common_email_domains = {
            'gmail': 'gmail.com',
            'googlemail': 'gmail.com',
            'hotmail': 'hotmail.com',
            'outlook': 'outlook.com',
            'yahoo': 'yahoo.com',
            'aol': 'aol.com',
            'protonmail': 'protonmail.com',
            'icloud': 'icloud.com',
        }
        
        for service, main_domain in common_email_domains.items():
            if service in domain_parts:
                return main_domain
                
        # For most other domains, we want to extract the main domain
        # This handles cases like notifications.github.com -> github.com
        # But keeps domains like co.uk intact
        tlds = ['com', 'org', 'net', 'edu', 'gov', 'mil', 'io', 'ai', 'dev', 'app']
        country_tlds = ['uk', 'us', 'ca', 'au', 'de', 'fr', 'jp', 'cn', 'in', 'br']
        
        # Check if we have a country TLD with a service TLD (like co.uk)
        if domain_parts[-1] in country_tlds and domain_parts[-2] in ['co', 'com', 'org', 'net', 'ac']:
            # For domains like example.co.uk, return co.uk
            if len(domain_parts) > 2:
                return '.'.join(domain_parts[-3:])
        
        # For most domains, return the main domain and TLD
        if domain_parts[-1] in tlds or domain_parts[-1] in country_tlds:
            return '.'.join(domain_parts[-2:])
    
    return domain


def print_progress_bar(iteration, total, prefix='', suffix='', length=50, fill='█', print_end='\r'):
    """Print a progress bar to the console."""
    percent = ("{0:.1f}").format(100 * (iteration / float(total)))
    filled_length = int(length * iteration // total)
    bar = fill * filled_length + '-' * (length - filled_length)
    print(f'\r{prefix} |{bar}| {percent}% {suffix}', end=print_end)
    # Print a new line on completion
    if iteration == total:
        print()


def get_message_id(message) -> str:
    """Extract a unique identifier for a message to detect duplicates."""
    # Try to use Message-ID header
    message_id = message.get('Message-ID', '')
    if message_id:
        return message_id
    
    # If no Message-ID, create a hash from subject, date and from
    subject = decode_str(message.get('Subject', ''))
    date = message.get('Date', '')
    from_header = decode_str(message.get('From', ''))
    
    # Create a hash from these fields
    hash_input = f"{subject}|{date}|{from_header}"
    return hashlib.md5(hash_input.encode()).hexdigest()


def analyze_mbox(mbox_path: str, time_period: Optional[int] = None, 
                 detect_duplicates: bool = True) -> Tuple[Counter, Counter, Dict[str, List[str]], Dict[str, int]]:
    """
    Analyze mbox file and count email senders.
    
    Args:
        mbox_path: Path to the mbox file
        time_period: If provided, only analyze emails from the last N days
        detect_duplicates: If True, detect and report duplicate emails
        
    Returns:
        Tuple of (email counter, domain counter, domain to emails mapping, folder stats)
    """
    if not os.path.exists(mbox_path):
        print(f"Error: File {mbox_path} not found!")
        sys.exit(1)
        
    print(f"Analyzing {mbox_path}...")
    
    # Initialize counters
    email_counter: Counter = Counter()
    domain_counter: Counter = Counter()
    domain_to_emails: Dict[str, List[str]] = {}
    folder_stats: Dict[str, int] = defaultdict(int)
    
    # For duplicate detection
    seen_message_ids: Set[str] = set()
    duplicate_count = 0
    
    # Calculate cutoff date if time period is specified
    cutoff_date = None
    if time_period:
        cutoff_date = datetime.now() - timedelta(days=time_period)
    
    # Process the mbox file
    mbox = mailbox.mbox(mbox_path)
    total_messages = len(mbox)
    processed = 0
    
    start_time = time.time()
    last_update = start_time
    
    for message in mbox:
        processed += 1
        
        # Update progress bar every 0.1 seconds
        current_time = time.time()
        if current_time - last_update > 0.1 or processed == total_messages:
            last_update = current_time
            elapsed = current_time - start_time
            emails_per_second = processed / elapsed if elapsed > 0 else 0
            
            # Estimate time remaining
            if processed > 0 and processed < total_messages:
                remaining_messages = total_messages - processed
                estimated_seconds = remaining_messages / emails_per_second if emails_per_second > 0 else 0
                minutes, seconds = divmod(int(estimated_seconds), 60)
                hours, minutes = divmod(minutes, 60)
                time_remaining = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
            else:
                time_remaining = "00:00:00"
                
            suffix = f"{processed}/{total_messages} | {emails_per_second:.1f} emails/s | ETA: {time_remaining}"
            print_progress_bar(processed, total_messages, prefix='Progress:', suffix=suffix, length=40)
        
        # Check for duplicates
        if detect_duplicates:
            message_id = get_message_id(message)
            if message_id in seen_message_ids:
                duplicate_count += 1
                continue
            seen_message_ids.add(message_id)
        
        # Track folder statistics
        folder = None
        for header in message.keys():
            if header.lower() == 'x-gmail-labels':
                labels = message[header].split(',')
                for label in labels:
                    label = label.strip()
                    if label:
                        folder_stats[label] += 1
                break
        
        # If no Gmail labels, try to determine folder from other headers
        if not folder:
            # Check common folder headers
            for header_name in ['X-Folder', 'Folder', 'X-Mozilla-Status']:
                if header_name in message:
                    folder_stats[f"Other-{message[header_name]}"] += 1
                    break
            else:
                folder_stats['Unknown'] += 1
        
        # Check if message is within time period
        if cutoff_date:
            date_str = message.get('Date')
            if date_str:
                try:
                    # Parse the date (this is simplified and might not work for all date formats)
                    date = utils.parsedate_to_datetime(date_str)
                    if date < cutoff_date:
                        continue
                except Exception:
                    # If we can't parse the date, include the message anyway
                    pass
        
        # Extract sender information
        from_header = decode_str(message.get('From', ''))
        sender_email = extract_sender_email(from_header)
        
        if sender_email:
            email_counter[sender_email] += 1
            
            domain = extract_sender_domain(sender_email)
            if domain:
                domain_counter[domain] += 1
                
                # Map domain to emails
                if domain not in domain_to_emails:
                    domain_to_emails[domain] = []
                if sender_email not in domain_to_emails[domain]:
                    domain_to_emails[domain].append(sender_email)
    
    elapsed_time = time.time() - start_time
    hours, remainder = divmod(elapsed_time, 3600)
    minutes, seconds = divmod(remainder, 60)
    
    print(f"\nAnalysis complete!")
    print(f"Processed {processed} emails in {int(hours):02d}:{int(minutes):02d}:{seconds:.2f}")
    
    if detect_duplicates:
        print(f"Found {duplicate_count} duplicate emails ({duplicate_count/total_messages*100:.1f}% of total)")
        print(f"Unique emails: {len(seen_message_ids)}")
    
    return email_counter, domain_counter, domain_to_emails, folder_stats


def print_results(email_counter: Counter, domain_counter: Counter, 
                  domain_to_emails: Dict[str, List[str]], folder_stats: Dict[str, int],
                  top_n: int = 20, show_domains: bool = True, show_emails: bool = True,
                  export_csv: Optional[str] = None, min_count: int = 10) -> None:
    """Print analysis results and optionally export to CSV."""
    print("\n" + "="*50)
    
    # Print folder statistics
    print("\nEmail Folder Statistics:")
    print("-"*50)
    for folder, count in sorted(folder_stats.items(), key=lambda x: x[1], reverse=True)[:top_n]:
        print(f"{folder}: {count} emails")
    
    if show_domains:
        print("\n" + "="*50)
        print(f"\nTop {top_n} Domains by Email Count:")
        print("-"*50)
        for domain, count in domain_counter.most_common(top_n):
            print(f"{domain}: {count} emails")
    
    if show_emails:
        print("\n" + "="*50)
        print(f"\nTop {top_n} Email Addresses by Count:")
        print("-"*50)
        for email, count in email_counter.most_common(top_n):
            print(f"{email}: {count} emails")
    
    print("\n" + "="*50)
    print("\nPotential Unsubscribe Candidates:")
    print("-"*50)
    
    # Find newsletters and marketing emails (simplified approach)
    newsletter_keywords = ['newsletter', 'noreply', 'no-reply', 'updates', 'info', 'news', 
                          'marketing', 'mail', 'email', 'alert', 'notification', 'digest',
                          'support', 'hello', 'contact', 'team', 'community', 'reply']
    
    potential_unsubs = []
    
    for email, count in email_counter.items():
        # Check if it's likely a newsletter or marketing email
        is_likely_newsletter = any(keyword in email.lower() for keyword in newsletter_keywords)
        
        # Consider frequency and likelihood of being a newsletter
        if (count >= min_count and is_likely_newsletter) or count >= max(30, min_count * 3):
            potential_unsubs.append((email, count))
    
    # Sort by count (descending)
    potential_unsubs.sort(key=lambda x: x[1], reverse=True)
    
    # Print top candidates
    for email, count in potential_unsubs[:top_n]:
        print(f"{email}: {count} emails")
    
    # Export to CSV if requested
    if export_csv:
        export_path = Path(export_csv)
        
        # Create directory if it doesn't exist
        export_path.parent.mkdir(parents=True, exist_ok=True)
        
        print(f"\nExporting results to {export_csv}...")
        
        with open(export_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            
            # Write headers
            writer.writerow(['Type', 'Address', 'Count', 'Domain'])
            
            # Write folder data
            for folder, count in sorted(folder_stats.items(), key=lambda x: x[1], reverse=True):
                writer.writerow(['Folder', folder, count, ''])
            
            # Write domain data
            for domain, count in domain_counter.most_common():
                writer.writerow(['Domain', domain, count, ''])
            
            # Write email data
            for email, count in email_counter.most_common():
                domain = extract_sender_domain(email)
                writer.writerow(['Email', email, count, domain])
            
            # Write unsubscribe candidates
            for email, count in potential_unsubs:
                domain = extract_sender_domain(email)
                writer.writerow(['Unsubscribe Candidate', email, count, domain])
        
        print(f"Export complete! File saved to {export_csv}")


def main():
    parser = argparse.ArgumentParser(description='Analyze mbox file to find email addresses to unsubscribe from.')
    parser.add_argument('--mbox', default='mail/all-mail.mbox', help='Path to the mbox file')
    parser.add_argument('--top', type=int, default=20, help='Number of top results to show')
    parser.add_argument('--period', type=int, help='Only analyze emails from the last N days')
    parser.add_argument('--domains-only', action='store_true', help='Only show domain statistics')
    parser.add_argument('--emails-only', action='store_true', help='Only show email statistics')
    parser.add_argument('--export', help='Export results to CSV file')
    parser.add_argument('--min-count', type=int, default=10, help='Minimum email count to consider for unsubscribe')
    parser.add_argument('--no-duplicates', action='store_true', help='Detect and skip duplicate emails')
    
    args = parser.parse_args()
    
    # Analyze the mbox file
    email_counter, domain_counter, domain_to_emails, folder_stats = analyze_mbox(
        args.mbox, 
        time_period=args.period,
        detect_duplicates=args.no_duplicates
    )
    
    # Determine what to show
    show_domains = True
    show_emails = True
    
    if args.domains_only:
        show_emails = False
    if args.emails_only:
        show_domains = False
    
    # Print results
    print_results(
        email_counter, 
        domain_counter, 
        domain_to_emails,
        folder_stats,
        top_n=args.top,
        show_domains=show_domains,
        show_emails=show_emails,
        export_csv=args.export,
        min_count=args.min_count
    )


if __name__ == "__main__":
    main()
