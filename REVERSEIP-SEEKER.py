import requests
from bs4 import BeautifulSoup
import re
from colorama import init, Fore, Style, Back
import urllib.parse
import time
import os
from tqdm import tqdm

# Initialize colorama
init()

def print_banner():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(Fore.CYAN + """
   ____            _     ____  _   _ ____  
  |  _ \ __ _ _ __| |_  |  _ \| \ | / ___| 
  | |_) / _` | '__| __| | | | |  \| \___ \ 
  |  __/ (_| | |  | |_  | |_| | |\  |___) |
  |_|   \__,_|_|   \__| |____/|_| \_|____/ 
  """ + Style.RESET_ALL)
    print(Fore.YELLOW + "  REVERSE IP DATABASE SEEKER" + Style.RESET_ALL)
    print(Fore.MAGENTA + "  ----------------------------------" + Style.RESET_ALL)

def query_rapiddns(ip_or_cidr, page=1):
    """Query RapidDNS.io with improved error handling"""
    base_url = f"https://rapiddns.io/sameip/{urllib.parse.quote(ip_or_cidr)}"
    url = f"{base_url}?page={page}" if page > 1 else base_url
    
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept-Language': 'en-US,en;q=0.9',
        }
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, 'html.parser')
        table = soup.find('table', {'id': 'table'})
        
        if not table:
            return [], False
        
        hostnames = []
        rows = table.find_all('tr')[1:]  # Skip header
        
        for row in rows:
            cols = row.find_all('td')
            if len(cols) >= 2:
                hostname = cols[0].get_text(strip=True)
                if hostname:
                    hostnames.append(hostname)
        
        # Improved pagination detection
        pagination = soup.find('ul', class_='pagination')
        if not pagination:
            return hostnames, False
            
        last_page = 1
        for link in pagination.find_all('a'):
            if link.text.isdigit():
                last_page = max(last_page, int(link.text))
        
        return hostnames, page < last_page
        
    except Exception as e:
        print(Fore.RED + f"\nError on page {page}: {str(e)}" + Style.RESET_ALL)
        return [], False

def scan_target(ip_or_cidr):
    """Perform the complete scan with progress tracking"""
    all_hostnames = []
    page = 1
    has_next = True
    max_retries = 3
    
    with tqdm(total=100, desc=Fore.CYAN + "Extracting Pages" + Style.RESET_ALL, 
              bar_format="{l_bar}%s{bar}%s{r_bar}" % (Fore.CYAN, Style.RESET_ALL)) as pbar:
        
        while has_next:
            retries = 0
            hostnames = []
            
            while retries < max_retries:
                hostnames, has_next = query_rapiddns(ip_or_cidr, page)
                if hostnames:
                    break
                retries += 1
                time.sleep(retries * 2)
            
            if hostnames:
                all_hostnames.extend(hostnames)
                pbar.update(1)
                pbar.set_postfix({"Hostnames": len(all_hostnames), "Page": page})
            
            page += 1
            time.sleep(1.2)  # Polite delay
            
            # Update total if we detect more pages
            if has_next and page > pbar.total:
                pbar.total = page + 10  # Add buffer
    
    return all_hostnames

def save_results(hostnames, filename="rapiddns_results.txt"):
    """Save results to file"""
    try:
        with open(filename, 'w') as f:
            f.write('\n'.join(hostnames))
        print(Fore.GREEN + f"\nResults saved to {filename} ({len(hostnames)} hostnames)" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"\nError saving file: {str(e)}" + Style.RESET_ALL)

def main():
    print_banner()
    
    while True:
        print("\n" + Fore.YELLOW + "[1] New Scan" + Style.RESET_ALL)
        print(Fore.YELLOW + "[2] Exit" + Style.RESET_ALL)
        choice = input(Fore.CYAN + "\nSelect option: " + Style.RESET_ALL).strip()
        
        if choice == '2':
            break
            
        if choice == '1':
            ip_or_cidr = input(Fore.BLUE + "\nEnter IP/CIDR (e.g., 1.1.1.1 or 1.1.1.0/24): " + Style.RESET_ALL).strip()
            
            if not re.match(r'^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$', ip_or_cidr):
                print(Fore.RED + "\nInvalid input format!" + Style.RESET_ALL)
                time.sleep(1.5)
                continue
                
            print(Fore.MAGENTA + "\nStarting scan..." + Style.RESET_ALL)
            start_time = time.time()
            
            try:
                hostnames = scan_target(ip_or_cidr)
                
                if not hostnames:
                    print(Fore.RED + "\nNo hostnames found for the specified IP/CIDR." + Style.RESET_ALL)
                    continue
                    
                elapsed = time.time() - start_time
                print(Fore.GREEN + f"\nScan completed in {elapsed:.2f} seconds" + Style.RESET_ALL)
                print(Fore.GREEN + f"Total hostnames found: {len(hostnames)}" + Style.RESET_ALL)
                
                save = input(Fore.CYAN + "\nSave results to file? (y/n): " + Style.RESET_ALL).lower()
                if save == 'y':
                    filename = input(Fore.CYAN + "Enter filename (default: rapiddns_results.txt): " + Style.RESET_ALL).strip()
                    save_results(hostnames, filename or "rapiddns_results.txt")
                
            except KeyboardInterrupt:
                print(Fore.RED + "\nScan interrupted by user!" + Style.RESET_ALL)
            except Exception as e:
                print(Fore.RED + f"\nFatal error during scan: {str(e)}" + Style.RESET_ALL)
            
            input(Fore.CYAN + "\nPress Enter to continue..." + Style.RESET_ALL)
            print_banner()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(Fore.RED + "\nProgram terminated by user" + Style.RESET_ALL)
    finally:
        print(Fore.YELLOW + "\nGoodbye!" + Style.RESET_ALL)