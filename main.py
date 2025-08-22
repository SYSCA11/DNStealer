import dns.resolver
import argparse
from colorama import Fore

parser = argparse.ArgumentParser(description='DNS Enumerator')
parser.add_argument('-d', '--domain', nargs="*", required=True, help="Enter domain(s)")
parser.add_argument('-enumSubdomains', required=False, help="Whether you want to search for subdomains. Enter file of list of subdomain names wished to look up")
parser.add_argument('-enumTLD', required=False, help="Whether you want to search available and unavailable TLD's of a domain. Enter file of list of subdomain names wished to look up")
parser.add_argument('-enumSec', required=False, help="Check a domains, SPF, DKIM, DMARC", type=bool)


args = parser.parse_args()

record_types = ['A', 'AAAA', 'NS', 'MX', 'PTR', 'SOA', 'TXT', 'CNAME'] 


def get_DNS_data(domains):
    for domain in domains:
        print(f"{Fore.BLUE}------------Domain: {domain}------------{Fore.RESET}")
        for type in record_types:
            try:
                answers = dns.resolver.resolve(domain, type)
                print(f"{Fore.YELLOW}-----Record: {type}-----{Fore.RESET}")
                for server in answers:
                    print(server.to_text()+"\n")

            except dns.resolver.NoAnswer:
                print("No Record found.")
                pass #try the next type
            except KeyboardInterrupt:
                quit()
            except dns.resolver.NXDOMAIN:
                print("Invalid domain")
                quit()
            except Exception as e:
                print(f"Error: {e}")
                quit()


def enumerate_subdomains(domains):
    for domain in domains:
        try:
            with open(args.enumsubdomains, 'r') as file:
                print(f"{Fore.BLUE}------------subdomains of: {domain}------------{Fore.RESET}")
                lines = file.readlines()

                for line in lines:
                    subdomain = line.strip()
                    try:
                        ip_value = dns.resolver.resolve(f"{subdomain}.{domain}.com","A")
                        if ip_value:
                            print(f"{subdomain}.{domain}.com")
                    except Exception:
                        pass
        except FileNotFoundError:
                    print("File Not Found")    


def enumerate_TLDs(domains):
    for domain in domains:
        print(f"{Fore.BLUE}------------similar domains: {domain}------------{Fore.RESET}")

        domain = domain.partition('.')[0]

        try:
            with open(args.enumTLD, 'r') as tlds, open(args.enumsubdomains) as subs:
                tlds = [line.strip() for line in tlds.readlines()]
                subs = [line.strip() for line in subs.readlines()]

                for tld in tlds:
                    for sub in subs:
                        domain1 = f"{domain}{sub}.{tld}"
                        domain2 = f"{domain}-{sub}.{tld}"
                        
                        for d in [domain1,domain2]:
                            try:
                                dns.resolver.resolve(d, "A")
                                print(f"{Fore.RED}{d} Taken{Fore.RESET}")
                            except dns.resolver.NXDOMAIN:
                                print(f"{Fore.GREEN}{d} Available{Fore.RESET}")
                            except Exception:
                                pass
                            
        except FileNotFoundError:
            print("Need file")
        except KeyboardInterrupt:
            quit()
        except:
            pass

#check sec - spf, dkim, dmarc
def check_sec(domains):
    selectors = [
    "google._domainkey",
    "selector1._domainkey",
    "selector2._domainkey",
    "k1._domainkey",
    "mandrill._domainkey",
    "s1._domainkey",
    "s2._domainkey",
    "smtpapi._domainkey",
    "amazonses._domainkey",
    "default._domainkey",
    "dkim._domainkey",
    "zoho._domainkey",
    "zmail._domainkey",
    "everlytickey1._domainkey",
    "everlytickey2._domainkey",
    "mxvault._domainkey",
    "ctct1._domainkey",
    "ctct2._domainkey",
    "sm._domainkey",
    "sig1._domainkey",
    "litesrv._domainkey",
    "zendesk1._domainkey",
    "zendesk2._domainkey",
    "mail._domainkey",
    "email._domainkey"
    ]
    #check spf
    for domain in domains:
        try:
            spf_records = dns.resolver.resolve(domain, 'TXT')
            for spf_record in spf_records:
                record = spf_record.to_text()
                if "v=spf1" in record:
                    print(f"SPF: {record}")
        except Exception as e:
            print(e)

    #check dmarc
    for domain in domains:
        try:
            dmarc_records = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
            for dmarc_record in dmarc_records:
                record = dmarc_record.to_text()
                if "v=DMARC1" in record:
                    print(f"DMARC: {record}")
        except Exception as e:
            print(e)

    #check dkim
    for domain in domains:
        try:
            for selector in selectors:
                dkim_records = dns.resolver.resolve(f"{selector}._domainkey.{domain}", "TXT")
                for record in dkim_records:
                    record = record.to_text()
                    if "v=DKIM1" in record:
                        print(f"Selector: {selector}")
                        print(f"DKIM: {record}")

        except Exception as e:
            pass

def main():
    
    get_DNS_data(args.domain)

    if args.enumSubdomains:    
        enumerate_subdomains(args.domain)
    if args.enumTLD:
         enumerate_TLDs(args.domain)
    if args.enumSec:    
        check_sec(args.domain)


if __name__ == "__main__":
    main()