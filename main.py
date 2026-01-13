import sys
from colorama import Fore, Style, init
from modules.scanner import PhishScanner
from modules.reporter import ReportGenerator  # <--- NEW: Import the reporter

init(autoreset=True)


def print_banner():
    print(Fore.CYAN + "=" * 45)
    print(Fore.CYAN + "      PHISHLYZER: SENDER ANALYSIS TOOL")
    print(Fore.CYAN + "=" * 45 + Style.RESET_ALL)


def main():
    print_banner()
    scanner = PhishScanner()
    reporter = ReportGenerator()  # <--- NEW: Initialize the reporter

    while True:
        email = input(f"\n{Fore.YELLOW}Enter sender email to analyze (or 'exit' to quit): {Style.RESET_ALL}").strip()

        if email.lower() == 'exit':
            print(Fore.CYAN + "Goodbye!")
            break

        if not email or "@" not in email:
            print(Fore.RED + "[!] Please enter a valid email address.")
            continue

        try:
            results = scanner.scan_email(email)

            # --- NEW: Save the reports automatically ---
            json_path = reporter.save_json(results)
            pdf_path = reporter.save_pdf(results)

            # Print Summary
            score = results['risk_score']
            color = Fore.GREEN if score < 30 else Fore.YELLOW if score < 70 else Fore.RED

            print(f"\n{Fore.WHITE}{'=' * 20} RESULTS {'=' * 20}")
            print(f"Target Domain: {results['domain']}")
            print(f"Risk Score:    {color}{score}/100")
            print(f"{Fore.CYAN}[+] Reports saved to the 'data' folder:")
            print(f"    - PDF: {pdf_path}")
            print(f"    - JSON: {json_path}")
            print(f"{Fore.WHITE}{'=' * 49}\n")

        except Exception as e:
            print(f"{Fore.RED}[X] Error during analysis: {e}")


if __name__ == "__main__":
    main()