import sys
from colorama import Fore, Style, init
from modules.scanner import PhishScanner
from modules.reporter import ReportGenerator

init(autoreset=True)


def print_banner():
    print(Fore.CYAN + "=" * 45)
    print(Fore.CYAN + "      PHISHLYZER: SENDER ANALYSIS TOOL")
    print(Fore.CYAN + "=" * 45 + Style.RESET_ALL)


def main():
    print_banner()
    scanner = PhishScanner()
    reporter = ReportGenerator()

    while True:
        email = input(f"\n{Fore.YELLOW}Enter sender email to analyze (or 'exit' to quit): {Style.RESET_ALL}").strip()

        if email.lower() == 'exit':
            print(Fore.CYAN + "Goodbye!")
            break

        if not email:
            print(Fore.RED + "[!] Please enter a valid email address or IP.")
            continue

        try:
            results = scanner.scan_email(email)

            # --- Save the reports automatically ---
            json_path = reporter.save_json(results)
            pdf_path = reporter.save_pdf(results)

            # --- Safe Extraction for Printing ---
            # We use .get() to prevent the 'domain' KeyError crash
            score = results.get('risk_score', 0)
            # Use 'target' if 'domain' is missing (common for IP scans)
            display_name = results.get('domain') or results.get('target', 'Unknown')

            color = Fore.GREEN if score < 30 else Fore.YELLOW if score < 70 else Fore.RED

            print(f"\n{Fore.WHITE}{'=' * 20} RESULTS {'=' * 20}")
            print(f"Target:        {display_name}")
            print(f"Risk Score:    {color}{score}/100")
            print(f"{Fore.CYAN}[+] Reports saved to the 'data' folder:")
            print(f"    - PDF: {pdf_path}")
            print(f"    - JSON: {json_path}")
            print(f"{Fore.WHITE}{'=' * 49}\n")

        except Exception as e:
            # This catches any remaining UI-level errors without closing the app
            print(f"{Fore.RED}[X] UI Error: {e}")


if __name__ == "__main__":
    main()