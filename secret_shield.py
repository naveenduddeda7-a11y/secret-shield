import os
import re
import json


# Patterns used to detect possible secrets
PATTERNS = {
    "Password": r'password\s*=\s*["\'][^"\']+["\']',

    "API Key": r'api[_-]?key\s*=\s*["\'][^"\']+["\']',

    "Secret Key": r'secret[_-]?key\s*=\s*["\'][^"\']+["\']',

    "Access Token": r'access[_-]?token\s*=\s*["\'][^"\']+["\']'
}


# Severity level for each secret type
SEVERITY = {
    "Password": "HIGH",
    "API Key": "HIGH",
    "Secret Key": "CRITICAL",
    "Access Token": "CRITICAL"
}


def scan_file(file_path):

    findings = []

    try:

        with open(file_path, "r", errors="ignore") as file:

            lines = file.readlines()

        for line_number, line in enumerate(lines, start=1):

            for secret_type, pattern in PATTERNS.items():

                if re.search(pattern, line, re.IGNORECASE):

                    findings.append({
                        "file": file_path,
                        "line": line_number,
                        "type": secret_type,
                        "severity": SEVERITY[secret_type]
                    })

    except Exception as e:

        print(f"Error reading {file_path}: {e}")

    return findings


def scan_project():

    findings = []

    ignored_directories = {
        ".git",
        "venv",
        "__pycache__"
    }

    for root, directories, files in os.walk("."):

        directories[:] = [
            directory
            for directory in directories
            if directory not in ignored_directories
        ]

        for file in files:

            if file.endswith((
                ".py",
                ".js",
                ".java",
                ".php",
                ".yml",
                ".yaml",
                ".json",
                ".env",
                ".txt"
            )):

                file_path = os.path.join(root, file)

                results = scan_file(file_path)

                findings.extend(results)

    return findings


def generate_report(findings):

    os.makedirs("reports", exist_ok=True)

    report = {
        "status": "FAILED" if findings else "PASSED",
        "total_findings": len(findings),
        "findings": findings
    }

    with open("reports/security_report.json", "w") as file:

        json.dump(report, file, indent=4)

    print("\n📄 Security report generated:")
    print("reports/security_report.json")


def main():

    print("=" * 55)
    print("          SECRET SHIELD SECURITY SCANNER")
    print("=" * 55)

    results = scan_project()

    if results:

        print("\n⚠️ POTENTIAL SECRETS DETECTED\n")

        for finding in results:

            print(f"File: {finding['file']}")
            print(f"Line: {finding['line']}")
            print(f"Type: {finding['type']}")
            print(f"Severity: {finding['severity']}")

            print("-" * 40)

        generate_report(results)

        print("\n❌ SECURITY SCAN FAILED")

        return 1

    else:

        print("\n✅ No potential secrets detected")

        generate_report(results)

        print("✅ SECURITY SCAN PASSED")

        return 0


if __name__ == "__main__":

    exit(main())