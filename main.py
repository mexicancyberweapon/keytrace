import sys
from scanner import scan_file


if len(sys.argv) != 2:
    print("Usage: python3 main.py <python file>")
    sys.exit(1)


scanner = scan_file(sys.argv[1])

print("\nKeytrace")
print("=" * 40)

if not scanner.findings:
    print("No secrets reached sensitive sinks.")
else:
    for finding in scanner.findings:
        print()
        print("Potential Secret Found")
        print("----------------------")
        print("Value:", finding["candidate"])
        print("Source:", finding["source"])
        print("Sink:", finding["sink"])
        print("Line:", finding["line"])

print("\nFlows")
print("-----")

for source, destinations in scanner.flows.items():
    for destination in destinations:
        print(f"{source} -> {destination}")