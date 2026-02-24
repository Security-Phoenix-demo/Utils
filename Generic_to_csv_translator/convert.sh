#!/bin/bash
#
# CSV Vulnerability Converter - Convenience Script
# Converts vulnerability export CSV to Phoenix Security import formats
#

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default source file
DEFAULT_SOURCE="source/VulnerabilityListingExport.csv"

# Function to display usage
usage() {
    echo -e "${BLUE}CSV Vulnerability Converter${NC}"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -f, --format FORMAT    Target format (required): infra, cloud, web, software"
    echo "  -s, --source FILE      Source CSV file (default: $DEFAULT_SOURCE)"
    echo "  -o, --output FILE      Output file path (optional, auto-generated if not provided)"
    echo "  -n, --scanner NAME     Scanner name (e.g., rapid7, tenable, qualys)"
    echo "  -h, --help             Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 --format infra"
    echo "  $0 --format cloud --source my_vulns.csv"
    echo "  $0 --format infra --scanner rapid7"
    echo "  $0 --format web --output custom_output.csv"
    echo ""
    exit 1
}

# Parse command line arguments
FORMAT=""
SOURCE="$DEFAULT_SOURCE"
OUTPUT=""
SCANNER=""

while [[ $# -gt 0 ]]; do
    case $1 in
        -f|--format)
            FORMAT="$2"
            shift 2
            ;;
        -s|--source)
            SOURCE="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT="$2"
            shift 2
            ;;
        -n|--scanner)
            SCANNER="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo -e "${RED}Error: Unknown option $1${NC}"
            usage
            ;;
    esac
done

# Check if format is provided
if [ -z "$FORMAT" ]; then
    echo -e "${RED}Error: Format is required${NC}"
    usage
fi

# Validate format
if [[ ! "$FORMAT" =~ ^(infra|cloud|web|software)$ ]]; then
    echo -e "${RED}Error: Invalid format '$FORMAT'${NC}"
    echo -e "Valid formats: infra, cloud, web, software"
    exit 1
fi

# Check if source file exists
if [ ! -f "$SOURCE" ]; then
    echo -e "${RED}Error: Source file '$SOURCE' not found${NC}"
    exit 1
fi

# Build command
CMD="python3 csv_converter.py \"$SOURCE\" --format $FORMAT"
if [ -n "$OUTPUT" ]; then
    CMD="$CMD --output \"$OUTPUT\""
fi
if [ -n "$SCANNER" ]; then
    CMD="$CMD --scanner \"$SCANNER\""
fi

# Display what we're doing
echo -e "${BLUE}╔════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   CSV Vulnerability Converter                  ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${YELLOW}Configuration:${NC}"
echo -e "  Source:  ${GREEN}$SOURCE${NC}"
echo -e "  Format:  ${GREEN}$FORMAT${NC}"
if [ -n "$SCANNER" ]; then
    echo -e "  Scanner: ${GREEN}$SCANNER${NC}"
fi
if [ -n "$OUTPUT" ]; then
    echo -e "  Output:  ${GREEN}$OUTPUT${NC}"
fi
echo ""

# Run the conversion
eval $CMD
EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
    echo ""
    echo -e "${GREEN}✓ Conversion completed successfully!${NC}"
    echo ""
    echo -e "${YELLOW}Next steps:${NC}"
    echo "  1. Open the generated CSV file in the results/ directory"
    echo "  2. Fill in the asset identification fields for each vulnerability"
    echo "  3. Review and adjust severity values if needed"
    echo "  4. Import the file into Phoenix Security"
else
    echo ""
    echo -e "${RED}✗ Conversion failed!${NC}"
    exit $EXIT_CODE
fi

