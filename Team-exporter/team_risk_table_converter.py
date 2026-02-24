#!/usr/bin/env python3
"""
Team Risk Assessment Table Converter

Converts the Team-list.json file into a comprehensive risk assessment table
with all requested risk metrics and calculations.
"""

import json
import csv
from datetime import datetime
from pathlib import Path

def load_json_data(file_path):
    """Load the JSON data from file"""
    with open(file_path, 'r') as f:
        return json.load(f)

def format_risk_magnitude(value):
    """Format risk magnitude with 'k' suffix for thousands"""
    if value >= 1000:
        return f"{value/1000:.1f}k"
    return str(value)

def calculate_time_periods(from_date_str, to_date_str):
    """Calculate days, weeks, and months between two dates"""
    try:
        from_date = datetime.strptime(from_date_str, '%Y-%m-%d')
        to_date = datetime.strptime(to_date_str, '%Y-%m-%d')
        
        # Calculate difference
        delta = to_date - from_date
        days = delta.days
        weeks = round(days / 7, 1)
        months = round(days / 30.4, 2)
        
        return days, weeks, months
    except:
        # Default values if date parsing fails
        return 7, 1.0, 0.23

def convert_to_risk_table(json_data):
    """Convert JSON data to risk assessment table"""
    
    table_data = []
    teams = json_data.get('content', [])
    
    for team in teams:
        # Basic information
        team_name = team.get('teamName', '')
        total_risk = team.get('totalRisk', 0)
        avg_risk = team.get('avgRisk', 0)
        
        # Date information
        date = team.get('date', '')
        from_date = team.get('fromDate', '')
        data_from_to = f"{from_date} to {date}"
        
        # Calculate time periods
        days, weeks, months = calculate_time_periods(from_date, date)
        
        # Counts
        app_count = team.get('appCount', 0)
        component_count = team.get('componentCount', 0)
        asset_count = team.get('assetCount', 0)
        
        # Vulnerability data
        vulns = team.get('vulns', {})
        open_vulns = vulns.get('open', 0)
        closed_vulns = vulns.get('closed', 0)
        critical = vulns.get('critical', 0)
        high = vulns.get('high', 0)
        medium = vulns.get('medium', 0)
        low = vulns.get('low', 0)
        none_risk = vulns.get('none', 0)
        
        # Delta data
        delta = team.get('delta', {})
        delta_open = delta.get('open', 0)
        delta_closed = delta.get('closed', 0)
        total_risk_delta = delta.get('totalRisk', 0)
        
        # Create table row
        row = {
            'team_name': team_name,
            'risk': total_risk,
            'total_risk_magnitude': format_risk_magnitude(total_risk),
            'delta_calculated': total_risk_delta,
            'data_from_to': data_from_to,
            'days': days,
            'weeks': weeks,
            'months': months,
            'app_count': app_count,
            'component_count': component_count,
            'asset_count': asset_count,
            'delta_open': delta_open,
            'delta_closed': delta_closed,
            'total_risk_delta': total_risk_delta,
            'open': open_vulns,
            'closed': closed_vulns,
            'critical': critical,
            'high': high,
            'medium': medium,
            'low': low,
            'none': none_risk,
            'average_risk': avg_risk
        }
        
        table_data.append(row)
    
    return table_data

def save_to_csv(data, output_file):
    """Save data to CSV file"""
    
    fieldnames = [
        'team_name',
        'risk', 
        'total_risk_magnitude',
        'delta_calculated',
        'data_from_to',
        'days',
        'weeks', 
        'months',
        'app_count',
        'component_count',
        'asset_count',
        'delta_open',
        'delta_closed', 
        'total_risk_delta',
        'open',
        'closed',
        'critical',
        'high',
        'medium',
        'low', 
        'none',
        'average_risk'
    ]
    
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(data)

def print_summary_table(data):
    """Print a formatted summary table to console"""
    
    print("\n" + "="*140)
    print("TEAM RISK ASSESSMENT SUMMARY TABLE")
    print("="*140)
    
    # Header
    header = (f"{'Team':<15} {'Risk':<8} {'Magnitude':<10} {'Delta':<8} {'Period':<6} "
              f"{'Apps':<5} {'Components':<11} {'Assets':<7} {'Open':<6} {'Closed':<7} "
              f"{'Crit':<5} {'High':<5} {'Med':<5} {'Low':<5} {'None':<5} {'AvgRisk':<8}")
    print(header)
    print("-" * 140)
    
    # Data rows
    for row in data:
        line = (f"{row['team_name']:<15} "
                f"{row['risk']:<8} "
                f"{row['total_risk_magnitude']:<10} "
                f"{row['delta_calculated']:<8} "
                f"{row['days']}d{'':<3} "
                f"{row['app_count']:<5} "
                f"{row['component_count']:<11} "
                f"{row['asset_count']:<7} "
                f"{row['open']:<6} "
                f"{row['closed']:<7} "
                f"{row['critical']:<5} "
                f"{row['high']:<5} "
                f"{row['medium']:<5} "
                f"{row['low']:<5} "
                f"{row['none']:<5} "
                f"{row['average_risk']:<8}")
        print(line)
    
    print("-" * 140)
    
    # Totals
    total_risk = sum(row['risk'] for row in data)
    total_apps = sum(row['app_count'] for row in data)
    total_components = sum(row['component_count'] for row in data)
    total_assets = sum(row['asset_count'] for row in data)
    total_open = sum(row['open'] for row in data)
    total_closed = sum(row['closed'] for row in data)
    total_critical = sum(row['critical'] for row in data)
    total_high = sum(row['high'] for row in data)
    total_medium = sum(row['medium'] for row in data)
    total_low = sum(row['low'] for row in data)
    total_none = sum(row['none'] for row in data)
    avg_risk = round(sum(row['average_risk'] for row in data) / len(data), 1) if data else 0
    
    totals_line = (f"{'TOTALS':<15} "
                   f"{total_risk:<8} "
                   f"{format_risk_magnitude(total_risk):<10} "
                   f"{'':<8} "
                   f"{'':<6} "
                   f"{total_apps:<5} "
                   f"{total_components:<11} "
                   f"{total_assets:<7} "
                   f"{total_open:<6} "
                   f"{total_closed:<7} "
                   f"{total_critical:<5} "
                   f"{total_high:<5} "
                   f"{total_medium:<5} "
                   f"{total_low:<5} "
                   f"{total_none:<5} "
                   f"{avg_risk:<8}")
    print(totals_line)
    print("="*140)

def print_detailed_analysis(data):
    """Print detailed risk analysis"""
    
    print("\n" + "="*80)
    print("DETAILED RISK ANALYSIS")
    print("="*80)
    
    # Sort teams by total risk (descending)
    sorted_teams = sorted(data, key=lambda x: x['risk'], reverse=True)
    
    print(f"\n🔥 TOP 10 HIGHEST RISK TEAMS:")
    print("-" * 50)
    for i, team in enumerate(sorted_teams[:10], 1):
        print(f"{i:2d}. {team['team_name']:<15} - {team['total_risk_magnitude']:<8} "
              f"(Δ {team['delta_calculated']:+d})")
    
    # Teams with highest risk increase
    risk_increases = [team for team in data if team['delta_calculated'] > 0]
    risk_increases.sort(key=lambda x: x['delta_calculated'], reverse=True)
    
    print(f"\n📈 TOP 5 TEAMS WITH HIGHEST RISK INCREASE:")
    print("-" * 50)
    for i, team in enumerate(risk_increases[:5], 1):
        print(f"{i}. {team['team_name']:<15} - +{team['delta_calculated']:,} risk increase")
    
    # Teams with highest risk decrease
    risk_decreases = [team for team in data if team['delta_calculated'] < 0]
    risk_decreases.sort(key=lambda x: x['delta_calculated'])
    
    print(f"\n📉 TOP 5 TEAMS WITH HIGHEST RISK DECREASE:")
    print("-" * 50)
    for i, team in enumerate(risk_decreases[:5], 1):
        print(f"{i}. {team['team_name']:<15} - {team['delta_calculated']:,} risk decrease")
    
    # Critical vulnerabilities
    critical_teams = [team for team in data if team['critical'] > 0]
    critical_teams.sort(key=lambda x: x['critical'], reverse=True)
    
    print(f"\n🚨 TEAMS WITH CRITICAL VULNERABILITIES:")
    print("-" * 50)
    for team in critical_teams:
        print(f"• {team['team_name']:<15} - {team['critical']} critical vulnerabilities")
    
    if not critical_teams:
        print("✅ No teams have critical vulnerabilities!")

def main():
    """Main execution function"""
    
    # File paths
    input_file = Path("Team-list.json")
    output_file = Path("team_risk_assessment_table.csv")
    
    # Check if input file exists
    if not input_file.exists():
        print(f"Error: Input file {input_file} not found!")
        return
    
    try:
        # Load and process data
        print("Loading JSON data...")
        json_data = load_json_data(input_file)
        
        print("Converting to risk assessment table...")
        table_data = convert_to_risk_table(json_data)
        
        # Save to CSV
        print(f"Saving to {output_file}...")
        save_to_csv(table_data, output_file)
        
        # Print summary
        print_summary_table(table_data)
        
        # Print detailed analysis
        print_detailed_analysis(table_data)
        
        print(f"\n✅ Successfully converted {len(table_data)} teams to risk assessment table")
        print(f"📄 Output saved to: {output_file}")
        
    except Exception as e:
        print(f"❌ Error processing data: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main() 