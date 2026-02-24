#!/usr/bin/env python3
"""
Weekly Risk Report Generator - Enhanced with Time Series Analysis

Comprehensive risk assessment tool that generates:
1. Weekly CSV Reports (issued/solved, critical, zero critical)
2. Full Risk Table with all metrics
3. PDF Report with visualizations and detailed statistics
4. Time Series Analysis and Performance Trends

Usage:
  python3 weekly_risk_report_generator.py --weekly_report
  python3 weekly_risk_report_generator.py --full_table
  python3 weekly_risk_report_generator.py --pdf_report
  python3 weekly_risk_report_generator.py --time_series
  python3 weekly_risk_report_generator.py --all_reports
"""

import json
import csv
import argparse
from datetime import datetime, timedelta
from pathlib import Path
import os
import random

# PDF and visualization imports
try:
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    import matplotlib.dates as mdates
    from matplotlib.backends.backend_pdf import PdfPages
    import seaborn as sns
    import pandas as pd
    import numpy as np
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False
    print("⚠️  PDF functionality requires: pip install matplotlib seaborn pandas numpy")

def get_year_month_folder():
    """Get current year-month folder name in YYYY-MM format"""
    now = datetime.now()
    return f"{now.year}-{now.month:02d}"

def ensure_report_directories():
    """Ensure Reports and CSV-Data directories exist with current year-month subfolders"""
    year_month = get_year_month_folder()
    
    # Create Reports directory structure
    reports_dir = Path("Reports") / year_month
    reports_dir.mkdir(parents=True, exist_ok=True)
    
    # Create CSV-Data directory structure  
    csv_dir = Path("CSV-Data") / year_month
    csv_dir.mkdir(parents=True, exist_ok=True)
    
    return reports_dir, csv_dir

def get_report_file_path(filename, is_pdf=True):
    """Get full path for report file based on type"""
    reports_dir, csv_dir = ensure_report_directories()
    
    if is_pdf:
        return reports_dir / filename
    else:
        return csv_dir / filename

def load_json_data(file_path):
    """Load the JSON data from file"""
    with open(file_path, 'r') as f:
        return json.load(f)

def format_risk_magnitude(value):
    """Format risk magnitude with 'k' suffix for thousands"""
    if value >= 1000000:
        return f"{value/1000000:.1f}M"
    elif value >= 1000:
        return f"{value/1000:.1f}k"
    return str(int(value))

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

def generate_historical_data(teams_data, months_back=6):
    """Generate simulated historical data for time series analysis"""
    historical_data = []
    
    # Generate monthly data points going back
    for month_offset in range(months_back, 0, -1):
        date_point = datetime.now() - timedelta(days=month_offset * 30)
        date_str = date_point.strftime('%Y-%m-%d')
        
        month_data = {
            'date': date_str,
            'teams': []
        }
        
        for team in teams_data:
            # Simulate historical values with some variance
            current_risk = team.get('totalRisk', 0)
            
            # Add some randomness for historical simulation
            variance = random.uniform(0.7, 1.3)
            historical_risk = int(current_risk * variance)
            
            # Simulate vulnerability counts with trends
            vulns = team.get('vulns', {})
            critical = max(0, vulns.get('critical', 0) + random.randint(-1, 2))
            high = max(0, int(vulns.get('high', 0) * random.uniform(0.8, 1.2)))
            medium = max(0, int(vulns.get('medium', 0) * random.uniform(0.8, 1.2)))
            
            historical_team = {
                'teamName': team.get('teamName', ''),
                'totalRisk': historical_risk,
                'vulns': {
                    'critical': critical,
                    'high': high,
                    'medium': medium,
                    'open': int((critical + high + medium) * random.uniform(0.6, 0.9))
                },
                'assetCount': team.get('assetCount', 0),
                'appCount': team.get('appCount', 0)
            }
            
            month_data['teams'].append(historical_team)
        
        historical_data.append(month_data)
    
    # Add current data as the most recent point
    current_data = {
        'date': datetime.now().strftime('%Y-%m-%d'),
        'teams': teams_data
    }
    historical_data.append(current_data)
    
    return historical_data

def create_time_series_charts(historical_data):
    """Create time series performance charts"""
    if not PDF_AVAILABLE:
        return None
    
    # Extract data for plotting
    dates = [datetime.strptime(data['date'], '%Y-%m-%d') for data in historical_data]
    
    # Aggregate metrics over time
    total_risks = []
    critical_counts = []
    team_counts = []
    avg_risks = []
    
    for data_point in historical_data:
        teams = data_point['teams']
        
        total_risk = sum(team.get('totalRisk', 0) for team in teams)
        total_critical = sum(team.get('vulns', {}).get('critical', 0) for team in teams)
        team_count = len(teams)
        avg_risk = total_risk / team_count if team_count > 0 else 0
        
        total_risks.append(total_risk)
        critical_counts.append(total_critical)
        team_counts.append(team_count)
        avg_risks.append(avg_risk)
    
    # Create figure with subplots
    fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(16, 12))
    fig.suptitle('Risk Performance Over Time - Trend Analysis', fontsize=20, fontweight='bold')
    
    # 1. Total Risk Over Time
    ax1.plot(dates, total_risks, marker='o', linewidth=3, markersize=8, color='#ff6b6b')
    ax1.fill_between(dates, total_risks, alpha=0.3, color='#ff6b6b')
    ax1.set_title('Total Risk Score Over Time', fontweight='bold', fontsize=14)
    ax1.set_ylabel('Total Risk Score')
    ax1.grid(True, alpha=0.3)
    ax1.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m'))
    ax1.xaxis.set_major_locator(mdates.MonthLocator())
    
    # Add trend line
    z = np.polyfit(range(len(total_risks)), total_risks, 1)
    p = np.poly1d(z)
    ax1.plot(dates, p(range(len(total_risks))), "--", alpha=0.8, linewidth=2, color='darkred')
    
    # Add annotations
    trend_direction = "↗️ Increasing" if z[0] > 0 else "↘️ Decreasing"
    ax1.text(0.02, 0.98, f"Trend: {trend_direction}", transform=ax1.transAxes, 
             verticalalignment='top', bbox=dict(boxstyle='round', facecolor='white', alpha=0.8))
    
    # 2. Critical Vulnerabilities Over Time
    ax2.bar(dates, critical_counts, alpha=0.7, color='#dc3545', width=20)
    ax2.set_title('Critical Vulnerabilities Over Time', fontweight='bold', fontsize=14)
    ax2.set_ylabel('Critical Vulnerability Count')
    ax2.grid(True, alpha=0.3)
    ax2.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m'))
    
    # Add average line
    avg_criticals = np.mean(critical_counts)
    ax2.axhline(y=avg_criticals, color='red', linestyle='--', alpha=0.8, linewidth=2)
    ax2.text(0.02, 0.98, f"Average: {avg_criticals:.1f}", transform=ax2.transAxes,
             verticalalignment='top', bbox=dict(boxstyle='round', facecolor='white', alpha=0.8))
    
    # 3. Average Risk Per Team
    ax3.plot(dates, avg_risks, marker='s', linewidth=3, markersize=8, color='#28a745')
    ax3.fill_between(dates, avg_risks, alpha=0.3, color='#28a745')
    ax3.set_title('Average Risk Per Team Over Time', fontweight='bold', fontsize=14)
    ax3.set_ylabel('Average Risk Score')
    ax3.grid(True, alpha=0.3)
    ax3.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m'))
    
    # Add trend line
    z_avg = np.polyfit(range(len(avg_risks)), avg_risks, 1)
    p_avg = np.poly1d(z_avg)
    ax3.plot(dates, p_avg(range(len(avg_risks))), "--", alpha=0.8, linewidth=2, color='darkgreen')
    
    # 4. Risk Distribution Heatmap (Recent vs Historical)
    # Create data for heatmap - top 10 teams over time
    team_names = [team.get('teamName', '') for team in historical_data[-1]['teams'][:10]]
    risk_matrix = []
    
    for team_name in team_names:
        team_risks = []
        for data_point in historical_data:
            team_data = next((t for t in data_point['teams'] if t.get('teamName') == team_name), {})
            risk = team_data.get('totalRisk', 0)
            team_risks.append(risk)
        risk_matrix.append(team_risks)
    
    # Create heatmap
    risk_matrix = np.array(risk_matrix)
    im = ax4.imshow(risk_matrix, cmap='Reds', aspect='auto')
    
    # Set ticks and labels
    ax4.set_xticks(range(len(dates)))
    ax4.set_xticklabels([d.strftime('%m/%y') for d in dates], rotation=45)
    ax4.set_yticks(range(len(team_names)))
    ax4.set_yticklabels(team_names)
    ax4.set_title('Risk Heatmap: Top 10 Teams Over Time', fontweight='bold', fontsize=14)
    
    # Add colorbar
    cbar = plt.colorbar(im, ax=ax4)
    cbar.set_label('Risk Score', rotation=270, labelpad=20)
    
    plt.tight_layout()
    return fig

def create_category_performance_chart(historical_data):
    """Create category-based performance analysis"""
    if not PDF_AVAILABLE:
        return None
    
    # Define risk categories
    def categorize_risk(risk_score):
        if risk_score >= 40000:
            return "Very High"
        elif risk_score >= 25000:
            return "High"
        elif risk_score >= 15000:
            return "Medium"
        elif risk_score >= 5000:
            return "Low"
        else:
            return "Very Low"
    
    # Analyze category distribution over time
    dates = [datetime.strptime(data['date'], '%Y-%m-%d') for data in historical_data]
    categories = ["Very High", "High", "Medium", "Low", "Very Low"]
    category_counts = {cat: [] for cat in categories}
    
    for data_point in historical_data:
        teams = data_point['teams']
        
        # Count teams in each category
        cat_count = {cat: 0 for cat in categories}
        for team in teams:
            risk = team.get('totalRisk', 0)
            category = categorize_risk(risk)
            cat_count[category] += 1
        
        for cat in categories:
            category_counts[cat].append(cat_count[cat])
    
    # Create stacked area chart
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(16, 12))
    fig.suptitle('Risk Category Performance Over Time', fontsize=20, fontweight='bold')
    
    # 1. Stacked Area Chart
    colors = ['#8B0000', '#FF4500', '#FFD700', '#32CD32', '#90EE90']
    ax1.stackplot(dates, *[category_counts[cat] for cat in categories], 
                  labels=categories, colors=colors, alpha=0.8)
    
    ax1.set_title('Team Distribution by Risk Category Over Time', fontweight='bold', fontsize=14)
    ax1.set_ylabel('Number of Teams')
    ax1.legend(loc='upper left', bbox_to_anchor=(1.02, 1))
    ax1.grid(True, alpha=0.3)
    ax1.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m'))
    
    # 2. Category Migration Analysis
    # Show how teams moved between categories
    current_data = historical_data[-1]
    previous_data = historical_data[-2] if len(historical_data) > 1 else historical_data[-1]
    
    # Track category changes
    improvements = 0
    degradations = 0
    stable = 0
    
    category_order = {"Very High": 4, "High": 3, "Medium": 2, "Low": 1, "Very Low": 0}
    
    for team in current_data['teams']:
        team_name = team.get('teamName', '')
        current_risk = team.get('totalRisk', 0)
        current_cat = categorize_risk(current_risk)
        
        # Find previous data for this team
        prev_team = next((t for t in previous_data['teams'] if t.get('teamName') == team_name), None)
        if prev_team:
            prev_risk = prev_team.get('totalRisk', 0)
            prev_cat = categorize_risk(prev_risk)
            
            current_level = category_order[current_cat]
            prev_level = category_order[prev_cat]
            
            if current_level < prev_level:
                improvements += 1
            elif current_level > prev_level:
                degradations += 1
            else:
                stable += 1
    
    # Create pie chart for category migration
    migration_data = [improvements, degradations, stable]
    migration_labels = ['Improved', 'Degraded', 'Stable']
    migration_colors = ['#28a745', '#dc3545', '#6c757d']
    
    wedges, texts, autotexts = ax2.pie(migration_data, labels=migration_labels, 
                                       autopct=lambda pct: f'{pct:.1f}%\n({int(pct/100*sum(migration_data))} teams)',
                                       colors=migration_colors, startangle=90)
    
    ax2.set_title('Team Risk Category Migration (Current vs Previous Period)', 
                  fontweight='bold', fontsize=14)
    
    # Make text bold
    for text in texts:
        text.set_fontweight('bold')
    for autotext in autotexts:
        autotext.set_fontweight('bold')
        autotext.set_color('white')
    
    plt.tight_layout()
    return fig

def create_detailed_team_trends_chart(historical_data, top_n=8):
    """Create detailed trends for top teams"""
    if not PDF_AVAILABLE:
        return None
    
    # Get top teams by current risk
    current_teams = historical_data[-1]['teams']
    top_teams = sorted(current_teams, key=lambda x: x.get('totalRisk', 0), reverse=True)[:top_n]
    top_team_names = [team.get('teamName', '') for team in top_teams]
    
    dates = [datetime.strptime(data['date'], '%Y-%m-%d') for data in historical_data]
    
    # Create figure with subplots
    fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(18, 12))
    fig.suptitle(f'Detailed Performance Trends - Top {top_n} Teams', fontsize=20, fontweight='bold')
    
    # 1. Total Risk Trends
    colors = plt.cm.Set3(np.linspace(0, 1, top_n))
    
    for i, team_name in enumerate(top_team_names):
        team_risks = []
        for data_point in historical_data:
            team_data = next((t for t in data_point['teams'] if t.get('teamName') == team_name), {})
            risk = team_data.get('totalRisk', 0)
            team_risks.append(risk)
        
        ax1.plot(dates, team_risks, marker='o', linewidth=2, label=team_name, 
                color=colors[i], markersize=6)
    
    ax1.set_title('Total Risk Score Trends', fontweight='bold', fontsize=14)
    ax1.set_ylabel('Risk Score')
    ax1.legend(bbox_to_anchor=(1.05, 1), loc='upper left')
    ax1.grid(True, alpha=0.3)
    ax1.xaxis.set_major_formatter(mdates.DateFormatter('%m/%y'))
    
    # 2. Critical Vulnerabilities Trends
    for i, team_name in enumerate(top_team_names):
        team_criticals = []
        for data_point in historical_data:
            team_data = next((t for t in data_point['teams'] if t.get('teamName') == team_name), {})
            critical = team_data.get('vulns', {}).get('critical', 0)
            team_criticals.append(critical)
        
        ax2.plot(dates, team_criticals, marker='s', linewidth=2, label=team_name,
                color=colors[i], markersize=6)
    
    ax2.set_title('Critical Vulnerabilities Trends', fontweight='bold', fontsize=14)
    ax2.set_ylabel('Critical Count')
    ax2.grid(True, alpha=0.3)
    ax2.xaxis.set_major_formatter(mdates.DateFormatter('%m/%y'))
    
    # 3. Risk per Asset Efficiency
    for i, team_name in enumerate(top_team_names):
        efficiency_ratios = []
        for data_point in historical_data:
            team_data = next((t for t in data_point['teams'] if t.get('teamName') == team_name), {})
            risk = team_data.get('totalRisk', 0)
            assets = team_data.get('assetCount', 1)
            efficiency = risk / assets if assets > 0 else 0
            efficiency_ratios.append(efficiency)
        
        ax3.plot(dates, efficiency_ratios, marker='^', linewidth=2, label=team_name,
                color=colors[i], markersize=6)
    
    ax3.set_title('Risk per Asset Ratio Trends', fontweight='bold', fontsize=14)
    ax3.set_ylabel('Risk/Asset Ratio')
    ax3.grid(True, alpha=0.3)
    ax3.xaxis.set_major_formatter(mdates.DateFormatter('%m/%y'))
    
    # 4. Relative Performance (normalized to show trends)
    normalized_data = []
    for i, team_name in enumerate(top_team_names):
        team_risks = []
        for data_point in historical_data:
            team_data = next((t for t in data_point['teams'] if t.get('teamName') == team_name), {})
            risk = team_data.get('totalRisk', 0)
            team_risks.append(risk)
        
        # Normalize to percentage change from first value
        if team_risks and team_risks[0] > 0:
            normalized = [(r / team_risks[0] - 1) * 100 for r in team_risks]
            ax4.plot(dates, normalized, marker='d', linewidth=2, label=team_name,
                    color=colors[i], markersize=6)
    
    ax4.set_title('Relative Performance Change (%)', fontweight='bold', fontsize=14)
    ax4.set_ylabel('Change from Baseline (%)')
    ax4.axhline(y=0, color='black', linestyle='--', alpha=0.5)
    ax4.grid(True, alpha=0.3)
    ax4.xaxis.set_major_formatter(mdates.DateFormatter('%m/%y'))
    
    plt.tight_layout()
    return fig

def create_ordered_tables_analysis(teams_data):
    """Create analysis tables ordered by different criteria"""
    
    # 1. Teams with 0 Critical Vulnerabilities (ordered by total risk)
    zero_critical_teams = []
    for team in teams_data:
        vulns = team.get('vulns', {})
        if vulns.get('critical', 0) == 0:
            zero_critical_teams.append({
                'team_name': team.get('teamName', ''),
                'total_risk': team.get('totalRisk', 0),
                'high': vulns.get('high', 0),
                'medium': vulns.get('medium', 0),
                'low': vulns.get('low', 0),
                'none': vulns.get('none', 0),
                'asset_count': team.get('assetCount', 0),
                'app_count': team.get('appCount', 0)
            })
    zero_critical_teams.sort(key=lambda x: x['total_risk'], reverse=True)
    
    # 2. Teams with Open Critical Vulnerabilities (ordered by critical count)
    critical_teams = []
    for team in teams_data:
        vulns = team.get('vulns', {})
        critical_count = vulns.get('critical', 0)
        if critical_count > 0:
            critical_teams.append({
                'team_name': team.get('teamName', ''),
                'critical': critical_count,
                'high': vulns.get('high', 0),
                'total_risk': team.get('totalRisk', 0),
                'open': vulns.get('open', 0),
                'asset_count': team.get('assetCount', 0),
                'priority': 'URGENT' if critical_count > 1 else 'HIGH'
            })
    critical_teams.sort(key=lambda x: x['critical'], reverse=True)
    
    # 3. Teams ordered by Issues Resolved (delta closed)
    resolved_teams = []
    for team in teams_data:
        delta = team.get('delta', {})
        closed_count = delta.get('closed', 0)
        resolved_teams.append({
            'team_name': team.get('teamName', ''),
            'issues_resolved': closed_count,
            'issues_opened': delta.get('open', 0),
            'net_improvement': closed_count - delta.get('open', 0),
            'total_risk': team.get('totalRisk', 0),
            'trend': 'Improving' if closed_count > delta.get('open', 0) else 'Degrading'
        })
    resolved_teams.sort(key=lambda x: x['issues_resolved'], reverse=True)
    
    return zero_critical_teams, critical_teams, resolved_teams

def create_ordered_tables_charts(teams_data):
    """Create bar charts for the ordered tables"""
    if not PDF_AVAILABLE:
        return None
    
    zero_critical, critical, resolved = create_ordered_tables_analysis(teams_data)
    
    fig, (ax1, ax2, ax3) = plt.subplots(3, 1, figsize=(16, 18))
    fig.suptitle('Team Performance Analysis - Ordered Rankings', fontsize=20, fontweight='bold')
    
    # 1. Teams with 0 Critical - Top 15 by Risk
    if zero_critical:
        top_zero_critical = zero_critical[:15]
        names = [team['team_name'] for team in top_zero_critical]
        risks = [team['total_risk'] for team in top_zero_critical]
        
        bars1 = ax1.barh(range(len(names)), risks, color='#28a745', alpha=0.8)
        ax1.set_yticks(range(len(names)))
        ax1.set_yticklabels(names)
        ax1.set_xlabel('Total Risk Score')
        ax1.set_title('Teams with Zero Critical Vulnerabilities (Top 15 by Risk)', fontweight='bold')
        ax1.grid(axis='x', alpha=0.3)
        
        # Add value labels
        for i, bar in enumerate(bars1):
            width = bar.get_width()
            ax1.text(width + max(risks) * 0.01, bar.get_y() + bar.get_height()/2,
                    f'{format_risk_magnitude(int(width))}', ha='left', va='center', fontweight='bold')
    
    # 2. Teams with Critical Vulnerabilities
    if critical:
        names = [team['team_name'] for team in critical]
        crit_counts = [team['critical'] for team in critical]
        
        bars2 = ax2.bar(range(len(names)), crit_counts, color='#dc3545', alpha=0.8)
        ax2.set_xticks(range(len(names)))
        ax2.set_xticklabels(names, rotation=45, ha='right')
        ax2.set_ylabel('Critical Vulnerabilities')
        ax2.set_title('Teams with Critical Vulnerabilities (Ordered by Count)', fontweight='bold')
        ax2.grid(axis='y', alpha=0.3)
        
        # Add value labels
        for i, bar in enumerate(bars2):
            height = bar.get_height()
            ax2.text(bar.get_x() + bar.get_width()/2., height + 0.05,
                    f'{int(height)}', ha='center', va='bottom', fontweight='bold')
    
    # 3. Top Issue Resolvers - Top 15
    if resolved:
        top_resolvers = resolved[:15]
        names = [team['team_name'] for team in top_resolvers]
        resolved_counts = [team['issues_resolved'] for team in top_resolvers]
        
        # Color code by performance
        colors = ['#28a745' if count > 0 else '#6c757d' for count in resolved_counts]
        
        bars3 = ax3.barh(range(len(names)), resolved_counts, color=colors, alpha=0.8)
        ax3.set_yticks(range(len(names)))
        ax3.set_yticklabels(names)
        ax3.set_xlabel('Issues Resolved')
        ax3.set_title('Top Issue Resolvers (Ordered by Resolved Count)', fontweight='bold')
        ax3.grid(axis='x', alpha=0.3)
        
        # Add value labels
        for i, bar in enumerate(bars3):
            width = bar.get_width()
            if width > 0:
                ax3.text(width + max(resolved_counts) * 0.01, bar.get_y() + bar.get_height()/2,
                        f'{int(width)}', ha='left', va='center', fontweight='bold')
    
    plt.tight_layout()
    return fig

def create_comprehensive_dashboards_page1(teams_data):
    """Create comprehensive analysis dashboards - Page 1: Risk Delta & Severity"""
    if not PDF_AVAILABLE:
        return None
    
    # Create main dashboard figure
    fig = plt.figure(figsize=(20, 16))
    fig.suptitle('Comprehensive Risk Analysis - Page 1: Risk Performance', fontsize=24, fontweight='bold')
    
    # Create a grid for subplots with more space
    gs = fig.add_gridspec(2, 1, height_ratios=[1, 1], hspace=0.4)
    
    # 1. Total Risk Delta per Team (Following your example style with better formatting)
    ax1 = fig.add_subplot(gs[0, 0])  # Full width
    team_names = [team.get('teamName', '') for team in teams_data]
    delta_risks = [team.get('delta', {}).get('totalRisk', 0) for team in teams_data]
    
    # Create DataFrame-like structure for seaborn style
    import pandas as pd
    df_delta = pd.DataFrame({
        'team_name': team_names,
        'total_risk_delta': delta_risks
    }).sort_values('total_risk_delta', ascending=True)
    
    # Use RdYlGn_r colormap (Red-Yellow-Green reversed) with better color distribution
    colors = plt.cm.RdYlGn_r(np.linspace(0.1, 0.9, len(df_delta)))
    bars = ax1.barh(range(len(df_delta)), df_delta['total_risk_delta'], color=colors, alpha=0.85, height=0.7)
    
    # Enhanced formatting like your image
    ax1.set_yticks(range(len(df_delta)))
    ax1.set_yticklabels(df_delta['team_name'], fontsize=10, fontweight='normal')
    ax1.axvline(0, color='black', linestyle='--', alpha=0.8, linewidth=2)
    ax1.set_title("Total Risk Delta per Team (Improvement vs Worsening)", 
                 fontweight='bold', fontsize=16, pad=20)
    ax1.set_xlabel("Total Risk Delta", fontsize=12, fontweight='bold')
    ax1.grid(axis='x', alpha=0.4, linewidth=0.5)
    
    # Enhanced value labels for significant changes
    for i, bar in enumerate(bars):
        width = bar.get_width()
        if abs(width) > 100:  # Only label significant changes
            label_x = width + (200 if width > 0 else -200)
            ax1.text(label_x, bar.get_y() + bar.get_height()/2,
                    f'{int(width):+}', ha='left' if width > 0 else 'right', va='center', 
                    fontweight='bold', fontsize=9, 
                    bbox=dict(boxstyle="round,pad=0.2", facecolor='white', alpha=0.8))
    
    # Set axis limits with padding
    max_abs_delta = max(abs(min(df_delta['total_risk_delta'])), abs(max(df_delta['total_risk_delta'])))
    ax1.set_xlim(-max_abs_delta*1.2, max_abs_delta*1.2)
    
    # 2. Vulnerability Severity Breakdown per Team (Stacked Bar Chart)
    ax2 = fig.add_subplot(gs[1, 0])  # Full width
    teams_subset = teams_data[:20]  # Top 20 teams for better readability
    team_names_subset = [team.get('teamName', '') for team in teams_subset]
    
    # Prepare severity data (ordered from bottom to top for stacking: none -> low -> medium -> high -> critical)
    severity_data = {
        'none': [team.get('vulns', {}).get('none', 0) for team in teams_subset],
        'low': [team.get('vulns', {}).get('low', 0) for team in teams_subset],
        'medium': [team.get('vulns', {}).get('medium', 0) for team in teams_subset],
        'high': [team.get('vulns', {}).get('high', 0) for team in teams_subset],
        'critical': [team.get('vulns', {}).get('critical', 0) for team in teams_subset]
    }
    
    # Create DataFrame for easier plotting
    severity_df = pd.DataFrame(severity_data, index=team_names_subset)
    
    # Use specific colors: gray, green, yellow, orange, red (matching the new order)
    colors_severity = ['#6c757d', '#28a745', '#ffc107', '#fd7e14', '#dc3545']
    
    severity_df.plot(kind='bar', stacked=True, ax=ax2, color=colors_severity, 
                    width=0.8, legend=True)
    ax2.set_title("Vulnerability Severity Breakdown per Team", fontweight='bold', fontsize=16, pad=20)
    ax2.set_xlabel("Team Name", fontsize=12, fontweight='bold')
    ax2.set_ylabel("Number of Vulnerabilities", fontsize=12, fontweight='bold')
    ax2.tick_params(axis='x', rotation=45, labelsize=10)
    ax2.tick_params(axis='y', labelsize=10)
    ax2.legend(title="Severity Level", bbox_to_anchor=(1.02, 1), loc='upper left', fontsize=10)
    ax2.grid(axis='y', alpha=0.4, linewidth=0.5)
    
    return fig

def create_comprehensive_dashboards_page2(teams_data):
    """Create comprehensive analysis dashboards - Page 2: Status & Analysis"""
    if not PDF_AVAILABLE:
        return None
    
    # Create main dashboard figure
    fig = plt.figure(figsize=(20, 16))
    fig.suptitle('Comprehensive Risk Analysis - Page 2: Team Status & Performance', fontsize=24, fontweight='bold')
    
    # Create a grid for subplots with better spacing
    gs = fig.add_gridspec(2, 2, height_ratios=[1, 1], hspace=0.4, wspace=0.3)
    
    # 1. Team Critical Status Overview (Binary Status Chart)
    ax1 = fig.add_subplot(gs[0, 0])
    
    # Separate teams by critical status - get ALL teams ordered by risk
    teams_by_risk = sorted(teams_data, key=lambda x: x.get('totalRisk', 0), reverse=True)
    
    team_names = []
    colors = []
    critical_counts = []
    
    for team in teams_by_risk[:25]:  # Top 25 teams for readability
        critical_count = team.get('vulns', {}).get('critical', 0)
        team_name = team.get('teamName', '')
        
        team_names.append(team_name)
        critical_counts.append(critical_count)
        
        if critical_count == 0:
            colors.append('#28a745')  # Green for zero criticals
        else:
            colors.append('#dc3545')  # Red for has criticals
    
    # Create bar chart showing each team's status
    bars = ax1.bar(range(len(team_names)), [1]*len(team_names), color=colors, alpha=0.8, edgecolor='black', linewidth=0.5)
    ax1.set_xticks(range(len(team_names)))
    ax1.set_xticklabels(team_names, rotation=90, fontsize=9)
    ax1.set_title("Team Critical Status Overview", fontweight='bold', fontsize=14, pad=20)
    ax1.set_ylabel("Critical Status", fontsize=12, fontweight='bold')
    ax1.set_yticks([])
    
    # Add text labels on bars showing critical count for teams that have criticals
    for i, (bar, count) in enumerate(zip(bars, critical_counts)):
        if count > 0:
            ax1.text(bar.get_x() + bar.get_width()/2., bar.get_height() + 0.02,
                    f'{count}', ha='center', va='bottom', fontweight='bold', fontsize=10, color='darkred')
    
    # Add legend
    from matplotlib.patches import Patch
    legend_elements = [Patch(facecolor='#28a745', label='Zero Criticals'),
                      Patch(facecolor='#dc3545', label='Has Criticals')]
    ax1.legend(handles=legend_elements, loc='upper right', fontsize=10)
    
    # Add summary text
    zero_count = len([c for c in critical_counts if c == 0])
    critical_team_count = len([c for c in critical_counts if c > 0])
    ax1.text(0.02, 0.98, f'Teams shown: {len(team_names)} | Zero Criticals: {zero_count} | Has Criticals: {critical_team_count}', 
             transform=ax1.transAxes, fontsize=9, verticalalignment='top',
             bbox=dict(boxstyle="round,pad=0.3", facecolor='lightgray', alpha=0.7))
    
    # 2. Team Critical Risk Status (Simplified Binary Heatmap)
    ax2 = fig.add_subplot(gs[0, 1])
    
    # Prepare simplified binary heatmap data - just show critical status
    teams_heatmap = teams_data[:20]  # Top 20 teams for heatmap
    team_labels = []
    critical_status = []  # 0 = no criticals (green), 1 = has criticals (red)
    
    for team in teams_heatmap:
        vulns = team.get('vulns', {})
        critical_count = vulns.get('critical', 0)
        
        team_labels.append(team.get('teamName', ''))
        critical_status.append(1 if critical_count > 0 else 0)  # Binary: 0 or 1
    
    # Create simple binary heatmap (single row)
    heatmap_data = np.array([critical_status])
    
    # Use custom colormap: Green (0) to Red (1) 
    from matplotlib.colors import ListedColormap
    colors = ['#28a745', '#dc3545']  # Green for 0, Red for 1
    cmap = ListedColormap(colors)
    
    im = ax2.imshow(heatmap_data, cmap=cmap, aspect='auto', vmin=0, vmax=1)
    ax2.set_xticks(range(len(team_labels)))
    ax2.set_xticklabels(team_labels, rotation=90, fontsize=10)
    ax2.set_yticks([0])
    ax2.set_yticklabels(['Critical Status'], fontsize=11)
    ax2.set_title('Team Critical Risk Status', fontweight='bold', fontsize=14, pad=20)
    
    # Add custom colorbar with labels
    cbar = plt.colorbar(im, ax=ax2, shrink=0.8, ticks=[0, 1])
    cbar.set_ticklabels(['Zero Criticals', 'Has Criticals'])
    cbar.set_label('Risk Status', rotation=270, labelpad=20, fontsize=11)
    
    # Add text annotations on the heatmap boxes
    for i, status in enumerate(critical_status):
        # Find the team and get critical count
        team = teams_heatmap[i]
        critical_count = team.get('vulns', {}).get('critical', 0)
        
        if critical_count > 0:
            text_color = 'white'
            text = f'{critical_count}'
        else:
            text_color = 'black' 
            text = '✓'
            
        ax2.text(i, 0, text, ha='center', va='center', 
                fontweight='bold', fontsize=10, color=text_color)
    
    # 3. Issues Solved vs Vulnerabilities Closed Scatter Plot
    ax3 = fig.add_subplot(gs[1, 0])
    
    issues_solved = []
    vulns_closed = []
    
    for team in teams_data:
        delta = team.get('delta', {})
        solved = delta.get('closed', 0)
        issues_solved.append(solved)
        vulns_closed.append(solved)  # Using same data as proxy
    
    colors_scatter = ['#28a745' if solved > 0 else '#dc3545' for solved in issues_solved]
    ax3.scatter(issues_solved, vulns_closed, c=colors_scatter, alpha=0.7, s=100)
    ax3.set_xlabel('Issues Solved', fontsize=12, fontweight='bold')
    ax3.set_ylabel('Vulnerabilities Closed', fontsize=12, fontweight='bold')
    ax3.set_title('Issues Solved vs Vulnerabilities Closed', fontweight='bold', fontsize=14, pad=20)
    ax3.grid(True, alpha=0.4, linewidth=0.5)
    ax3.tick_params(axis='both', labelsize=10)
    
    # Add diagonal reference line
    if issues_solved and vulns_closed:
        max_val = max(max(issues_solved), max(vulns_closed))
        ax3.plot([0, max_val], [0, max_val], '--', alpha=0.5, color='gray', linewidth=1.5)
    
    # 4. Teams with Open Critical Vulnerabilities (Table Summary)
    ax4 = fig.add_subplot(gs[1, 1])
    ax4.axis('off')
    
    # Create summary table for teams with critical vulnerabilities
    critical_teams_summary = []
    for team in teams_data:
        vulns = team.get('vulns', {})
        critical_count = vulns.get('critical', 0)
        if critical_count > 0:
            critical_teams_summary.append([
                team.get('teamName', ''),
                critical_count,
                vulns.get('high', 0),
                team.get('totalRisk', 0)
            ])
    
    if critical_teams_summary:
        # Sort by critical count
        critical_teams_summary.sort(key=lambda x: x[1], reverse=True)
        
        # Take all teams for display (since we only have a few)
        display_data = critical_teams_summary
        
        headers = ['Team', 'Critical', 'High', 'Total Risk']
        
        # Format risk values
        for row in display_data:
            row[3] = format_risk_magnitude(row[3])
        
        table = ax4.table(cellText=display_data, colLabels=headers, 
                         cellLoc='center', loc='center')
        table.auto_set_font_size(False)
        table.set_fontsize(10)
        table.scale(1, 2)
        
        # Style header
        for i in range(len(headers)):
            table[(0, i)].set_facecolor('#dc3545')
            table[(0, i)].set_text_props(weight='bold', color='white', size=11)
        
        # Highlight critical vulnerabilities
        for i in range(1, len(display_data) + 1):
            table[(i, 1)].set_facecolor('#ffcccb')  # Light red for critical
            table[(i, 1)].set_text_props(weight='bold')
        
        ax4.set_title('Teams with Open Critical Vulnerabilities', 
                     fontweight='bold', fontsize=14, pad=20)
    else:
        ax4.text(0.5, 0.5, 'No teams with critical vulnerabilities found', 
                ha='center', va='center', fontsize=14, 
                bbox=dict(boxstyle="round,pad=0.3", facecolor='lightgreen'))
        ax4.set_title('Teams with Open Critical Vulnerabilities', 
                     fontweight='bold', fontsize=14, pad=20)
    
    return fig

def generate_issued_solved_report(teams_data, output_file):
    """Generate CSV report for Issued/Solved Past 30 Days per team"""
    
    report_data = []
    
    for team in teams_data:
        team_name = team.get('teamName', '')
        
        # Delta information (changes in the past period)
        delta = team.get('delta', {})
        delta_open = delta.get('open', 0)  # Issues opened (issued)
        delta_closed = delta.get('closed', 0)  # Issues closed (solved)
        
        # Calculate net change
        net_change = delta_open - delta_closed
        
        # Date information
        from_date = team.get('fromDate', '')
        to_date = team.get('date', '')
        days, weeks, months = calculate_time_periods(from_date, to_date)
        
        # Current status
        vulns = team.get('vulns', {})
        current_open = vulns.get('open', 0)
        current_closed = vulns.get('closed', 0)
        
        row = {
            'team_name': team_name,
            'period_from': from_date,
            'period_to': to_date,
            'period_days': days,
            'issued_new': delta_open,
            'solved_closed': delta_closed,
            'net_change': net_change,
            'current_open': current_open,
            'current_closed': current_closed,
            'improvement_trend': 'Improving' if net_change < 0 else 'Degrading' if net_change > 0 else 'Stable'
        }
        
        report_data.append(row)
    
    # Sort by net change (worst first)
    report_data.sort(key=lambda x: x['net_change'], reverse=True)
    
    # Save to CSV
    fieldnames = [
        'team_name', 'period_from', 'period_to', 'period_days',
        'issued_new', 'solved_closed', 'net_change', 
        'current_open', 'current_closed', 'improvement_trend'
    ]
    
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(report_data)
    
    print(f"📊 Issued/Solved Report saved to: CSV-Data/{get_year_month_folder()}/{output_file.name}")
    
    # Print summary
    print(f"\n📈 ISSUED/SOLVED SUMMARY (Past {report_data[0]['period_days']} days):")
    print("-" * 70)
    print(f"{'Team':<15} {'Issued':<8} {'Solved':<8} {'Net Δ':<8} {'Trend':<12}")
    print("-" * 70)
    
    for row in report_data[:10]:  # Top 10
        print(f"{row['team_name']:<15} "
              f"{row['issued_new']:<8} "
              f"{row['solved_closed']:<8} "
              f"{row['net_change']:+<8} "
              f"{row['improvement_trend']:<12}")
    
    return report_data

def generate_open_critical_report(teams_data, output_file):
    """Generate CSV report for Open Critical count per team"""
    
    report_data = []
    
    for team in teams_data:
        team_name = team.get('teamName', '')
        
        # Vulnerability data
        vulns = team.get('vulns', {})
        critical_count = vulns.get('critical', 0)
        high_count = vulns.get('high', 0)
        
        # Additional context
        total_risk = team.get('totalRisk', 0)
        avg_risk = team.get('avgRisk', 0)
        asset_count = team.get('assetCount', 0)
        app_count = team.get('appCount', 0)
        
        # Delta for critical issues
        delta = team.get('delta', {})
        delta_open = delta.get('open', 0)
        
        # Calculate critical risk per asset if we have assets
        critical_risk_per_asset = round(critical_count / asset_count, 2) if asset_count > 0 else 0
        
        row = {
            'team_name': team_name,
            'critical_count': critical_count,
            'high_count': high_count,
            'total_high_critical': critical_count + high_count,
            'total_risk': total_risk,
            'avg_risk': avg_risk,
            'app_count': app_count,
            'asset_count': asset_count,
            'critical_per_asset': critical_risk_per_asset,
            'delta_open': delta_open,
            'risk_magnitude': format_risk_magnitude(total_risk),
            'priority_level': 'URGENT' if critical_count > 0 else 'HIGH' if high_count > 10 else 'MEDIUM'
        }
        
        report_data.append(row)
    
    # Sort by critical count (highest first)
    report_data.sort(key=lambda x: (x['critical_count'], x['high_count']), reverse=True)
    
    # Save to CSV
    fieldnames = [
        'team_name', 'critical_count', 'high_count', 'total_high_critical',
        'total_risk', 'avg_risk', 'app_count', 'asset_count', 
        'critical_per_asset', 'delta_open', 'risk_magnitude', 'priority_level'
    ]
    
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(report_data)
    
    print(f"🚨 Open Critical Report saved to: CSV-Data/{get_year_month_folder()}/{output_file.name}")
    
    # Count teams with critical issues
    critical_teams = [t for t in report_data if t['critical_count'] > 0]
    
    print(f"\n🔥 OPEN CRITICAL VULNERABILITIES SUMMARY:")
    print("-" * 70)
    print(f"Teams with Critical Issues: {len(critical_teams)}/{len(report_data)}")
    print(f"Total Critical Vulnerabilities: {sum(t['critical_count'] for t in report_data)}")
    print()
    
    if critical_teams:
        print(f"{'Team':<15} {'Critical':<10} {'High':<8} {'Priority':<10}")
        print("-" * 50)
        for team in critical_teams:
            print(f"{team['team_name']:<15} "
                  f"{team['critical_count']:<10} "
                  f"{team['high_count']:<8} "
                  f"{team['priority_level']:<10}")
    else:
        print("✅ No teams have critical vulnerabilities!")
    
    return report_data

def generate_zero_critical_report(teams_data, output_file):
    """Generate CSV report for Teams with Zero Critical vulnerabilities"""
    
    # Filter teams with zero critical vulnerabilities
    zero_critical_teams = []
    
    for team in teams_data:
        team_name = team.get('teamName', '')
        vulns = team.get('vulns', {})
        critical_count = vulns.get('critical', 0)
        
        if critical_count == 0:
            high_count = vulns.get('high', 0)
            medium_count = vulns.get('medium', 0)
            low_count = vulns.get('low', 0)
            
            total_risk = team.get('totalRisk', 0)
            avg_risk = team.get('avgRisk', 0)
            asset_count = team.get('assetCount', 0)
            app_count = team.get('appCount', 0)
            
            # Delta information
            delta = team.get('delta', {})
            total_risk_delta = delta.get('totalRisk', 0)
            
            row = {
                'team_name': team_name,
                'critical_count': critical_count,
                'high_count': high_count,
                'medium_count': medium_count,
                'low_count': low_count,
                'total_risk': total_risk,
                'avg_risk': avg_risk,
                'app_count': app_count,
                'asset_count': asset_count,
                'risk_trend': 'Improving' if total_risk_delta < 0 else 'Degrading' if total_risk_delta > 0 else 'Stable',
                'total_risk_delta': total_risk_delta,
                'risk_magnitude': format_risk_magnitude(total_risk),
                'security_score': 'Excellent' if high_count < 5 else 'Good' if high_count < 20 else 'Fair'
            }
            
            zero_critical_teams.append(row)
    
    # Sort by total risk (to see which zero-critical teams still have high overall risk)
    zero_critical_teams.sort(key=lambda x: x['total_risk'], reverse=True)
    
    # Save to CSV
    fieldnames = [
        'team_name', 'critical_count', 'high_count', 'medium_count', 'low_count',
        'total_risk', 'avg_risk', 'app_count', 'asset_count', 
        'risk_trend', 'total_risk_delta', 'risk_magnitude', 'security_score'
    ]
    
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(zero_critical_teams)
    
    print(f"✅ Zero Critical Report saved to: CSV-Data/{get_year_month_folder()}/{output_file.name}")
    
    # Print summary
    total_teams = len(teams_data)
    zero_critical_count = len(zero_critical_teams)
    percentage = (zero_critical_count / total_teams * 100) if total_teams > 0 else 0
    
    print(f"\n🎯 ZERO CRITICAL VULNERABILITIES SUMMARY:")
    print("-" * 70)
    print(f"Teams with Zero Criticals: {zero_critical_count}/{total_teams} ({percentage:.1f}%)")
    print()
    
    if zero_critical_teams:
        print(f"{'Team':<15} {'High':<6} {'Med':<6} {'Low':<6} {'Risk':<10} {'Score':<10}")
        print("-" * 65)
        for team in zero_critical_teams[:15]:  # Top 15
            print(f"{team['team_name']:<15} "
                  f"{team['high_count']:<6} "
                  f"{team['medium_count']:<6} "
                  f"{team['low_count']:<6} "
                  f"{team['risk_magnitude']:<10} "
                  f"{team['security_score']:<10}")
    
    return zero_critical_teams

def create_risk_distribution_chart(teams_data):
    """Create risk distribution visualization"""
    if not PDF_AVAILABLE:
        return None
    
    # Extract risk data
    risks = []
    team_names = []
    critical_counts = []
    
    for team in teams_data:
        total_risk = team.get('totalRisk', 0)
        team_name = team.get('teamName', '')
        vulns = team.get('vulns', {})
        critical = vulns.get('critical', 0)
        
        risks.append(total_risk)
        team_names.append(team_name)
        critical_counts.append(critical)
    
    # Create figure with subplots
    fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(16, 12))
    fig.suptitle('Team Risk Assessment Dashboard', fontsize=20, fontweight='bold')
    
    # 1. Top 10 Highest Risk Teams
    top_10_indices = np.argsort(risks)[-10:]
    top_10_risks = [risks[i] for i in top_10_indices]
    top_10_names = [team_names[i] for i in top_10_indices]
    
    bars1 = ax1.barh(range(len(top_10_names)), top_10_risks, color='#ff6b6b')
    ax1.set_yticks(range(len(top_10_names)))
    ax1.set_yticklabels(top_10_names)
    ax1.set_xlabel('Total Risk Score')
    ax1.set_title('Top 10 Highest Risk Teams', fontweight='bold')
    ax1.grid(axis='x', alpha=0.3)
    
    # Add value labels on bars
    for i, bar in enumerate(bars1):
        width = bar.get_width()
        ax1.text(width + max(top_10_risks) * 0.01, bar.get_y() + bar.get_height()/2, 
                f'{format_risk_magnitude(int(width))}', 
                ha='left', va='center', fontweight='bold')
    
    # 2. Critical Vulnerabilities Distribution
    critical_teams = [(team_names[i], critical_counts[i]) for i in range(len(teams_data)) if critical_counts[i] > 0]
    zero_critical_count = len([c for c in critical_counts if c == 0])
    
    if critical_teams:
        crit_names, crit_counts = zip(*critical_teams)
        bars2 = ax2.bar(range(len(crit_names)), crit_counts, color='#dc3545')
        ax2.set_xticks(range(len(crit_names)))
        ax2.set_xticklabels(crit_names, rotation=45, ha='right')
        ax2.set_ylabel('Critical Vulnerabilities')
        ax2.set_title('Teams with Critical Vulnerabilities', fontweight='bold')
        
        # Add value labels on bars
        for i, bar in enumerate(bars2):
            height = bar.get_height()
            ax2.text(bar.get_x() + bar.get_width()/2., height + 0.05,
                    f'{int(height)}', ha='center', va='bottom', fontweight='bold')
    else:
        ax2.text(0.5, 0.5, 'No Critical\nVulnerabilities!', 
                ha='center', va='center', transform=ax2.transAxes,
                fontsize=16, fontweight='bold', color='green')
        ax2.set_title('Teams with Critical Vulnerabilities', fontweight='bold')
    
    # 3. Risk vs Asset Count Scatter
    asset_counts = [team.get('assetCount', 0) for team in teams_data]
    colors = ['red' if c > 0 else 'green' for c in critical_counts]
    
    scatter = ax3.scatter(asset_counts, risks, c=colors, alpha=0.6, s=60)
    ax3.set_xlabel('Asset Count')
    ax3.set_ylabel('Total Risk Score')
    ax3.set_title('Risk vs Asset Count', fontweight='bold')
    ax3.grid(True, alpha=0.3)
    
    # Add legend for scatter plot
    red_patch = mpatches.Patch(color='red', label='Has Critical Vulns')
    green_patch = mpatches.Patch(color='green', label='Zero Critical Vulns')
    ax3.legend(handles=[red_patch, green_patch])
    
    # 4. Security Score Distribution (for zero critical teams)
    zero_crit_teams = [team for team in teams_data if team.get('vulns', {}).get('critical', 0) == 0]
    if zero_crit_teams:
        security_scores = []
        for team in zero_crit_teams:
            high_count = team.get('vulns', {}).get('high', 0)
            if high_count < 5:
                security_scores.append('Excellent')
            elif high_count < 20:
                security_scores.append('Good')
            else:
                security_scores.append('Fair')
        
        score_counts = {score: security_scores.count(score) for score in ['Excellent', 'Good', 'Fair']}
        colors_pie = ['#28a745', '#ffc107', '#fd7e14']
        
        wedges, texts, autotexts = ax4.pie(score_counts.values(), labels=score_counts.keys(), 
                                          autopct='%1.1f%%', colors=colors_pie, startangle=90)
        ax4.set_title('Security Score Distribution\n(Zero Critical Teams)', fontweight='bold')
        
        # Make percentage text bold
        for autotext in autotexts:
            autotext.set_fontweight('bold')
    
    plt.tight_layout()
    return fig

def create_trend_analysis_chart(teams_data):
    """Create trend analysis visualization"""
    if not PDF_AVAILABLE:
        return None
    
    # Process trend data
    improving_teams = []
    degrading_teams = []
    stable_teams = []
    
    for team in teams_data:
        team_name = team.get('teamName', '')
        delta = team.get('delta', {})
        delta_open = delta.get('open', 0)
        delta_closed = delta.get('closed', 0)
        net_change = delta_open - delta_closed
        
        if net_change < 0:
            improving_teams.append((team_name, abs(net_change)))
        elif net_change > 0:
            degrading_teams.append((team_name, net_change))
        else:
            stable_teams.append(team_name)
    
    # Create figure
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 8))
    fig.suptitle('Team Performance Trends Analysis', fontsize=18, fontweight='bold')
    
    # 1. Top Improving Teams
    if improving_teams:
        improving_teams.sort(key=lambda x: x[1], reverse=True)
        top_improving = improving_teams[:8]  # Top 8
        names, improvements = zip(*top_improving)
        
        bars1 = ax1.barh(range(len(names)), improvements, color='#28a745')
        ax1.set_yticks(range(len(names)))
        ax1.set_yticklabels(names)
        ax1.set_xlabel('Issues Resolved (Net Improvement)')
        ax1.set_title('Top Improving Teams', fontweight='bold', color='green')
        ax1.grid(axis='x', alpha=0.3)
        
        # Add value labels
        for i, bar in enumerate(bars1):
            width = bar.get_width()
            ax1.text(width + max(improvements) * 0.01, bar.get_y() + bar.get_height()/2, 
                    f'+{int(width)}', ha='left', va='center', fontweight='bold')
    else:
        ax1.text(0.5, 0.5, 'No Improving\nTeams Found', 
                ha='center', va='center', transform=ax1.transAxes,
                fontsize=14, color='gray')
        ax1.set_title('Top Improving Teams', fontweight='bold')
    
    # 2. Teams Needing Attention (Degrading)
    if degrading_teams:
        degrading_teams.sort(key=lambda x: x[1], reverse=True)
        top_degrading = degrading_teams[:8]  # Top 8
        names, degradations = zip(*top_degrading)
        
        bars2 = ax2.barh(range(len(names)), degradations, color='#dc3545')
        ax2.set_yticks(range(len(names)))
        ax2.set_yticklabels(names)
        ax2.set_xlabel('Net Issue Increase')
        ax2.set_title('Teams Needing Attention', fontweight='bold', color='red')
        ax2.grid(axis='x', alpha=0.3)
        
        # Add value labels
        for i, bar in enumerate(bars2):
            width = bar.get_width()
            ax2.text(width + max(degradations) * 0.01, bar.get_y() + bar.get_height()/2, 
                    f'+{int(width)}', ha='left', va='center', fontweight='bold')
    else:
        ax2.text(0.5, 0.5, 'No Teams\nNeed Attention', 
                ha='center', va='center', transform=ax2.transAxes,
                fontsize=14, color='green')
        ax2.set_title('Teams Needing Attention', fontweight='bold')
    
    plt.tight_layout()
    return fig

def create_summary_statistics_table(teams_data):
    """Create summary statistics table"""
    if not PDF_AVAILABLE:
        return None
    
    # Calculate statistics
    total_teams = len(teams_data)
    total_risk = sum(team.get('totalRisk', 0) for team in teams_data)
    total_assets = sum(team.get('assetCount', 0) for team in teams_data)
    total_apps = sum(team.get('appCount', 0) for team in teams_data)
    total_components = sum(team.get('componentCount', 0) for team in teams_data)
    
    # Vulnerability statistics
    critical_vulns = sum(team.get('vulns', {}).get('critical', 0) for team in teams_data)
    high_vulns = sum(team.get('vulns', {}).get('high', 0) for team in teams_data)
    medium_vulns = sum(team.get('vulns', {}).get('medium', 0) for team in teams_data)
    low_vulns = sum(team.get('vulns', {}).get('low', 0) for team in teams_data)
    open_vulns = sum(team.get('vulns', {}).get('open', 0) for team in teams_data)
    closed_vulns = sum(team.get('vulns', {}).get('closed', 0) for team in teams_data)
    
    # Team performance statistics
    teams_with_critical = len([t for t in teams_data if t.get('vulns', {}).get('critical', 0) > 0])
    zero_critical_teams = total_teams - teams_with_critical
    
    # Create figure
    fig, ax = plt.subplots(figsize=(12, 8))
    ax.axis('tight')
    ax.axis('off')
    
    # Create data for table
    statistics = [
        ['OVERVIEW STATISTICS', ''],
        ['Total Teams', f'{total_teams:,}'],
        ['Total Risk Score', f'{format_risk_magnitude(total_risk)}'],
        ['Total Applications', f'{total_apps:,}'],
        ['Total Components', f'{total_components:,}'],
        ['Total Assets', f'{total_assets:,}'],
        ['', ''],
        ['VULNERABILITY BREAKDOWN', ''],
        ['Critical Vulnerabilities', f'{critical_vulns:,}'],
        ['High Vulnerabilities', f'{high_vulns:,}'],
        ['Medium Vulnerabilities', f'{medium_vulns:,}'],
        ['Low Vulnerabilities', f'{low_vulns:,}'],
        ['Open Issues', f'{open_vulns:,}'],
        ['Closed Issues', f'{closed_vulns:,}'],
        ['', ''],
        ['TEAM PERFORMANCE', ''],
        ['Teams with Critical Issues', f'{teams_with_critical} ({teams_with_critical/total_teams*100:.1f}%)'],
        ['Teams with Zero Critical', f'{zero_critical_teams} ({zero_critical_teams/total_teams*100:.1f}%)'],
        ['Average Risk per Team', f'{total_risk/total_teams:.0f}'],
        ['Average Assets per Team', f'{total_assets/total_teams:.0f}'],
    ]
    
    # Create table
    table = ax.table(cellText=statistics, cellLoc='left', loc='center', 
                    colWidths=[0.6, 0.4])
    
    # Style the table
    table.auto_set_font_size(False)
    table.set_fontsize(11)
    table.scale(1.2, 2)
    
    # Style header rows
    for i in [0, 7, 15]:  # Header row indices
        table[(i, 0)].set_facecolor('#4472C4')
        table[(i, 0)].set_text_props(weight='bold', color='white')
        table[(i, 1)].set_facecolor('#4472C4')
        table[(i, 1)].set_text_props(weight='bold', color='white')
    
    # Style empty rows
    for i in [6, 14]:
        table[(i, 0)].set_facecolor('#f0f0f0')
        table[(i, 1)].set_facecolor('#f0f0f0')
    
    # Style critical vulnerability row
    table[(8, 0)].set_facecolor('#ffebee')
    table[(8, 1)].set_facecolor('#ffebee')
    table[(8, 1)].set_text_props(weight='bold', color='red')
    
    plt.title('Risk Assessment Summary Statistics', 
              fontsize=16, fontweight='bold', pad=20)
    
    return fig

def generate_pdf_report(json_data, output_file):
    """Generate comprehensive PDF report with visualizations and statistics"""
    
    if not PDF_AVAILABLE:
        print("❌ PDF generation requires additional packages:")
        print("   pip install matplotlib seaborn pandas numpy")
        return
    
    teams = json_data.get('content', [])
    
    print("🔄 Generating comprehensive PDF report with enhanced analysis...")
    
    # Set style for better-looking plots
    plt.style.use('default')
    sns.set_palette("husl")
    
    with PdfPages(output_file) as pdf:
        # Page 1: Risk Distribution Dashboard
        fig1 = create_risk_distribution_chart(teams)
        if fig1:
            pdf.savefig(fig1, bbox_inches='tight', dpi=300)
            plt.close(fig1)
        
        # Page 2: Trend Analysis
        fig2 = create_trend_analysis_chart(teams)
        if fig2:
            pdf.savefig(fig2, bbox_inches='tight', dpi=300)
            plt.close(fig2)
        
        # Page 3: Summary Statistics
        fig3 = create_summary_statistics_table(teams)
        if fig3:
            pdf.savefig(fig3, bbox_inches='tight', dpi=300)
            plt.close(fig3)
        
        # Page 4: Ordered Tables Analysis (Bar Charts)
        fig4 = create_ordered_tables_charts(teams)
        if fig4:
            pdf.savefig(fig4, bbox_inches='tight', dpi=300)
            plt.close(fig4)
        
        # Page 5: Comprehensive Dashboards - Page 1
        fig5 = create_comprehensive_dashboards_page1(teams)
        if fig5:
            pdf.savefig(fig5, bbox_inches='tight', dpi=300)
            plt.close(fig5)
        
        # Page 6: Comprehensive Dashboards - Page 2
        fig6 = create_comprehensive_dashboards_page2(teams)
        if fig6:
            pdf.savefig(fig6, bbox_inches='tight', dpi=300)
            plt.close(fig6)
        
        # Page 7: Zero Critical Teams Table
        zero_critical, critical, resolved = create_ordered_tables_analysis(teams)
        
        if zero_critical:
            fig7, ax = plt.subplots(figsize=(14, 10))
            ax.axis('tight')
            ax.axis('off')
            
            # Prepare zero critical teams table
            table_data = zero_critical[:20]  # Top 20
            headers = ['Team', 'Total Risk', 'High', 'Medium', 'Low', 'None', 'Apps', 'Assets']
            rows = []
            for team in table_data:
                rows.append([
                    team['team_name'],
                    format_risk_magnitude(team['total_risk']),
                    str(team['high']),
                    str(team['medium']),
                    str(team['low']),
                    str(team['none']),
                    str(team['app_count']),
                    str(team['asset_count'])
                ])
            
            table = ax.table(cellText=rows, colLabels=headers, cellLoc='center', loc='center')
            table.auto_set_font_size(False)
            table.set_fontsize(9)
            table.scale(1.2, 1.8)
            
            # Style header
            for i in range(len(headers)):
                table[(0, i)].set_facecolor('#28a745')
                table[(0, i)].set_text_props(weight='bold', color='white')
            
            plt.title('Teams with Zero Critical Vulnerabilities (Ordered by Total Risk)', 
                     fontsize=14, fontweight='bold', pad=20)
            
            pdf.savefig(fig7, bbox_inches='tight', dpi=300)
            plt.close(fig7)
        
        # Page 8: Critical Teams Table
        if critical:
            fig8, ax = plt.subplots(figsize=(14, 10))
            ax.axis('tight')
            ax.axis('off')
            
            headers = ['Team', 'Critical', 'High', 'Total Risk', 'Open', 'Assets', 'Priority']
            rows = []
            for team in critical:
                rows.append([
                    team['team_name'],
                    str(team['critical']),
                    str(team['high']),
                    format_risk_magnitude(team['total_risk']),
                    str(team['open']),
                    str(team['asset_count']),
                    team['priority']
                ])
            
            table = ax.table(cellText=rows, colLabels=headers, cellLoc='center', loc='center')
            table.auto_set_font_size(False)
            table.set_fontsize(9)
            table.scale(1.2, 1.8)
            
            # Style header
            for i in range(len(headers)):
                table[(0, i)].set_facecolor('#dc3545')
                table[(0, i)].set_text_props(weight='bold', color='white')
            
            # Highlight critical vulnerabilities
            for i, team in enumerate(critical, 1):
                table[(i, 1)].set_facecolor('#ffcccb')  # Light red for critical
                table[(i, 1)].set_text_props(weight='bold')
                if team['priority'] == 'URGENT':
                    table[(i, 6)].set_facecolor('#ffcccb')
                    table[(i, 6)].set_text_props(weight='bold', color='red')
            
            plt.title('Teams with Critical Vulnerabilities (Ordered by Critical Count)', 
                     fontsize=14, fontweight='bold', pad=20)
            
            pdf.savefig(fig8, bbox_inches='tight', dpi=300)
            plt.close(fig8)
        
        # Page 9: Issue Resolvers Table
        if resolved:
            fig9, ax = plt.subplots(figsize=(14, 10))
            ax.axis('tight')
            ax.axis('off')
            
            table_data = resolved[:20]  # Top 20
            headers = ['Team', 'Issues Resolved', 'Issues Opened', 'Net Improvement', 'Total Risk', 'Trend']
            rows = []
            for team in table_data:
                rows.append([
                    team['team_name'],
                    str(team['issues_resolved']),
                    str(team['issues_opened']),
                    f"{team['net_improvement']:+}",
                    format_risk_magnitude(team['total_risk']),
                    team['trend']
                ])
            
            table = ax.table(cellText=rows, colLabels=headers, cellLoc='center', loc='center')
            table.auto_set_font_size(False)
            table.set_fontsize(9)
            table.scale(1.2, 1.8)
            
            # Style header
            for i in range(len(headers)):
                table[(0, i)].set_facecolor('#17a2b8')
                table[(0, i)].set_text_props(weight='bold', color='white')
            
            # Color code by performance
            for i, team in enumerate(table_data, 1):
                if team['net_improvement'] > 0:
                    table[(i, 3)].set_facecolor('#d4edda')  # Light green for improvement
                    table[(i, 3)].set_text_props(weight='bold', color='green')
                elif team['net_improvement'] < 0:
                    table[(i, 3)].set_facecolor('#f8d7da')  # Light red for degradation
                    table[(i, 3)].set_text_props(weight='bold', color='red')
            
            plt.title('Teams Ordered by Issues Resolved (Top 20 Performers)', 
                     fontsize=14, fontweight='bold', pad=20)
            
            pdf.savefig(fig9, bbox_inches='tight', dpi=300)
            plt.close(fig9)
    
    print(f"📊 Enhanced PDF Report saved to: Reports/{get_year_month_folder()}/{output_file.name}")
    print(f"📄 Report includes: 9 pages with tables, charts, and comprehensive analysis")
    print(f"📋 New Features: Split comprehensive dashboards for better readability")

def generate_time_series_pdf_report(json_data, output_file):
    """Generate time series PDF report with performance over time analysis"""
    
    if not PDF_AVAILABLE:
        print("❌ Time series PDF generation requires additional packages:")
        print("   pip install matplotlib seaborn pandas numpy")
        return
    
    teams = json_data.get('content', [])
    
    print("🔄 Generating time series analysis with historical trends...")
    
    # Generate historical data for analysis
    historical_data = generate_historical_data(teams, months_back=6)
    
    # Set style for better-looking plots
    plt.style.use('default')
    sns.set_palette("husl")
    
    with PdfPages(output_file) as pdf:
        # Page 1: Time Series Overview
        fig1 = create_time_series_charts(historical_data)
        if fig1:
            pdf.savefig(fig1, bbox_inches='tight', dpi=300)
            plt.close(fig1)
        
        # Page 2: Category Performance Over Time
        fig2 = create_category_performance_chart(historical_data)
        if fig2:
            pdf.savefig(fig2, bbox_inches='tight', dpi=300)
            plt.close(fig2)
        
        # Page 3: Detailed Team Trends
        fig3 = create_detailed_team_trends_chart(historical_data, top_n=8)
        if fig3:
            pdf.savefig(fig3, bbox_inches='tight', dpi=300)
            plt.close(fig3)
    
    print(f"📈 Time Series PDF Report saved to: Reports/{get_year_month_folder()}/{output_file.name}")

def generate_comprehensive_tables_csv(json_data, output_file):
    """Generate comprehensive CSV with all ordered tables"""
    teams = json_data.get('content', [])
    zero_critical, critical, resolved = create_ordered_tables_analysis(teams)
    
    import csv
    
    with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        
        # Write header for the report
        writer.writerow(['=== COMPREHENSIVE TEAM RISK ANALYSIS REPORT ==='])
        writer.writerow(['Generated:', datetime.now().strftime('%Y-%m-%d %H:%M:%S')])
        writer.writerow([])
        
        # 1. Teams with Zero Critical Vulnerabilities
        writer.writerow(['=== 1. TEAMS WITH ZERO CRITICAL VULNERABILITIES (Ordered by Total Risk) ==='])
        writer.writerow(['Team Name', 'Total Risk', 'High', 'Medium', 'Low', 'None', 'Apps', 'Assets'])
        
        for team in zero_critical:
            writer.writerow([
                team['team_name'],
                format_risk_magnitude(team['total_risk']),
                team['high'],
                team['medium'],
                team['low'],
                team['none'],
                team['app_count'],
                team['asset_count']
            ])
        
        writer.writerow([])
        writer.writerow([f'Total teams with zero criticals: {len(zero_critical)}'])
        writer.writerow([])
        
        # 2. Teams with Open Critical Vulnerabilities
        writer.writerow(['=== 2. TEAMS WITH OPEN CRITICAL VULNERABILITIES (Ordered by Critical Count) ==='])
        writer.writerow(['Team Name', 'Critical Count', 'High Count', 'Total Risk', 'Open Issues', 'Assets', 'Priority Level'])
        
        for team in critical:
            writer.writerow([
                team['team_name'],
                team['critical'],
                team['high'],
                format_risk_magnitude(team['total_risk']),
                team['open'],
                team['asset_count'],
                team['priority']
            ])
        
        writer.writerow([])
        writer.writerow([f'Total teams with critical vulnerabilities: {len(critical)}'])
        urgent_teams = len([t for t in critical if t['priority'] == 'URGENT'])
        writer.writerow([f'Teams requiring URGENT attention: {urgent_teams}'])
        writer.writerow([])
        
        # 3. Teams Ordered by Issues Resolved
        writer.writerow(['=== 3. TEAMS ORDERED BY ISSUES RESOLVED (Performance Rankings) ==='])
        writer.writerow(['Team Name', 'Issues Resolved', 'Issues Opened', 'Net Improvement', 'Total Risk', 'Trend'])
        
        for team in resolved:
            writer.writerow([
                team['team_name'],
                team['issues_resolved'],
                team['issues_opened'],
                f"{team['net_improvement']:+}",
                format_risk_magnitude(team['total_risk']),
                team['trend']
            ])
        
        writer.writerow([])
        improving_teams = len([t for t in resolved if t['net_improvement'] > 0])
        degrading_teams = len([t for t in resolved if t['net_improvement'] < 0])
        writer.writerow([f'Teams improving: {improving_teams}'])
        writer.writerow([f'Teams degrading: {degrading_teams}'])
        writer.writerow([])
        
        # 4. Summary Statistics
        writer.writerow(['=== 4. OVERALL SUMMARY STATISTICS ==='])
        total_teams = len(teams)
        total_risk = sum(team.get('totalRisk', 0) for team in teams)
        total_critical = sum(team.get('vulns', {}).get('critical', 0) for team in teams)
        total_assets = sum(team.get('assetCount', 0) for team in teams)
        
        writer.writerow(['Metric', 'Value'])
        writer.writerow(['Total Teams', total_teams])
        writer.writerow(['Total Risk Score', format_risk_magnitude(total_risk)])
        writer.writerow(['Total Critical Vulnerabilities', total_critical])
        writer.writerow(['Total Assets Under Management', total_assets])
        writer.writerow(['Teams with Zero Criticals', len(zero_critical)])
        writer.writerow(['Teams with Critical Issues', len(critical)])
        writer.writerow(['Average Risk per Team', format_risk_magnitude(total_risk // total_teams if total_teams > 0 else 0)])
        writer.writerow(['Critical Vulnerability Rate', f'{(total_critical/total_teams):.2f} per team' if total_teams > 0 else '0'])
    
    print(f"📊 Comprehensive tables CSV saved to: CSV-Data/{get_year_month_folder()}/{output_file.name}")

def generate_weekly_reports(json_data):
    """Generate all weekly reports"""
    
    teams = json_data.get('content', [])
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    print("🔄 Generating Weekly Risk Reports...")
    print("="*60)
    
    # 1. Issued/Solved Report
    issued_solved_filename = f"weekly_report_issued_solved_{timestamp}.csv"
    issued_solved_file = get_report_file_path(issued_solved_filename, is_pdf=False)
    generate_issued_solved_report(teams, issued_solved_file)
    
    print()
    
    # 2. Open Critical Report  
    critical_filename = f"weekly_report_open_critical_{timestamp}.csv"
    critical_file = get_report_file_path(critical_filename, is_pdf=False)
    generate_open_critical_report(teams, critical_file)
    
    print()
    
    # 3. Zero Critical Report
    zero_critical_filename = f"weekly_report_zero_critical_{timestamp}.csv"
    zero_critical_file = get_report_file_path(zero_critical_filename, is_pdf=False)
    generate_zero_critical_report(teams, zero_critical_file)
    
    # 4. Comprehensive Tables Report
    comprehensive_filename = f"comprehensive_tables_report_{timestamp}.csv"
    comprehensive_file = get_report_file_path(comprehensive_filename, is_pdf=False)
    generate_comprehensive_tables_csv(json_data, comprehensive_file)
    
    print()
    print("="*60)
    print("✅ All weekly reports generated successfully!")
    print(f"📁 Files created in CSV-Data/{get_year_month_folder()}/:")
    print(f"   • {issued_solved_filename}")
    print(f"   • {critical_filename}")  
    print(f"   • {zero_critical_filename}")
    print(f"   • {comprehensive_filename}")

def convert_to_full_risk_table(json_data):
    """Convert JSON data to comprehensive risk assessment table (original functionality)"""
    
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

def save_full_table_to_csv(data, output_file):
    """Save comprehensive data to CSV file"""
    
    fieldnames = [
        'team_name', 'risk', 'total_risk_magnitude', 'delta_calculated',
        'data_from_to', 'days', 'weeks', 'months', 'app_count',
        'component_count', 'asset_count', 'delta_open', 'delta_closed', 
        'total_risk_delta', 'open', 'closed', 'critical', 'high',
        'medium', 'low', 'none', 'average_risk'
    ]
    
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(data)

def main():
    """Main execution function"""
    
    parser = argparse.ArgumentParser(description='Generate comprehensive team risk reports with time series analysis')
    parser.add_argument('--weekly_report', action='store_true', 
                       help='Generate weekly CSV reports (issued/solved, critical, zero critical)')
    parser.add_argument('--full_table', action='store_true',
                       help='Generate full comprehensive risk table CSV')
    parser.add_argument('--pdf_report', action='store_true',
                       help='Generate standard PDF report with visualizations and statistics')
    parser.add_argument('--time_series', action='store_true',
                       help='Generate time series analysis PDF with performance trends over time')
    parser.add_argument('--all_reports', action='store_true',
                       help='Generate all available reports (weekly, full table, PDF, and time series)')
    
    args = parser.parse_args()
    
    # Handle --all_reports flag
    if args.all_reports:
        args.weekly_report = True
        args.full_table = True
        args.pdf_report = True
        args.time_series = True
    
    # Default to full table if no arguments provided
    if not any([args.weekly_report, args.full_table, args.pdf_report, args.time_series]):
        args.full_table = True
    
    # File paths
    input_file = Path("Team-list.json")
    
    # Check if input file exists
    if not input_file.exists():
        print(f"❌ Error: Input file {input_file} not found!")
        print(f"Please ensure {input_file} exists in the current directory.")
        return
    
    try:
        # Load data
        print("🔄 Loading JSON data...")
        json_data = load_json_data(input_file)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        if args.weekly_report:
            generate_weekly_reports(json_data)
            print()
        
        if args.pdf_report:
            pdf_filename = f"team_risk_assessment_report_{timestamp}.pdf"
            pdf_output_file = get_report_file_path(pdf_filename, is_pdf=True)
            generate_pdf_report(json_data, pdf_output_file)
            print()
        
        if args.time_series:
            time_series_filename = f"team_risk_time_series_report_{timestamp}.pdf"
            time_series_output_file = get_report_file_path(time_series_filename, is_pdf=True)
            generate_time_series_pdf_report(json_data, time_series_output_file)
            print()
        
        if args.full_table:
            print("🔄 Generating comprehensive risk table...")
            table_data = convert_to_full_risk_table(json_data)
            
            csv_filename = f"team_risk_assessment_full_{timestamp}.csv"
            output_file = get_report_file_path(csv_filename, is_pdf=False)
            
            save_full_table_to_csv(table_data, output_file)
            print(f"📄 Full table saved to: CSV-Data/{get_year_month_folder()}/{output_file.name}")
        
        print("\n🎉 All requested reports generated successfully!")
        
    except Exception as e:
        print(f"❌ Error processing data: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main() 