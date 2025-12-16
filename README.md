# DeepXCheck 🔍

**Open-source social media vigilance tool - Detect coordinated manipulation patterns on X/Twitter**

## 🎯 Mission
DeepXCheck provides tools to analyze X (Twitter) profiles for suspicious patterns, geographical inconsistencies, and coordinated manipulation tactics — while educating users about digital risks.

## ✨ Features
- **Three analysis modes**: Discovery (educational), Investigation (technical), Expert (full data)
- **Pattern detection**: Geo inconsistencies, fake identities, scam bios, coordinated networks
- **Risk scoring**: 0-10 scale with clear recommendations
- **Privacy-focused**: Anonymization by default, ethical disclosure
- **Open source**: MIT licensed, community-driven improvements

## 🚀 Quick Start

```python
from deepxcheck import DeepXCheck

# Initialize analyzer
analyzer = DeepXCheck()

# Prepare profile data (from manual observation or APIs)
profile = {
    'username': '@ExampleUser',
    'declared_location': 'New York, USA',
    'technical_location': 'Nigeria',
    'bio': 'Send me CashApp for blessing $$$',
    'join_date': 'November 2024',
    'followers': 1500,
    'following': 10
}

# Analyze in Discovery mode (anonymized, educational)
report = analyzer.analyze_profile(profile, mode='discovery')
analyzer.print_report(report)
