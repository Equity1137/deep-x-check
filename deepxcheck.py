#!/usr/bin/env python3
"""
DeepXCheck - X Profile Analysis Tool
MVP 1.0 - Discovery, Investigation, and Expert modes
Author: Hiram Abif with Kai (DeepSeek)
License: MIT
"""

import json
import re
from datetime import datetime
from typing import Dict, List, Tuple, Optional

class DeepXCheck:
    def __init__(self):
        self.version = "1.0"
        self.red_flags = []
        self.score = 0
        self.max_score = 10
        self.analysis_date = datetime.now().strftime("%Y-%m-%d %H:%M UTC")
        
    def analyze_profile(self, profile_data: Dict, mode: str = "discovery") -> Dict:
        """
        Analyze an X profile based on selected mode
        
        Available modes:
        - discovery: anonymized, educational
        - investigation: partial technical data
        - expert: complete data with disclaimer
        """
        self.profile_data = profile_data
        self.mode = mode
        self.red_flags = []
        self.score = 0
        
        # Run all checks
        self._check_geo_inconsistency()
        self._check_account_age()
        self._check_name_changes()
        self._check_telegram_links()
        self._check_suspicious_bio()
        self._check_follow_ratio()
        self._check_coordination_patterns()
        self._check_like_behavior()
        
        # Calculate risk score
        self._calculate_score()
        
        # Generate mode-appropriate report
        return self._generate_report()
    
    def _check_geo_inconsistency(self):
        """Check for geographical inconsistencies"""
        declared = self.profile_data.get('declared_location', '').lower()
        tech_location = self.profile_data.get('technical_location', '').lower()
        device = self.profile_data.get('device', '')
        
        if not declared or not tech_location:
            return
            
        # Country indicators
        us_indicators = ['usa', 'united states', 'new york', 'california', 'texas', 
                        'pennsylvania', 'memphis', 'boston', 'ma', 'pa', 'tn']
        nigeria_indicators = ['nigeria', 'ng', 'lagos', 'abuja', 'ikeja']
        
        is_declared_us = any(indicator in declared for indicator in us_indicators)
        is_tech_nigeria = any(indicator in tech_location for indicator in nigeria_indicators)
        
        if is_declared_us and is_tech_nigeria:
            self.red_flags.append({
                'type': 'geo_inconsistency',
                'severity': 'high',
                'message': f'Declared location: {declared.title()}, Technical location: {tech_location.title()}',
                'score_impact': 3
            })
    
    def _check_account_age(self):
        """Check account creation date and activity"""
        join_date = self.profile_data.get('join_date', '')
        current_year = datetime.now().year
        
        if '2024' in join_date or '2023' in join_date:
            followers = self.profile_data.get('followers', 0)
            if followers > 1000:
                self.red_flags.append({
                    'type': 'suspicious_growth',
                    'severity': 'medium',
                    'message': f'Recent account ({join_date}) with {followers} followers',
                    'score_impact': 2
                })
    
    def _check_name_changes(self):
        """Check for frequent username changes"""
        name_changes = self.profile_data.get('name_changes', 0)
        last_change = self.profile_data.get('last_name_change', '')
        
        if name_changes >= 3:
            self.red_flags.append({
                'type': 'identity_instability',
                'severity': 'medium',
                'message': f'{name_changes} username changes, last: {last_change}',
                'score_impact': 2
            })
    
    def _check_telegram_links(self):
        """Detect Telegram links and shared channels"""
        bio = self.profile_data.get('bio', '').lower()
        telegram_patterns = ['t.me/', 'telegram', 'tg://', 'joinchat/']
        
        for pattern in telegram_patterns:
            if pattern in bio:
                self.red_flags.append({
                    'type': 'telegram_promotion',
                    'severity': 'medium',
                    'message': 'Telegram link found in bio (common for coordinated groups)',
                    'score_impact': 2
                })
                break
    
    def _check_suspicious_bio(self):
        """Analyze bio for scam indicators"""
        bio = self.profile_data.get('bio', '').lower()
        scam_keywords = [
            'blessed', 'blessing', 'cashapp', 'paypal', 'apple pay', 
            'send me', 'dm me', 'instant money', 'get paid',
            'nfa', 'not financial advice', 'alpha', 'signal',
            'pump', 'moon', '100x', 'financial freedom'
        ]
        
        found_keywords = []
        for keyword in scam_keywords:
            if keyword in bio:
                found_keywords.append(keyword)
        
        if found_keywords:
            self.red_flags.append({
                'type': 'suspicious_bio',
                'severity': 'medium',
                'message': f'Bio contains suspicious keywords: {", ".join(found_keywords)}',
                'score_impact': 1 if len(found_keywords) < 3 else 2
            })
    
    def _check_follow_ratio(self):
        """Check following/followers ratio"""
        following = self.profile_data.get('following', 0)
        followers = self.profile_data.get('followers', 0)
        
        if followers > 0:
            ratio = following / followers
            if ratio > 10:  # Following way more than followers
                self.red_flags.append({
                    'type': 'unbalanced_ratio',
                    'severity': 'low',
                    'message': f'Following {following} but only {followers} followers (ratio: {ratio:.1f})',
                    'score_impact': 1
                })
    
    def _check_coordination_patterns(self):
        """Check for coordinated behavior patterns"""
        shared_channels = self.profile_data.get('shared_channels', [])
        if len(shared_channels) >= 2:
            self.red_flags.append({
                'type': 'coordinated_network',
                'severity': 'high',
                'message': f'Shares {len(shared_channels)} channels with other suspicious accounts',
                'score_impact': 3
            })
    
    def _check_like_behavior(self):
        """Check for like-fishing behavior"""
        like_fishing = self.profile_data.get('like_fishing', False)
        if like_fishing:
            self.red_flags.append({
                'type': 'like_fishing',
                'severity': 'medium',
                'message': 'Uses likes to attract attention before DM scams',
                'score_impact': 2
            })
    
    def _calculate_score(self):
        """Calculate risk score based on red flags"""
        base_score = 0
        for flag in self.red_flags:
            base_score += flag['score_impact']
        
        # Normalize to 0-10 scale
        self.score = min(base_score, self.max_score)
    
    def _generate_report(self) -> Dict:
        """Generate analysis report based on mode"""
        if self.mode == "expert":
            disclaimer = """
            ⚠️ EXPERT MODE - IDENTIFYING DATA VISIBLE
            This report contains identifying information.
            Public sharing may have legal and ethical consequences.
            Use responsibly for documentation purposes only.
            """
        else:
            disclaimer = "Educational analysis - patterns anonymized"
        
        # Apply anonymization based on mode
        if self.mode == "discovery":
            profile_display = self._anonymize_profile()
        elif self.mode == "investigation":
            profile_display = self._partial_anonymize()
        else:  # expert
            profile_display = self.profile_data
        
        report = {
            'meta': {
                'tool': 'DeepXCheck',
                'version': self.version,
                'mode': self.mode,
                'analysis_date': self.analysis_date,
                'disclaimer': disclaimer
            },
            'risk_assessment': {
                'score': self.score,
                'level': self._get_risk_level(),
                'red_flags_count': len(self.red_flags)
            },
            'profile': profile_display,
            'red_flags': self.red_flags,
            'recommendations': self._generate_recommendations()
        }
        
        return report
    
    def _anonymize_profile(self) -> Dict:
        """Anonymize profile for discovery mode"""
        anon = self.profile_data.copy()
        # Remove identifying information
        if 'username' in anon:
            anon['username'] = '@[REDACTED]'
        if 'display_name' in anon:
            anon['display_name'] = '[ANONYMIZED]'
        if 'bio' in anon:
            # Keep bio pattern but remove specifics
            anon['bio'] = re.sub(r'@\w+', '@[USER]', anon['bio'])
            anon['bio'] = re.sub(r't\.me/\w+', 't.me/[CHANNEL]', anon['bio'])
        return anon
    
    def _partial_anonymize(self) -> Dict:
        """Partially anonymize for investigation mode"""
        partial = self.profile_data.copy()
        if 'username' in partial:
            # Show partial username
            if len(partial['username']) > 4:
                partial['username'] = partial['username'][:2] + '***' + partial['username'][-2:]
        return partial
    
    def _get_risk_level(self) -> str:
        """Convert score to risk level"""
        if self.score >= 8:
            return "CRITICAL"
        elif self.score >= 6:
            return "HIGH"
        elif self.score >= 4:
            return "MEDIUM"
        elif self.score >= 2:
            return "LOW"
        else:
            return "MINIMAL"
    
    def _generate_recommendations(self) -> List[str]:
        """Generate actionable recommendations"""
        recs = []
        
        if self.score >= 6:
            recs.append("⚠️ Avoid any financial interaction with this account")
            recs.append("🔍 Report if promoting scams or manipulation")
        
        if any(f['type'] == 'geo_inconsistency' for f in self.red_flags):
            recs.append("🌍 Verify geographical claims before trust")
        
        if any(f['type'] == 'telegram_promotion' for f in self.red_flags):
            recs.append("📢 Be cautious of Telegram groups promising quick gains")
        
        if any(f['type'] == 'like_fishing' for f in self.red_flags):
            recs.append("👍 Likes can be bait - check profile before engaging")
        
        if len(recs) == 0:
            recs.append("✅ Profile appears normal - maintain standard vigilance")
        
        return recs
    
    def print_report(self, report: Dict):
        """Print formatted report to console"""
        print("\n" + "="*60)
        print("DEEPXCHECK ANALYSIS REPORT")
        print("="*60)
        
        # Meta info
        print(f"\n📊 MODE: {report['meta']['mode'].upper()}")
        print(f"📅 Date: {report['meta']['analysis_date']}")
        
        # Risk assessment
        risk = report['risk_assessment']
        print(f"\n⚠️  RISK SCORE: {risk['score']}/10 - {risk['level']}")
        print(f"🔴 Red flags detected: {risk['red_flags_count']}")
        
        # Profile info (mode-dependent)
        if report['meta']['mode'] != 'discovery':
            profile = report['profile']
            print(f"\n👤 PROFILE:")
            print(f"   Name: {profile.get('display_name', 'N/A')}")
            print(f"   Handle: {profile.get('username', 'N/A')}")
            print(f"   Bio: {profile.get('bio', 'N/A')[:100]}...")
            print(f"   Location: {profile.get('declared_location', 'N/A')}")
            print(f"   Technical: {profile.get('technical_location', 'N/A')}")
        
        # Red flags
        if report['red_flags']:
            print(f"\n🚨 RED FLAGS:")
            for i, flag in enumerate(report['red_flags'], 1):
                print(f"   {i}. [{flag['severity'].upper()}] {flag['message']}")
        
        # Recommendations
        print(f"\n💡 RECOMMENDATIONS:")
        for rec in report['recommendations']:
            print(f"   • {rec}")
        
        # Disclaimer for expert mode
        if report['meta']['mode'] == 'expert':
            print(f"\n{'-'*60}")
            print("EXPERT MODE DISCLAIMER:")
            print(report['meta']['disclaimer'])
            print("-"*60)
        
        print("\n" + "="*60)
        print("End of report - Use responsibly")
        print("="*60 + "\n")


# Example usage
if __name__ == "__main__":
    # Example profile
    test_profile = {
        'username': '@TestUser',
        'display_name': 'Test',
        'bio': 'Follow me on t.me/test for signals!',
        'declared_location': 'New York, USA',
        'technical_location': 'Nigeria',
        'join_date': 'November 2024',
        'name_changes': 0,
        'following': 10,
        'followers': 100,
        'shared_channels': ['t.me/test'],
        'like_fishing': True
    }
    
    analyzer = DeepXCheck()
    report = analyzer.analyze_profile(test_profile, mode='discovery')
    analyzer.print_report(report)
