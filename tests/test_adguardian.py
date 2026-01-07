"""
Test per ADGuardian
Sviluppato da ISIPC - Truant Bruno | https://isipc.com
"""

import pytest
from datetime import datetime, timedelta
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.policy_analyzer import PolicyAnalyzer, RiskLevel, PolicyCheck
from src.user_auditor import UserAuditor, UserRisk, UserIssue, FILETIME_EPOCH


class TestPolicyAnalyzer:
    """Test per PolicyAnalyzer"""

    def test_weak_policy_critical(self):
        """Policy molto debole deve avere score basso"""
        weak_policy = {
            "min_password_length": 4,
            "complexity_enabled": False,
            "password_history": 0,
            "max_password_age_days": 0,
            "lockout_threshold": 0,
        }

        analyzer = PolicyAnalyzer()
        checks = analyzer.analyze(weak_policy)
        summary = analyzer.get_summary()

        assert summary['critical_count'] > 0
        assert summary['score'] < 50

    def test_strong_policy_ok(self):
        """Policy forte deve avere score alto"""
        strong_policy = {
            "min_password_length": 14,
            "complexity_enabled": True,
            "password_history": 24,
            "max_password_age_days": 60,
            "min_password_age_days": 1,
            "lockout_threshold": 5,
            "lockout_duration_minutes": 30,
        }

        analyzer = PolicyAnalyzer()
        checks = analyzer.analyze(strong_policy)
        summary = analyzer.get_summary()

        assert summary['critical_count'] == 0
        assert summary['score'] >= 80

    def test_complexity_disabled_critical(self):
        """Complessità disabilitata è critica"""
        policy = {"complexity_enabled": False}

        analyzer = PolicyAnalyzer()
        analyzer._check_complexity(False)

        assert any(
            c.risk_level == RiskLevel.CRITICAL
            for c in analyzer.checks
        )

    def test_password_never_expires_critical(self):
        """max_password_age_days=0 è critico"""
        analyzer = PolicyAnalyzer()
        analyzer._check_max_age(0)

        assert any(
            c.risk_level == RiskLevel.CRITICAL
            for c in analyzer.checks
        )

    def test_lockout_disabled_critical(self):
        """lockout_threshold=0 è critico"""
        analyzer = PolicyAnalyzer()
        analyzer._check_lockout_threshold(0)

        assert any(
            c.risk_level == RiskLevel.CRITICAL
            for c in analyzer.checks
        )


class TestUserAuditor:
    """Test per UserAuditor"""

    def _create_filetime(self, days_ago: int) -> int:
        """Crea FILETIME per X giorni fa"""
        dt = datetime.now() - timedelta(days=days_ago)
        delta = dt - FILETIME_EPOCH
        return int(delta.total_seconds() * 10000000)

    def test_password_never_expires_detected(self):
        """Rileva flag password never expires"""
        users = [{
            "dn": "CN=Test,DC=domain,DC=local",
            "attributes": {
                "sAMAccountName": "test.user",
                "displayName": "Test User",
                # 66048 = NORMAL_ACCOUNT (512) + DONT_EXPIRE_PASSWORD (65536)
                "userAccountControl": 66048,
                "pwdLastSet": self._create_filetime(30),
                "lastLogonTimestamp": self._create_filetime(5),
            }
        }]

        auditor = UserAuditor()
        issues = auditor.audit_users(users)

        assert len(issues) > 0
        assert any(i.issue_type == "PASSWORD_NEVER_EXPIRES" for i in issues)

    def test_password_not_required_detected(self):
        """Rileva flag password not required"""
        users = [{
            "dn": "CN=Test,DC=domain,DC=local",
            "attributes": {
                "sAMAccountName": "test.user",
                "displayName": "Test User",
                # 544 = NORMAL_ACCOUNT (512) + PASSWD_NOTREQD (32)
                "userAccountControl": 544,
                "pwdLastSet": self._create_filetime(30),
                "lastLogonTimestamp": self._create_filetime(5),
            }
        }]

        auditor = UserAuditor()
        issues = auditor.audit_users(users)

        assert any(i.issue_type == "PASSWORD_NOT_REQUIRED" for i in issues)
        assert any(i.risk_level == UserRisk.CRITICAL for i in issues)

    def test_inactive_user_detected(self):
        """Rileva utenti inattivi"""
        users = [{
            "dn": "CN=Test,DC=domain,DC=local",
            "attributes": {
                "sAMAccountName": "inactive.user",
                "displayName": "Inactive User",
                "userAccountControl": 512,  # NORMAL_ACCOUNT
                "pwdLastSet": self._create_filetime(100),
                "lastLogonTimestamp": self._create_filetime(100),  # 100 giorni fa
            }
        }]

        auditor = UserAuditor(inactive_days=90)
        issues = auditor.audit_users(users)

        assert any(i.issue_type == "INACTIVE_ACCOUNT" for i in issues)

    def test_disabled_users_skipped(self):
        """Account disabilitati non generano warning su password"""
        users = [{
            "dn": "CN=Disabled,DC=domain,DC=local",
            "attributes": {
                "sAMAccountName": "disabled.user",
                "displayName": "Disabled User",
                # 514 = NORMAL_ACCOUNT (512) + ACCOUNTDISABLE (2)
                "userAccountControl": 514,
                "pwdLastSet": 0,
            }
        }]

        auditor = UserAuditor()
        issues = auditor.audit_users(users)
        summary = auditor.get_summary()

        assert summary['disabled_users'] == 1
        assert len([i for i in issues if i.username == "disabled.user"]) == 0

    def test_summary_statistics(self):
        """Verifica statistiche riepilogative"""
        users = [
            {
                "dn": "CN=User1,DC=domain,DC=local",
                "attributes": {
                    "sAMAccountName": "user1",
                    "userAccountControl": 512,
                    "pwdLastSet": self._create_filetime(5),
                    "lastLogonTimestamp": self._create_filetime(5),
                }
            },
            {
                "dn": "CN=User2,DC=domain,DC=local",
                "attributes": {
                    "sAMAccountName": "user2",
                    "userAccountControl": 514,  # Disabled
                    "pwdLastSet": self._create_filetime(5),
                }
            },
        ]

        auditor = UserAuditor()
        auditor.audit_users(users)
        summary = auditor.get_summary()

        assert summary['total_users'] == 2
        assert summary['active_users'] == 1
        assert summary['disabled_users'] == 1


class TestIntegration:
    """Test di integrazione"""

    def test_policy_summary_format(self):
        """Verifica formato riepilogo policy"""
        policy = {
            "min_password_length": 8,
            "complexity_enabled": True,
            "password_history": 6,
            "max_password_age_days": 90,
            "lockout_threshold": 5,
        }

        analyzer = PolicyAnalyzer()
        analyzer.analyze(policy)
        summary = analyzer.get_summary()

        assert 'total_checks' in summary
        assert 'critical_count' in summary
        assert 'warning_count' in summary
        assert 'ok_count' in summary
        assert 'score' in summary
        assert 'assessment' in summary

    def test_user_summary_format(self):
        """Verifica formato riepilogo utenti"""
        auditor = UserAuditor()
        auditor.audit_users([])
        summary = auditor.get_summary()

        assert 'total_users' in summary
        assert 'active_users' in summary
        assert 'critical_count' in summary
        assert 'score' in summary
        assert 'assessment' in summary


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
