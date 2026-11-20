# KMJ OmniDesk Support Runbook

## Purpose

This runbook defines support procedures and recovery paths for KMJ OmniDesk users. Required for M14 gate: `support_and_recovery_path_defined`.

---

## Support Tiers

### Tier 1: Self-Service Recovery

**User can resolve without contacting support:**

| Issue | Resolution |
|-------|------------|
| App won't launch | Delete `%LOCALAPPDATA%\kmj-omnidesk` and relaunch |
| Stuck session | Task Manager → End Task → Relaunch |
| Connection failed | Check firewall allows UDP 3478, TCP 443 |
| Black screen | Settings → Quality → Lower bandwidth profile |

### Tier 2: Support Ticket

**Escalate to support@kmjtechno.com:**

| Issue | Diagnostic Data Required |
|-------|-------------------------|
| Session drops repeatedly | `logs\session_*.jsonl` + network profile |
| High latency complaint | `logs\performance_*.json` + topology diagram |
| Permission denied errors | Screenshot + session ID + user role |

### Tier 3: Engineering Escalation

**Escalate to engineering with:**

- Reproduction steps
- Session logs (last 24 hours)
- Network capture (Wireshark .pcap if relay involved)
- Exact build version from Settings → About

---

## Recovery Procedures

### Session Recovery

1. User reconnects → session state machine restores last known state
2. If state mismatch → full refresh requested from host
3. If host unavailable → show "Device offline" with retry option

### Data Recovery

- **Clipboard sync**: No persistent storage; lost on disconnect
- **File transfer**: Resume from last checkpoint (stored in `%LOCALAPPDATA%\kmj-omnidesk\transfers\`)
- **Session history**: Retained 30 days in user account

### Rollback Procedure

If release causes regressions:

1. Disable update metadata in `evidence/release/beta.json`
2. Set `minimum_client_version` to prior working version
3. Publish rollback notice to support channel
4. Re-open investigation ticket

---

## Contact Points

| Role | Contact | Escalation Trigger |
|------|---------|-------------------|
| Support Lead | support@kmjtechno.com | Tier 2 tickets |
| Engineering | engineering@kmjtechno.com | Tier 3, security incidents |
| Legal | legal@kmjtechno.com | License disputes, compliance |

---

## SLA Targets

| Plan | Response Time | Resolution Target |
|------|---------------|-------------------|
| Personal | 48 hours | Best effort |
| Professional | 24 hours | 5 business days |
| Business | 8 hours | 3 business days |
| Enterprise | 4 hours | 1 business day |

---

## Signoff

| Role | Name | Date | Status |
|------|------|------|--------|
| Support Lead | _pending_ | _pending_ | pending |
| Engineering Lead | _pending_ | _pending_ | pending |
