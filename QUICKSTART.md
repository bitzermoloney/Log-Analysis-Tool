# Quick Start Guide

## 🚀 Get Started in 30 Seconds

### 1. Try the Demo
```bash
python Src/main.py --demo
```
This generates sample security events and creates an interactive HTML report in `reports/security_report.html`

### 2. Analyze Real Logs
```bash
# Analyze SSH logs
python Src/main.py --ssh /var/log/auth.log

# Analyze multiple log sources
python Src/main.py \
  --ssh /var/log/auth.log \
  --apache /var/log/apache2/access.log \
  --firewall /var/log/firewall.log
```

### 3. View Results
- **HTML Report**: Open `reports/security_report.html` in your browser
- **Timeline**: Read `reports/timeline.txt` in any text editor
- **Summary**: View the printed summary in terminal

## 📊 What You Get

✅ **Threat Detection**
- Failed login attempts
- Brute force attacks (5+ failures in 300 seconds)
- Suspicious IP scoring (0-2 none, 3-6 caution, 7+ critical)

✅ **Interactive Report**
- Summary statistics
- Risk-scored IP addresses
- Events over time chart
- Events by type and severity breakdowns
- Complete timeline of all security events

✅ **Multiple Log Formats**
- SSH authentication logs
- Apache access/error logs  
- Firewall logs (iptables, pfSense)
- Windows event logs

## 📖 Full Documentation

For detailed usage, log format examples, and advanced options, see [USAGE.md](USAGE.md)

## ⚙️ Requirements

- Python 3.7+
- Jinja2 (for report generation)
- Chart.js (loaded from CDN, no install needed)

Install dependencies:
```bash
pip install jinja2
```

## 🎯 Next Steps

1. Run the demo: `python Src/main.py --demo`
2. Test with samples: `python Src/main.py --ssh data/logs/sample_ssh.log`
3. Point to real logs and analyze
4. Open the HTML report in your browser
5. Share findings with your team

---

**Need help?** Check [USAGE.md](USAGE.md) for comprehensive documentation
