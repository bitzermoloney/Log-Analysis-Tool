#!/bin/bash
echo "🔍 VERIFYING LOG ANALYSIS TOOL INSTALLATION..."
echo ""

# Check Python version
python_version=$(python --version 2>&1)
echo "✅ Python: $python_version"

# Check required packages
if python -c "import jinja2" 2>/dev/null; then
    echo "✅ Jinja2: $(python -c 'import jinja2; print(jinja2.__version__)')"
else
    echo "❌ Jinja2: NOT INSTALLED (run: pip install jinja2)"
fi

# Check project structure
echo ""
echo "📁 Project Structure:"
for file in Src/main.py Src/analyser.py Src/timeline.py Src/reports.py \
            Src/Parsers/ssh.py Src/Parsers/apache.py Src/Parsers/firewall.py Src/Parsers/windows.py \
            Src/Detection/failed_logins.py Src/Detection/brute_force.py Src/Detection/suspicious_IP.py \
            Templates/report.html QUICKSTART.md USAGE.md README.md PROJECT_COMPLETION.md; do
    if [ -f "$file" ]; then
        echo "   ✅ $file"
    else
        echo "   ❌ $file (MISSING)"
    fi
done

echo ""
echo "🧪 Sample Data:"
for file in data/logs/sample_ssh.log data/logs/sample_apache.log data/logs/sample_firewall.log; do
    if [ -f "$file" ]; then
        lines=$(wc -l < "$file")
        echo "   ✅ $file ($lines entries)"
    else
        echo "   ❌ $file (MISSING)"
    fi
done

echo ""
echo "🚀 Quick Test:"
python Src/main.py --demo 2>&1 | tail -3

echo ""
echo "✨ Installation verified!"
echo ""
echo "📚 Get started:"
echo "   python Src/main.py --demo              # Run demo"
echo "   python Src/main.py --ssh <logfile>    # Analyze logs"
echo "   python Src/main.py --help              # Show help"
