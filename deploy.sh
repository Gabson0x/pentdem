#!/bin/bash
set -e

echo "🚀 AI Pentest Daemon v2.0 - Deployment"
echo "========================================"
echo ""

# Check for .env
if [ ! -f .env ]; then
    echo "❌ .env file not found! Copy .env.example and add your API keys."
    echo "   cp .env.example .env"
    exit 1
fi

# Install Python dependencies
echo "📦 Installing Python dependencies..."
pip install -r requirements.txt

# Create required directories
echo "📁 Creating directories..."
mkdir -p data reports

# Check for optional security tools
echo ""
echo "🔧 Optional tools check:"
for tool in subfinder httpx katana ffuf nuclei curl; do
    if command -v $tool &> /dev/null; then
        echo "   ✅ $tool installed"
    else
        echo "   ⚠️  $tool not found (recon/hunt features limited)"
    fi
done

echo ""
echo "🔍 Running mock test..."
python cli.py example.com quick hackerone --mock

echo ""
echo "✅ Deployment verified!"
echo ""
echo "To start the API server:"
echo "   python main.py"
echo ""
echo "Or with Docker:"
echo "   ./deploy.sh"
exit 0
