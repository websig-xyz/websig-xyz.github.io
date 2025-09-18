#!/bin/bash

# Replace YOUR_USERNAME with your actual GitHub username
GITHUB_USERNAME="YOUR_USERNAME"
REPO_NAME="websig-recovery"

echo "🚀 Deploying WebSig Recovery to GitHub Pages"
echo "============================================"
echo ""
echo "Make sure you've created a repository at:"
echo "https://github.com/$GITHUB_USERNAME/$REPO_NAME"
echo ""
echo "Press Enter to continue or Ctrl+C to cancel..."
read

# Add remote and push
git remote add origin "https://github.com/$GITHUB_USERNAME/$REPO_NAME.git"
git branch -M main
git push -u origin main

echo ""
echo "✅ Code pushed to GitHub!"
echo ""
echo "Now follow these steps:"
echo "1. Go to https://github.com/$GITHUB_USERNAME/$REPO_NAME/settings/pages"
echo "2. Under 'Source', select 'Deploy from a branch'"
echo "3. Choose 'main' branch and '/ (root)' folder"
echo "4. Click 'Save'"
echo ""
echo "Your recovery tool will be available at:"
echo "https://$GITHUB_USERNAME.github.io/$REPO_NAME/"
echo ""
echo "For custom domain (recovery.websig.xyz):"
echo "1. Create a CNAME file with 'recovery.websig.xyz'"
echo "2. Configure DNS CNAME: recovery -> $GITHUB_USERNAME.github.io"
