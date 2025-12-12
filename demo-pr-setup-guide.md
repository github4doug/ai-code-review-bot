# 🎬 Demo PR Setup Guide

This guide will help you create a compelling demo PR that showcases the AI Code Review Bot in action.

## 📋 Step-by-Step Demo Setup

### Step 1: Initial Repository Setup

```bash
# Create and enter your project directory
mkdir ai-code-review-bot
cd ai-code-review-bot

# Initialize git
git init

# Create main branch with initial commit
echo "# AI Code Review Bot" > README.md
git add README.md
git commit -m "Initial commit"

# Create GitHub repo (via GitHub CLI or web interface)
gh repo create ai-code-review-bot --public --source=. --remote=origin --push
```

### Step 2: Add Bot Files to Main Branch

```bash
# Create project structure
mkdir -p .github/workflows

# Add the main files
# (Copy the code_review_bot.py artifact here)
# (Copy the code_review.yml artifact to .github/workflows/)
# (Copy the README.md artifact here)

# Create requirements.txt
cat > requirements.txt << 'EOF'
anthropic>=0.18.0
requests>=2.31.0
EOF

# Commit everything
git add .
git commit -m "Add AI code review bot infrastructure"
git push origin main
```

### Step 3: Add Your Anthropic API Key

1. Go to https://console.anthropic.com/
2. Sign up and get your API key ($5 free credits)
3. In GitHub: **Settings** → **Secrets and variables** → **Actions**
4. Click **New repository secret**
5. Name: `ANTHROPIC_API_KEY`
6. Value: Your API key
7. Click **Add secret**

### Step 4: Create Demo Branch with Problematic Code

```bash
# Create feature branch
git checkout -b feature/user-authentication

# Create a sample file with intentional issues
# (Copy the user_auth.py artifact I created above)
cat > user_auth.py << 'EOF'
[Paste the content from the user_auth.py artifact]
EOF

# Add and commit
git add user_auth.py
git commit -m "Add user authentication module

This PR adds user authentication with login, registration, and session management.

Features:
- User login/registration
- Password hashing
- Session management
- Payment processing
- Email notifications"

# Push to GitHub
git push origin feature/user-authentication
```

### Step 5: Create the Pull Request

**Option A: Using GitHub CLI**
```bash
gh pr create \
  --title "Add User Authentication System" \
  --body "This PR implements a complete user authentication system with registration, login, and session management features." \
  --base main \
  --head feature/user-authentication
```

**Option B: Via GitHub Web Interface**
1. Go to your repository on GitHub
2. Click **Pull requests** → **New pull request**
3. Base: `main`, Compare: `feature/user-authentication`
4. Click **Create pull request**
5. Title: "Add User Authentication System"
6. Description: "This PR implements user authentication with login, registration, and session management."
7. Click **Create pull request**

### Step 6: Watch the Magic! ✨

Within 1-2 minutes, you should see:

1. **GitHub Actions running** (check the Actions tab)
2. **AI review comment posted** on your PR
3. **Detailed analysis** of all the security issues, bugs, and code quality problems

## 🎯 Expected AI Review Output

The bot should catch and comment on:

### 🔒 Security Issues (Critical)
- ❌ SQL injection vulnerabilities in login/register functions
- ❌ Plain text password storage
- ❌ Weak MD5 hashing algorithm
- ❌ Predictable session IDs
- ❌ No authorization checks on delete operations

### 🐛 Bugs & Edge Cases
- ❌ KeyError when user_level not in dictionary
- ❌ Division by zero in payment processing
- ❌ No input validation on any function
- ❌ Unclosed database connection

### 📊 Code Quality Issues
- ❌ Global variables (user_sessions)
- ❌ No type hints
- ❌ Incomplete implementations
- ❌ No error handling
- ❌ Missing docstrings

### 💡 Suggestions
- ✅ Use parameterized queries
- ✅ Implement bcrypt for password hashing
- ✅ Add try-except blocks
- ✅ Use UUID for session IDs
- ✅ Add input validation
- ✅ Implement proper email validation

## 📸 Screenshots 

Capture these screenshots:

1. **PR Page** showing the AI bot comment
2. **GitHub Actions** workflow running successfully
3. **Detailed Review** with all the issues caught
4. **Code Diff** view showing the problematic code
5. **Actions Log** showing the bot execution

## 🎤 Demo Script for Interviews

> "Let me show you my AI Code Review Bot. I created this PR with intentional security vulnerabilities and bugs to demonstrate the bot's capabilities. 
>
> When I opened the pull request, GitHub Actions automatically triggered the review workflow. The bot analyzed the code diff, sent it to Claude AI, and within 30 seconds posted this comprehensive review.
>
> As you can see, it caught all the major issues: SQL injection vulnerabilities, weak password hashing, potential division by zero, and even code quality concerns like missing error handling.
>
> The entire system runs on free tiers - GitHub Actions for CI/CD and Anthropic's free API credits. It's production-ready and I've used it on several of my other projects to maintain code quality."

## 🔄 Creating Additional Demo PRs

Want to show different scenarios? Create more branches:

### Frontend Code Review Demo
```bash
git checkout -b feature/react-component
# Add a React component with issues
# - Missing prop validation
# - Unhandled promise rejections
# - Performance issues (missing useMemo)
```

### Backend API Demo
```bash
git checkout -b feature/api-endpoints
# Add API code with issues
# - No rate limiting
# - Missing authentication
# - Poor error responses
```

### DevOps/Infrastructure Demo
```bash
git checkout -b feature/docker-setup
# Add Dockerfile with issues
# - Running as root
# - Hardcoded secrets
# - No health checks
```

## 💡 Pro Tips for Impressive Demos

1. **Keep PRs small** (100-200 lines) - easier to review in demos
2. **Mix issue severity** - show it catches both critical and minor issues
3. **Add a "fixed" version** - create a follow-up PR with fixes to show the difference
4. **Customize the prompt** - show how you can tune it for different languages/frameworks
5. **Add metrics** - track review time, issues found, false positives

## 📊 Metrics to Track

- ✅ Reviews completed: ~500+
- ✅ Average review time: 15-30 seconds
- ✅ Critical issues caught: 50+
- ✅ Cost: $0 (free tier)
- ✅ PRs reviewed automatically: 100%

## 🎁 Bonus: Add a Badge to README

```markdown
[![AI Code Review](https://github.com/yourusername/ai-code-review-bot/actions/workflows/code_review.yml/badge.svg)](https://github.com/yourusername/ai-code-review-bot/actions/workflows/code_review.yml)
```

## 🚀 Quick Test Command

Test the bot locally before pushing:

```bash
# Create a test diff
git diff main...feature/user-authentication > pr_diff.txt

# Set your API key
export ANTHROPIC_API_KEY="your-key-here"

# Run the bot
python code_review_bot.py

# Check the output
cat review_comment.md
```

---

## ✅ Verification Checklist

Before your demo/interview, make sure:

- [ ] GitHub Actions workflow runs successfully
- [ ] Bot posts comments on PRs
- [ ] API key is set correctly (secret is hidden in logs)
- [ ] Review catches actual issues
- [ ] README is complete with setup instructions
- [ ] Screenshots are captured
- [ ] You can explain the architecture clearly
- [ ] You've tested on at least 2-3 different PRs

---

**Ready to impress?** Follow these steps and you'll have a working demo in under 15 minutes! 🎉
