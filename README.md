# 🤖 AI Code Review Bot

An automated code review bot powered by Claude AI that analyzes pull requests and provides intelligent feedback on security, bugs, code quality, and performance.

## ✨ Features

- 🔒 **Security Analysis**: Identifies potential vulnerabilities
- 🐛 **Bug Detection**: Catches edge cases and logic errors
- 📊 **Code Quality**: Checks style, readability, and best practices
- ⚡ **Performance Review**: Flags performance concerns
- 💡 **Smart Suggestions**: Provides actionable improvements with examples
- 🚀 **Zero Cost**: Runs on GitHub Actions free tier + Claude API free credits

## 🏗️ Architecture

```
┌─────────────┐      ┌──────────────┐      ┌─────────────┐
│   PR Event  │─────▶│GitHub Actions│─────▶│ Python Bot  │
└─────────────┘      └──────────────┘      └─────────────┘
                                                   │
                                                   ▼
                                            ┌─────────────┐
                                            │ Claude API  │
                                            └─────────────┘
                                                   │
                                                   ▼
                                            ┌─────────────┐
                                            │PR Comments  │
                                            └─────────────┘
```

## 🚀 Quick Start

### 1. Fork/Clone This Repository

```bash
git clone https://github.com/yourusername/ai-code-review-bot.git
cd ai-code-review-bot
```

### 2. Get Your Anthropic API Key

1. Go to [console.anthropic.com](https://console.anthropic.com/)
2. Sign up for free account ($5 free credits)
3. Generate an API key

### 3. Add Secret to GitHub

1. Go to your repository → **Settings** → **Secrets and variables** → **Actions**
2. Click **New repository secret**
3. Name: `ANTHROPIC_API_KEY`
4. Value: Your API key from step 2
5. Click **Add secret**

### 4. Project Structure

```
ai-code-review-bot/
├── .github/
│   └── workflows/
│       └── code_review.yml       # GitHub Actions workflow
├── code_review_bot.py            # Main bot script
├── requirements.txt              # Python dependencies
├── README.md                     # This file
└── examples/
    └── sample_pr_diff.txt        # Test diff file
```

### 5. Create Required Files

**requirements.txt:**
```
anthropic>=0.18.0
requests>=2.31.0
```

**Save both artifacts I created above:**
- `code_review_bot.py` (first artifact)
- `.github/workflows/code_review.yml` (second artifact)

### 6. Test Locally

```bash
# Install dependencies
pip install -r requirements.txt

# Set your API key
export ANTHROPIC_API_KEY="your-key-here"

# Create a test diff
echo "your code changes here" > pr_diff.txt

# Run the bot
python code_review_bot.py
```

### 7. Create a Test PR

1. Create a new branch: `git checkout -b test-review`
2. Make some code changes
3. Commit and push: `git push origin test-review`
4. Open a Pull Request on GitHub
5. Watch the bot automatically review your code! 🎉

## 📝 Example Review Output

```markdown
## 🤖 AI Code Review

### ✅ Positive Aspects
- Clean implementation of the calculation logic
- Good variable naming

### ⚠️ Potential Issues

**Line 13: Possible division by zero**
\`\`\`python
result = total / count  # What if count is 0?
\`\`\`

**Suggestion:**
\`\`\`python
result = total / count if count > 0 else 0
\`\`\`

### 🔒 Security Considerations
- No SQL injection risks detected
- Input validation looks good

### 💡 Code Quality Improvements
Consider adding type hints for better code documentation:
\`\`\`python
def calculate_total(items: list[dict]) -> float:
    ...
\`\`\`
```

## 🎯 Resume-Worthy Highlights

**Skills Demonstrated:**
- ✅ LLM API Integration (Anthropic Claude)
- ✅ CI/CD with GitHub Actions
- ✅ Python scripting and automation
- ✅ Git/GitHub workflows
- ✅ API authentication and secrets management
- ✅ Prompt engineering for code analysis
- ✅ Error handling and logging

## 🔧 Customization

### Adjust Review Focus

Edit the prompt in `code_review_bot.py`:

```python
prompt = f"""Review this code focusing on:
1. TypeScript best practices
2. React performance
3. Accessibility issues
... your custom criteria ...
"""
```

### Change AI Model

```python
model="claude-sonnet-4-20250514",  # Current: Fast & efficient
# model="claude-opus-4-20250514",  # Alternative: Most capable
```

### Add File Type Filtering

```yaml
# In .github/workflows/code_review.yml
on:
  pull_request:
    paths:
      - '**.py'
      - '**.js'
      - '**.ts'
```

## 💰 Cost Breakdown

- **GitHub Actions**: FREE (2,000 minutes/month for public repos)
- **Anthropic API**: FREE ($5 credits ≈ 500+ reviews)
- **Total Monthly Cost**: $0 for typical usage

## 🎓 Learning Resources

- [Claude API Documentation](https://docs.anthropic.com/)
- [GitHub Actions Tutorial](https://docs.github.com/en/actions)
- [Prompt Engineering Guide](https://docs.anthropic.com/en/docs/prompt-engineering)

## 🐛 Troubleshooting

**Bot doesn't comment on PR:**
- Check GitHub Actions logs
- Verify `ANTHROPIC_API_KEY` is set correctly
- Ensure workflow has `pull-requests: write` permission

**API errors:**
- Check API key is valid
- Verify you have remaining credits
- Check rate limits

**Review quality issues:**
- Adjust the prompt for more specific feedback
- Try different Claude models
- Limit diff size for better context

## 📈 Next Steps / Enhancements

- [ ] Add support for specific file types (Python, JavaScript, etc.)
- [ ] Integrate with ESLint/Pylint for automated fixes
- [ ] Add severity levels (critical, warning, suggestion)
- [ ] Store review history in database
- [ ] Add web dashboard for review analytics
- [ ] Support multiple LLM providers (OpenAI, Google, etc.)

## 🤝 Contributing

Feel free to open issues or submit pull requests to improve the bot!

## 📄 License

MIT License - feel free to use this in your portfolio!

---

**Built with:** Python 🐍 | Claude AI 🤖 | GitHub Actions ⚡

**Perfect for:** Portfolio projects, resume demos, learning LLM integration
