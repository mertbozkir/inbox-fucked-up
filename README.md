# 📧 Inbox-Fucked-Up

<img width="920" alt="image" src="https://github.com/user-attachments/assets/c9c921a1-b7d3-46f6-9375-819e18a6f62f" />


**Take back control of your inbox by finding out who's flooding it with crap!**

A simple script to analyze your `.mbox` email exports and show you what to unsubscribe from.

## 🏁 Quick Start

```bash
# Install
git clone https://github.com/yourusername/inbox-fucked-up.git
cd inbox-fucked-up
pip install -e .

# Run
python src/main.py --mbox path/to/your/emails.mbox
```

## 📋 Common Commands

```bash
# Show all options
python src/main.py --help

# Analyze last 90 days only
python src/main.py --period 90

# Skip duplicate emails
python src/main.py --no-duplicates

# Save results to CSV
python src/main.py --export results.csv
```

## 📥 Getting Your .mbox File

<details>
<summary><b>Gmail</b></summary>

1. Go to [Google Takeout](https://takeout.google.com/)
2. Select only "Mail" and download
</details>

<details>
<summary><b>Other Email Providers</b></summary>

- **Apple Mail**: Mailbox > Export Mailbox
- **Outlook**: Use ImportExport tool > Export to file
- **Thunderbird**: Use ImportExportTools NG add-on
</details>

## 🧹 Tips

1. Start with the highest-volume senders in the "Unsubscribe Candidates" list
2. Look for multiple emails from the same domain
3. Re-run the analysis periodically to see your improvement

---

*Built with Python and pure rage against email overload.*
