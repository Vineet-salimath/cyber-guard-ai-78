# Quick Start Guide - Cybersecurity News Aggregator

## 🚀 Get Up and Running in 5 Minutes

### Step 1: Get Your API Key (1 minute)

1. Go to [newsapi.org](https://newsapi.org)
2. Sign up for free account
3. Copy your API key

### Step 2: Configure Backend (1 minute)

1. Create `backend/.env` file:
```
NEWS_API_KEY=your_api_key_here
FLASK_ENV=production
```

2. Install Python dependencies:
```bash
cd backend
pip install -r requirements.txt
```

### Step 3: Build Frontend (1 minute)

```bash
npm install
npm run build
```

### Step 4: Start Backend (1 minute)

```bash
# Terminal 1
python backend/app.py
# You should see: "Running on http://localhost:5000"
```

### Step 5: Start Frontend (1 minute)

```bash
# Terminal 2
npm run dev
# You should see: "Local: http://localhost:8081"
```

## 🌐 Access the App

Open your browser:
```
http://localhost:8081/
```

Click **"Blogs"** in the left sidebar to see news articles!

## 📰 What You'll See

1. **Categories** - 8 cybersecurity topics
2. **Articles** - News from around the web
3. **Filters** - Click category buttons to filter
4. **Auto-refresh** - 5-minute countdown
5. **Dark Mode** - Toggle in header

## 🎯 Basic Features

### Viewing Articles
- Click article card to read full story
- See source, date, and summary
- Articles update every 5 minutes automatically

### Filtering by Category
1. Articles show from "cybersecurity" by default
2. Click other category buttons to filter:
   - Data Breach
   - Ransomware
   - Vulnerability
   - Compliance
   - Fraud
   - Security Tools
   - Cloud Security

### Dark Mode
- Click moon icon in header
- Your preference is saved
- Applies to entire page

### Manual Refresh
- Click "Refresh" button anytime
- Articles update from NewsAPI
- Countdown resets to 5 minutes

## 🔍 Verify It's Working

**Check Backend is Running:**
```powershell
# Windows PowerShell
(Invoke-WebRequest -Uri "http://localhost:5000/api/news/categories").Content | ConvertFrom-Json
```

Should show 8 categories like:
```
[
  "cybersecurity",
  "data-breach",
  "ransomware",
  ...
]
```

**Check Frontend is Running:**
- Go to `http://localhost:8081/`
- Click "Blogs" tab
- Should see articles loading

## ❌ Troubleshooting

### "Cannot connect to server"
```bash
# Check backend is running
# Terminal 1 should show: Running on http://localhost:5000
# If not, run: python backend/app.py
```

### "Articles not showing"
1. Check API key in `backend/.env`
2. Check internet connection
3. Check browser console for errors (F12)
4. Restart backend

### "Port already in use"
```bash
# Backend on different port:
python backend/app.py --port 5001

# Then update frontend API calls to use 5001
```

### "npm command not found"
```bash
# Install Node.js from nodejs.org
# Then try npm again
```

### "Python not found"
```bash
# Install Python from python.org
# Then try python again
```

## 📁 File Structure

```
cyber-guard-ai-78/
├── backend/
│   ├── app.py           (Flask server)
│   ├── news_manager.py  (News fetching)
│   ├── requirements.txt  (Python packages)
│   ├── .env             (Your API key)
│   └── data/            (News cache)
├── src/
│   ├── pages/Blog.tsx   (Main component)
│   └── components/      (UI components)
├── dist/                (Built frontend)
└── package.json         (JavaScript packages)
```

## 📝 Common Tasks

### Update API Key
Edit `backend/.env`:
```
NEWS_API_KEY=new_key_here
```
Restart backend

### Change Refresh Interval
Edit `src/pages/Blog.tsx`, find:
```javascript
const REFRESH_INTERVAL = 5 * 60 * 1000; // 5 minutes
```
Change 5 to your desired minutes

### Add New Category
1. Edit `backend/news_manager.py`, add to `CATEGORIES`
2. Edit `src/pages/Blog.tsx`, add to `CATEGORY_LABELS`
3. Restart both

### Clear News Cache
Delete `backend/data/cache.db`, then restart backend

## 🎮 Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `R` | Refresh articles |
| `?` | Show help |
| `Esc` | Close article |

## 📊 Performance Targets

- **Page Load**: < 2 seconds
- **Category Switch**: < 500ms
- **Auto-Refresh**: < 3 seconds
- **Dark Mode Toggle**: Instant

## 🔐 Security Notes

✅ API key stays on backend only
✅ No secrets in frontend code
✅ All URLs validated
✅ Error messages sanitized
✅ CORS properly configured

## 📞 Need Help?

1. Check the **Blogs** tab is visible
2. Verify backend running: `python backend/app.py`
3. Check `backend/.env` has valid API key
4. Open browser console (F12) for errors
5. Check logs in terminal

## 🎉 You're Done!

Your cybersecurity news aggregator is live! 

**Next Steps:**
- Explore different categories
- Test dark mode
- Watch auto-refresh countdown
- Read real security news

---

**Questions?** Check [CYBERSECURITY_NEWS_AGGREGATOR_COMPLETE.md](CYBERSECURITY_NEWS_AGGREGATOR_COMPLETE.md) for detailed docs.

**Status**: ✅ Ready to Use!
