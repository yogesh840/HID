# HID Guardian - Cloud Deployment

## Streamlit Cloud Deployment

### Step 1: Push to GitHub
1. Create a new repository on GitHub
2. Upload these files:
   - app.py
   - requirements.txt
   - README.md

### Step 2: Deploy on Streamlit Cloud
1. Go to https://share.streamlit.io/
2. Sign in with GitHub
3. Click "New app"
4. Select your repository
5. Main file path: `app.py`
6. Click "Deploy"

Your app will be live in ~2 minutes at a URL like:
`https://[your-username]-hid-guardian.streamlit.app`

## Local Testing
```bash
pip install -r requirements.txt
streamlit run app.py

