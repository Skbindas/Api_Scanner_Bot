# API Scanner Bot 🔍

## Overview / परियोजना विवरण

API Scanner Bot is a powerful tool designed to analyze websites, detect API endpoints, and assess security vulnerabilities. It provides comprehensive information about network requests, storage data, and potential security risks.

API स्कैनर बॉट एक शक्तिशाली टूल है जो वेबसाइटों का विश्लेषण करने, API एंडपॉइंट्स का पता लगाने और सुरक्षा कमजोरियों का आकलन करने के लिए डिज़ाइन किया गया है। यह नेटवर्क अनुरोधों, स्टोरेज डेटा और संभावित सुरक्षा जोखिमों के बारे में व्यापक जानकारी प्रदान करता है।

## Features / विशेषताएं

- API endpoint detection / API एंडपॉइंट की पहचान
- Network request monitoring / नेटवर्क अनुरोध निगरानी
- Security vulnerability scanning / सुरक्षा कमजोरी स्कैनिंग
- Local & session storage analysis / लोकल और सेशन स्टोरेज विश्लेषण
- Cookie analysis / कुकी विश्लेषण
- AI-powered phishing detection / AI-संचालित फ़िशिंग पहचान

## Prerequisites / आवश्यकताएं

1. Python 3.7 or higher / पायथन 3.7 या उच्चतर
2. Shodan API Key / शोडन API की
3. pip (Python package installer) / पिप (पायथन पैकेज इंस्टॉलर)

## Installation / इंस्टालेशन

1. Clone the repository / रिपॉजिटरी को क्लोन करें:
```bash
git clone https://github.com/skbindas/api_scanner_bot.git
cd api_scanner_bot
```

2. Install required packages / आवश्यक पैकेज इंस्टॉल करें:
```bash
pip install -r requirements.txt
```

3. Configure Shodan API Key / शोडन API की कॉन्फ़िगर करें:
   - Copy `.env.example` to `.env` / `.env.example` को `.env` में कॉपी करें
   - Replace `your_shodan_api_key_here` with your Shodan API key / `your_shodan_api_key_here` को अपनी Shodan API की से बदलें

## Usage / उपयोग

1. Start the application / एप्लिकेशन शुरू करें:
```bash
python api_scanner_bot.py
```

2. Enter the website URL in the input field / इनपुट फ़ील्ड में वेबसाइट URL दर्ज करें

3. Click "Scan Website" to analyze API endpoints and network data / API एंडपॉइंट्स और नेटवर्क डेटा का विश्लेषण करने के लिए "Scan Website" पर क्लिक करें

4. Click "Check Security" to perform vulnerability scanning / कमजोरी स्कैनिंग करने के लिए "Check Security" पर क्लिक करें

## Results / परिणाम

The scan results are saved in the following directories / स्कैन परिणाम निम्नलिखित डायरेक्टरी में सहेजे जाते हैं:

- `scan_results/network_logs/`: Network request logs / नेटवर्क अनुरोध लॉग
- `scan_results/api_info/`: Detected API endpoints / पता लगाए गए API एंडपॉइंट्स
- `scan_results/storage_data/`: Local and session storage data / लोकल और सेशन स्टोरेज डेटा
- `scan_results/security_findings/`: Security vulnerability reports / सुरक्षा कमजोरी रिपोर्ट

## Important Notes / महत्वपूर्ण नोट्स

- Ensure you have a valid Shodan API key / सुनिश्चित करें कि आपके पास वैध शोडन API की है
- Use the tool responsibly and only on websites you have permission to scan / टूल का जिम्मेदारी से उपयोग करें और केवल उन वेबसाइटों पर स्कैन करें जिनकी आपको अनुमति है
- Some websites may block automated scanning / कुछ वेबसाइटें स्वचालित स्कैनिंग को ब्लॉक कर सकती हैं

## Troubleshooting / समस्या समाधान

1. If the scan fails / यदि स्कैन विफल हो जाता है:
   - Check your internet connection / अपना इंटरनेट कनेक्शन जांचें
   - Verify the website URL is correct / सत्यापित करें कि वेबसाइट URL सही है
   - Ensure Shodan API key is valid / सुनिश्चित करें कि शोडन API की वैध है

2. If no results appear / यदि कोई परिणाम नहीं दिखता:
   - Try scanning a different website / एक अलग वेबसाइट स्कैन करने का प्रयास करें
   - Check if the website is accessible / जांचें कि वेबसाइट एक्सेसिबल है
   - Verify all required packages are installed / सत्यापित करें कि सभी आवश्यक पैकेज इंस्टॉल हैं

## Support / सहायता

For issues and queries, please create an issue in the repository.
समस्याओं और प्रश्नों के लिए, कृपया रिपॉजिटरी में एक इश्यू बनाएं।