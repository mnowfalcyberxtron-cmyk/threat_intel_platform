# 🐔 Al-Ansar Telegram Bot Integration Guide

This guide details how to create your private Telegram bot, configure webhook communications with the Al-Ansar Chicken Shop Management System, and begin recording sales directly from your phone.

---

## 📅 Step 1: Create Your Telegram Bot
1. Open the Telegram app on your mobile device or desktop.
2. Search for the official account **@BotFather** (it has a blue verification checkmark) and start a conversation.
3. Send the command: `/newbot`
4. Follow the instructions from BotFather:
   * **Choose a display name** for your bot, e.g., `Al-Ansar Chicken Shop`
   * **Choose a unique username** ending in "bot", e.g., `AlAnsarChickenBot` or `AlAnsarShopBot`
5. Once complete, BotFather will message you a **HTTP API Token** (e.g., `7123456789:AAH-Xxxxxxxxxxxxx_xxxxxxxxxxxx_xxx`).
6. **Copy this Token** — you will paste this into the Al-Ansar settings page.

---

## 🆔 Step 2: Retrieve Your Telegram Chat ID
To ensure that only authorized workers can send commands and record sales, the bot enforces chat-level validation.
1. In Telegram, search for the official **@userinfobot** or **@RawDataBot**.
2. Start the bot. It will instantly reply with your personal **Chat ID** (e.g., `987654321` - a 9 or 10-digit number).
3. **Copy this Chat ID** — you will paste this into the Al-Ansar settings page to secure your terminal.

---

## ⚙️ Step 3: Configure Al-Ansar Admin Settings
1. Open the Al-Ansar application in your browser.
2. Log in using the predefined credentials:
   * **Username:** `admin`
   * **Password:** `ansar`
3. Click on the **Admin Settings** tab or gear icon in the navigation header.
4. Input your retrieved credentials:
   * **Telegram Bot Token:** Paste the API Token from Step 1.
   * **Telegram Chat ID:** Paste the 9/10-digit number from Step 2.
   * **Daily Report Time:** Select when you want the automated evening ledger report (e.g., `21:00`).
   * **Stock Alert Level:** Set the critical threshold for low stock alerts (e.g., `25` kg).
   * **Conversion Ratio:** Enter your Live-to-Cleaned ratio (e.g., `1.50` means 1.50 kg live converts to 1.00 kg cleaned).
5. Click **Save Settings**. The application will automatically communicate with Telegram's servers to register its webhook endpoints!

---

## 💬 Step 4: Start Recording Sales
Open a conversation with your newly created Telegram bot and click `/start`. You are now ready to record transactions:

### Option A: Send a Sale Amount
Type any number. The bot converts the amount to weight sold based on the configured selling rate:
* Message: `150`
* Calculation: `₹150 ÷ ₹250/kg = 0.600 kg`
* Response: `✅ Sale Recorded. Amount: ₹150 | Weight Sold: 0.600 kg | Stock Remaining: 119.7 kg`

### Option B: Send a Specific Weight
Type any number followed by `kg` or `g`. The bot will calculate the bill amount based on the rate:
* Message: `1.5kg`
* Calculation: `1.5 kg * ₹250/kg = ₹375`
* Response: `✅ Sale Recorded. Amount: ₹375 | Weight Sold: 1.500 kg | Stock Remaining: 118.2 kg`

### Option C: Use Quick Action Buttons
The bot automatically shows a touch-friendly custom keyboard with quick prices:
* `₹50`, `₹100`, `₹150`, `₹200`, `₹250`, `₹300`, `₹500`
* `1kg`, `2kg`
* Simply tap any button to record the transaction instantly!

---

## 📊 Step 5: Automated Evening Reports
Every day at the configured time, or by sending the `/report` command to the bot, Al-Ansar compiles all metrics (Today's revenue, stock, expenses, and gross/net profit margin) and pushes a formatted PDF/HTML dashboard report directly to your Telegram chat.
