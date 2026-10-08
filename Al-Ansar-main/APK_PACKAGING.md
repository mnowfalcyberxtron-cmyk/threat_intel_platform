# 📱 Packaging Al-Ansar as an Installable Android APK

This document provides a step-by-step guide to compile and package your Al-Ansar Chicken Shop Management System into an **installable Android APK** using **CapacitorJS**.

---

## 🛠️ Prerequisites
To build the APK locally, make sure you have the following installed on your computer:
1. **Node.js** (v18 or higher)
2. **Android Studio** (includes Android SDK and Gradle build tools)
3. **Java Development Kit (JDK)** (v17 or higher)

---

## 🚀 Step-by-Step Compilation

### 1. Build the Production Web Code
Run the compilation command in your project directory:
```bash
npm run build
```
This compiles all TypeScript assets and bundles the React frontend into the `/dist` directory.

### 2. Install Capacitor Core & CLI
Add the Capacitor integration libraries as dev dependencies:
```bash
npm install @capacitor/core @capacitor/cli
```

### 3. Initialize Capacitor
Initialize Capacitor with the Al-Ansar app ID and branding details:
```bash
npx cap init AlAnsar "Al-Ansar" --web-dir=dist
```
* **App Name:** `Al-Ansar`
* **Package ID:** `com.al_ansar.management` (Your unique Android package name)

### 4. Add the Android Platform Module
Install the Capacitor Android bridge package and register it:
```bash
npm install @capacitor/android
npx cap add android
```
This creates an `/android` directory inside your project containing the native Android project structures.

### 5. Sync Web Assets to Android
Whenever you modify your frontend code and want to update the APK, sync the build folder:
```bash
npx cap sync
```

### 6. Compile the Installable APK
Open the project in Android Studio or build it directly from the terminal:

#### Method A: Build inside Android Studio (Recommended)
1. Launch Android Studio and select **Open**.
2. Navigate to your project folder and select the `/android` directory.
3. Wait for Gradle to finish indexing.
4. In the top navigation menu, click **Build > Build Bundle(s) / APK(s) > Build APK(s)**.
5. Android Studio will generate the debug APK. Click on the **"Locate"** popup to find the file `app-debug.apk`. You can send this file to any Android phone to install it!

#### Method B: Build using Command Line CLI (Fastest)
Run the Gradle wrapper wrapper directly in your project root:
```bash
cd android
./gradlew assembleDebug
```
The installable APK will be built and saved at:
`android/app/build/outputs/apk/debug/app-debug.apk`

---

## 📲 Installing on Your Devices
1. Transfer the generated `app-debug.apk` file to your Android phone (via WhatsApp, Google Drive, or USB).
2. Tap the file in your phone's file explorer.
3. If prompted, toggle **"Allow installation from unknown sources"** in your phone settings.
4. Open the Al-Ansar application from your home screen and start tracking!
