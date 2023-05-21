# ceserver-ios

Porting ceserver to iOS.Dynamic analysis is possible with Cheat Engine.

**Note:**  
**This project contains many bugs at this time.**
# Usage

Only patreon ce version 7.5 is supported.  
Jailbreaking of iphone is required.  
Place your PC and iphone in the same network.  
Place ceserver and Entitlements.plist in /usr/bin.

Connect to the iphone via ssh.

```
cd /usr/bin
chmod a+x ceserver
ldid -SEntitlements.plist ceserver
./ceserver
```

# Project Status
## Progress
- Memory read/write and search only.

# Build

`./build.sh`
