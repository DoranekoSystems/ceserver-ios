# ceserver-ios

Porting ceserver to iOS.Dynamic analysis is possible with Cheat Engine.  
It also works on macOS.  

# Usage

## iOS
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

## Mac

```
sudo ./ceserver
```

# Tested

- Windows:CE 7.5(patreon)  
  => Note:The module size is inaccurate, whether due to CE or not.
- Mac:CE 7.4.3(patreon)

# Project Status

## Progress

- Memory read/write and search
- Pointer Scan
- Enumerate Modules
- Enumerate Memory Ranges

# Build

## iOS
`./build.sh`

## Mac
`make`
