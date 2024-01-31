# ceserver-ios

Porting ceserver to iOS.Dynamic analysis is possible with Cheat Engine.  
It also works on macOS.

# Usage

## iOS

### with a Jailbroken iPhone

Place your PC and iphone in the same network.  
Place ceserver and Entitlements.plist in /usr/bin.

Connect to the iphone via ssh.

```
cd /usr/bin
chmod a+x ceserver
ldid -SEntitlements.plist ceserver
./ceserver
```

### without a Jailbroken iPhone

Set up the same way as FridaGadget to force loading of libceserver.dylib.  
Connect to the network from CE as usual.  
The debugger does not work.  
Log output is written to NSLog.

## Mac

```
sudo ./ceserver
```

# Tested

- Windows:CE 7.5.2(patreon)
- Mac:CE 7.5.2(patreon)

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
