# ceserver-ios

Porting ceserver to iOS.Dynamic analysis is possible with Cheat Engine.

# Usage

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

# Build

`./build.sh`
