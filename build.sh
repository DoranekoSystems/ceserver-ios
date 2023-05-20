export SDKROOT=$(xcrun --sdk iphoneos --show-sdk-path)
export VER_MIN=11.2
export CC=$(xcrun --sdk iphoneos --find clang) 
export CXX=$(xcrun --sdk iphoneos --find clang++) 
export LD=$(xcrun --sdk iphoneos --find ld) 
export AR=$(xcrun --sdk iphoneos --find ar) 
export CPP="$(xcrun --sdk iphoneos -f clang) -E -D __arm__=1" 
export CXXCPP="$(xcrun --sdk iphoneos -f clang++) -E -D __arm__=1" 
export RANLIB=$(xcrun --sdk iphoneos --find ranlib) 
export LIBTOOL=$(xcrun --sdk iphoneos --find libtool) 
export STRIP=$(xcrun --sdk iphoneos --find strip) 
export CFLAGS="-arch arm64 -isysroot $SDKROOT -miphoneos-version-min=$VER_MIN" 
export CXXFLAGS=$CFLAGS
export LDFLAGS="-arch arm64 -isysroot $SDKROOT"

make
