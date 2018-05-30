xcrun -sdk iphoneos clang -fembed-bitcode -arch armv7 -arch armv7s -arch arm64 -c keccak-tiny-unrolled.c -o keccak-tiny-unrolled.o

xcrun --sdk iphonesimulator clang -arch i386 -arch x86_64 -c keccak-tiny-unrolled.c -o simulator-keccak-tiny-unrolled.o

lipo -create keccak-tiny-unrolled.o simulator-keccak-tiny-unrolled.o -o keccak-tiny-lib.a



