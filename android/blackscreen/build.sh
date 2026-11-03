#!/bin/bash
# Builds build/blackscreen.apk without Gradle: javac -> d8 -> aapt2 link -> zipalign -> apksigner.
# Toolchain (WSL only): ~/android-sdk with jdk, platforms;android-33, build-tools;34.0.0.
# The debug signing key lives in ~/android-sdk, outside the project.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
sdk=${ANDROID_HOME:-$HOME/android-sdk}
tools=$sdk/build-tools/34.0.0
jar=$sdk/platforms/android-33/android.jar
export JAVA_HOME=$sdk/jdk PATH=$sdk/jdk/bin:$PATH
key=$sdk/blackscreen-debug.keystore
out=$here/build
rm -rf "$out"; mkdir -p "$out/classes" "$out/dex"
javac --release 11 -Xlint:all -Werror -classpath "$jar" -d "$out/classes" $(find "$here/src" -name '*.java')
"$tools/d8" --release --min-api 31 --lib "$jar" --output "$out/dex" $(find "$out/classes" -name '*.class')
"$tools/aapt2" link --manifest "$here/AndroidManifest.xml" -I "$jar" -o "$out/unsigned.apk"
python3 -c 'import sys,zipfile; zipfile.ZipFile(sys.argv[1],"a",zipfile.ZIP_DEFLATED).write(sys.argv[2],"classes.dex")' \
    "$out/unsigned.apk" "$out/dex/classes.dex"
"$tools/zipalign" -f -p 4 "$out/unsigned.apk" "$out/aligned.apk"
if [ ! -f "$key" ]; then
    keytool -genkeypair -keystore "$key" -storepass android -keypass android -alias blackscreen \
        -keyalg RSA -keysize 2048 -validity 10000 -dname "CN=blackscreen debug" > /dev/null 2>&1
fi
"$tools/apksigner" sign --ks "$key" --ks-pass pass:android --key-pass pass:android \
    --out "$out/blackscreen.apk" "$out/aligned.apk"
"$tools/apksigner" verify --print-certs "$out/blackscreen.apk" | head -2
rm -rf "$out/classes" "$out/unsigned.apk" "$out/aligned.apk"
sha256sum "$out/blackscreen.apk"
