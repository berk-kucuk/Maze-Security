# Keep SSHJ / BouncyCastle reflective providers used for brute-force auth checks.
-dontwarn org.slf4j.**
-dontwarn net.schmizz.**
-keep class net.schmizz.** { *; }
-keep class org.bouncycastle.** { *; }
-dontwarn org.bouncycastle.**
