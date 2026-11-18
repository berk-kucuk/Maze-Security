# Shrink and optimize, but do not rename: renaming hides nothing in an open
# tool and is the part of R8 that breaks libraries which look classes up by
# name at runtime (SSHJ's crypto providers, kotlinx, commons-net).
-dontobfuscate
-keepattributes SourceFile,LineNumberTable

# Keep SSHJ / BouncyCastle reflective providers used for brute-force auth checks.
-dontwarn org.slf4j.**
-dontwarn net.schmizz.**
-keep class net.schmizz.** { *; }
-keep class org.bouncycastle.** { *; }
-dontwarn org.bouncycastle.**

# SSHJ's ed25519 implementation. Its JDK-only branch (sun.security.x509) is
# never reached on Android; the classes themselves are found through the
# security provider, so they are kept whole.
-dontwarn sun.security.x509.**
-keep class net.i2p.crypto.eddsa.** { *; }
