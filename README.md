# IMMIO
Is My Mint ISO Okay? A simple app to check if you've downloaded the right file to install Linux Mint

## Disclaimer

Like any other piece of software (and information generally), immio comes with NO WARRANTY.

## Description

If the [Linux Mint verification steps for Windows users](https://forums.linuxmint.com/viewtopic.php?f=42&t=291093) is too complicated for you, here's an easy Windows tool to compute the checksum for you.

## What's a checksum?

Not every file you find online is safe. Before you install a new operating system, you should trust that the file you're about to run with the highest privileges possible on your own computer is a valid file, that it was the exact file the Mint developers intended you to download, and that no malicious actors have edited the file or altered it in any way.

A checksum is a mathematical operation performed on a file that is easy to calculate and difficult to replicate. It effectively acts like a fingerprint for a specific file to ensure it hasn't been modified or corrupted.

SHA-256 checksums are published by the Mint development team. These checksums allow you to make sure you have the correct file. These checksums are then cryptographically signed with GnuPG to ensure authenticity.

Be aware: this tool does not perform any authenticity checks. It only verifies the integrity of the downloaded image based on previously published checksums.

*Integrity and authenticity are not the same thing*.

If you don't know what GnuPG is, don't worry. If you trust me, a total stranger, to validate your Linux ISOs for you, even better.

If you actually care to ensure the Linux Mint ISO you've downloaded is authentic, take the time to [learn how to validate an ISO properly](https://forums.linuxmint.com/viewtopic.php?f=42&t=291093). This tool is meant only for the laziest of the lazy.

## For the lazy

Download a [Linux Mint ISO](https://www.linuxmint.com/download.php). Preferably a recent one. This app only validates Mint ISOs as far back as version 19.3. Run IMMIO. There are only two useful buttons: "Select ISO" and "Verify", so it's hard to screw up this process. Someone will complain about the interface anyway. Wallow in your laziness and check the checksum of your Mint ISO in peace.

## LMDE

Linux Minut Debian Edition versions are also supported as far back as version 4.

## Compiling

If you want to build IMMIO yourself, you will need to install [Build Tools for Visual Studio 2026](https://aka.ms/vs/stable/vs_BuildTools.exe) or newer on Windows and then run the following:

```
cl immio.cpp /link user32.lib comdlg32.lib gdi32.lib
```

## And now a warning

In the long run it really is better for you and for everyone else to just [learn how to validate an ISO properly](https://forums.linuxmint.com/viewtopic.php?f=42&t=291093) instead of trusting this tool. It will make you a better computer user. It will make dumb little hacks like this obsolete. Mint is a great operating system, but it really isn't meant to keep you in the dark forever. Part of using Mint is that you are expected to improve as a user and as a person.

Mint is about empowering you to control your own hardware. And yes, that means taking responsibility for it, and responsibility means learning things you might not normally otherwise know. You'll be better for it in the long run if you learn how to validate your own data.

Your limits are futher out than you may think they are.

Be better than this dumb little app.

## About IMMIO

This dumb little app was vibe-coded on Pi Day 2026 (2026-03-14) during the NCAA Houston/Arizona game, with a little more time spent working on the README. The SHA-256 checksums were taken from a uwaterloo.ca mirror. GnuPG support was strongly considered and then discarded for the sake of simplicity. Do it the right way instead, you're better off for it.
