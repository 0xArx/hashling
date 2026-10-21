# Does Hashling catch test malware?

Security companies agree on a few harmless "test malware" files that every antivirus should flag. They let anyone check that protection is switched on and working, without touching real malware. This page shows how Hashling does on them.

- **The EICAR test file** is a 68-byte text file made by [EICAR](https://www.eicar.org/download-anti-malware-testfile/), a European security research group. It does nothing, but scanners treat it as malware on purpose.
- **The AMTSO Security Features Check** is a set of small tests from [AMTSO](https://www.amtso.org/security-features-check/), the industry group that sets the rules for antivirus testing. It checks a downloaded file, the same file inside archives, a "potentially unwanted" app, a download that starts by itself (drive-by), a phishing page and a cloud lookup.

## Results

Run on 21 October 2026, Hashling 0.1.0, on a Mac with Apple silicon, against Hashling's normal engines (ClamAV, YARA-X with Apple's XProtect rules and community rules, and the download watch).

| Check | File | Result | |
|---|---|---|---|
| EICAR test file (made on this Mac) | `eicar-made-here.com` | Detected: Eicar-Test-Signature | Pass |
| Manually downloaded malware | `eicar.com` | Detected: Eicar-Test-Signature | Pass |
| Compressed malware | `eicar.zip` | Detected: Eicar-Test-Signature | Pass |
| Compressed malware | `eicar-made-here.zip` | Detected: Eicar-Test-Signature | Pass |
| Compressed malware (zip inside a zip) | `eicar-made-here-nested.zip` | Detected: Eicar-Test-Signature | Pass |
| Compressed malware | `eicar-made-here.tgz` | Detected: Eicar-Test-Signature | Pass |
| Drive-by download (file lands in Downloads) | `hashling-eicar-test.com` | Detected within seconds of arriving. Not blocked before it was saved. | Partly |
| Phishing page | `amtso.org/check-desktop-phishing-page` | Not on the public phishing lists Hashling uses, and Hashling does not block pages in the browser. | Fail |
| Potentially unwanted app (PUA) | `PotentiallyUnwanted.exe` | Could not run: AMTSO's file server (amtso.eicar.org) did not answer from this network. | Not run |
| Cloud lookup (CloudCar) | `cloudcar.exe` | Could not run, same reason. | Not run |

The EICAR files came from EICAR's own server (secure.eicar.org). The archives marked "made here" were built on the Mac by the test script, so the compressed check still runs when no server answers.

## What this means, in plain words

- **Hashling finds known malware files**, including inside zip and tar archives and archives inside archives, both when you ask it to scan and on its own when a file lands in Downloads.
- **Hashling finds things after they arrive, it does not stop them arriving.** A traditional antivirus hooks into macOS so a bad file is blocked before it can be saved or opened ("real-time, on-access protection"). Hashling watches and scans within seconds instead. With *Lock away malware automatically* switched on (on the Malware page), it moves the file into quarantine straight away; otherwise it asks you first.
- **Hashling does not block websites as you browse.** It checks the sites you visited against public phishing and malware lists afterwards, and can block a site for good with your Touch ID. AMTSO's phishing test page is a safe page on AMTSO's own site, so no public list includes it, and a browser-based check would be needed to pass this test. Pair Hashling with your browser's own protection (Safari's Fraudulent Website Warning, Chrome's Safe Browsing) for that.
- **The PUA and cloud tests use AMTSO's own files**, and their server did not answer when this was run. Hashling's "cloud lookup" is a fingerprint check with Team Cymru and CIRCL (only the file's fingerprint leaves the Mac), so CloudCar would only be flagged if those services know it.

These are quick self-checks, not an independent test. See [CERTIFICATION.md](CERTIFICATION.md) for independent testing.

## Run it yourself

With Hashling running:

```sh
node scripts/amtso-check.mjs
```

The script downloads the test files into a temporary folder, asks Hashling to scan them, drops one copy into Downloads to test the download watch, asks Hashling about AMTSO's phishing page, prints the table above and then deletes every test file. The test files are never opened. Hashling shows a "test file" finding while the check runs, and it closes by itself when the files are deleted.

You can also try it by hand: download `eicar.com` from [EICAR's page](https://www.eicar.org/download-anti-malware-testfile/) and watch Hashling's Downloads page, or run `hashling scan ~/Downloads`. Some browsers block the download themselves, which is also a pass for your Mac.
