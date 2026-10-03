# APKProxyHelper

Patches an APK so its traffic can be intercepted by an intercepting proxy
(mitmproxy/Burp): adds a debug network security config (user CAs trusted),
explicitly allows cleartext, and marks the app debuggable - all without
decompiling anything.

Usage
----------

```
$ python3 aph.py -a app.apk [-o app_patched.apk] [-k my.keystore]
```

The tool needs `zipalign`/`apksigner` from Android build-tools (34.0.0
preferred, discovered via ANDROID_HOME/sdk dirs) and re-signs with
`~/.android/debug.keystore` unless given a keystore.

What it does (zip surgery, no decompile/recompile)
----------

1. **resources.arsc** - appends one file-backed entry
   `@xml/network_security_config_aph -> res/xml/network_security_config_aph.xml`
   (reuses an existing `network_security_config.xml` entry if the app ships
   one). The original arsc is never decoded or regenerated; chunks are grown
   at boundaries, so obfuscated/unusual resources survive byte-for-byte.
2. **res/xml/network_security_config_aph.xml** - embedded as *compiled binary
   XML*, produced in-process from the text template (`compile_xml_to_axml`).
   The framework's ResXMLTree rejects plain-text XML resources - a text file
   here kills the app at bind time with "Failed to parse XML configuration".
3. **AndroidManifest.xml** - parsed as binary AXML; `<application>` gets
   - `android:networkSecurityConfig="@xml/network_security_config_aph"`
   - `android:usesCleartextTraffic="true"`  (make-or-break: okhttp consults
     this platform flag; a debug NSC alone did NOT stop okhttp cleartext
     IOExceptions in practice)
   - `android:debuggable="true"`            (activates NSC debug-overrides,
     plus run-as for on-device poking)
4. Everything else is copied byte-for-byte (same compression), stale
   signatures dropped, then `zipalign -f -p 4` + `apksigner` (v1+v2).

Why not apktool? apktool 2.10's decoder gives up on some valid binary XML
resources ("Could not decode file, replacing by FALSE value" - seen on HDO
Box 4.4.6 obfuscated builds: res/qz.xml et al.), and the FALSE placeholders
then fail `aapt2 compile` on rebuild, so those apps can't be patched at all.
Patching never requires decoding.

Two bugs that produce "works in aapt2, ignored by the framework"
----------

Both were found on a real app that installed fine and then silently ignored
the new manifest attributes:

1. **Attribute order matters.** `AssetManager2::RetrieveAttributes`
   (AttributeResolution.cpp - the code behind every `obtainAttributes()` on
   a manifest) does an ascending merge-walk over the requested styleable
   array and the element's attributes, *assuming both are sorted by resource
   ID*. aapt2 emits them sorted; an attribute appended out of order is
   skipped silently - `aapt2 dump xmltree` still resolves it, but
   debuggable/usesCleartextTraffic do not apply at runtime. A 2-byte
   experiment (swapping two attr name indices in an otherwise identical
   manifest) reproduces this deterministically. The tool therefore re-sorts
   the modified element's attributes by resource ID (attrs without a
   resource id last, order-preserving) after every edit.

2. **res/xml resources must be compiled AXML**, not text (see above). aapt2
   does this in a normal build; `compile_xml_to_axml` reimplements the small
   subset needed (elements + string attributes) so the tool stays
   self-contained.

Useful verification commands
----------

```
aapt2 dump xmltree out.apk --file AndroidManifest.xml        # 3 attrs, sorted by resid
aapt2 dump xmltree out.apk --file res/xml/network_security_config_aph.xml
zipalign -c 4 out.apk && apksigner verify out.apk
adb install -r out.apk
adb shell "dumpsys package <pkg> | grep pkgFlags="           # expect DEBUGGABLE
adb shell "run-as <pkg> id"                                  # expect uid=...
```

Caveats
----------

- The app is re-signed with a debug key: installing over a build signed with
  a different key needs an uninstall first (and v2-only signers will trip
  signature checks in some apps).
- Hidden API policy, SafetyNet/Play Integrity and certificate pinning are
  out of scope; pinning will still need objection/Frida or the app's own
  debug-overrides (user CAs are trusted via the NSC for apps that honor it).
