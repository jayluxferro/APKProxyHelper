import argparse
import sys

from APKProxyHelper import APKProxyHelper


def _handleArgs():
    argParser = argparse.ArgumentParser(prog="APKProxyHelper")
    argParser.add_argument(
        "--apk", "-a", help="The path to the apk file", required=True
    )
    argParser.add_argument(
        "--out", "-o", help="Output path for the patched apk (default: <apk>_proxy.apk next to the input)"
    )
    argParser.add_argument(
        "--keystore", "-k", help="Keystore to sign with (default: ~/.android/debug.keystore)"
    )
    return argParser.parse_args()


def _main():
    args = _handleArgs()

    patcher = APKProxyHelper(apk_path=args.apk, out_path=args.out, keystore=args.keystore)
    try:
        patcher.patch_apk()
    except Exception as e:
        print("[!] FAILED: {}".format(e), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    _main()
