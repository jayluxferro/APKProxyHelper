import os
import shutil
import subprocess
from pathlib import Path
from platform import system as sys_name
from xml.etree import ElementTree


class APKProxyHelper:
    def __init__(self, apk_path):
        self.apk = os.path.normpath(os.path.expanduser(apk_path))
        self.file_name = os.path.splitext(os.path.basename(self.apk))[0]
        self.apktool_output = self.apk.replace(".apk", "")
        self.patched_apk = self.apk.replace(
            self.file_name, "{}_proxy".format(self.file_name)
        )
        self.use_aapt2 = False

    # Public methods
    def patch_apk(self):
        if os.path.isfile(self.apk):
            self._delete_existing_resource_table()
            self._decompile_apk()
            self._copy_network_file()
            self._update_manifest()
            self._repackage_apk()
            self._resign_apk()
            self._clean_up()

    # Private methods
    def _apktool_path(self):
        return "deps/apktool.jar"

    def _apk_signer_path(self):
        return "deps/apk-signer.jar"

    def _run_command(self, command):
        command_string = " ".join(command)

        process = subprocess.Popen(command_string, shell=True, stdout=subprocess.PIPE)
        while True:
            output = process.stdout.readline()

            if output is None or output == "":
                break

            if process.poll() is not None:
                break

            if output:
                output = output.decode("utf-8").strip()
                print(output)

        return process.poll()

    def _decompile_apk(self):
        print("[*] Decompiling {}".format(self.apk))

        self._run_command(
            command=[
                "java",
                "-jar",
                self._apktool_path(),
                "-f",
                "d",
                '"{}"'.format(self.apk),
                "-o",
                self.apktool_output,
            ]
        )

    def _copy_network_file(self):
        res_path = os.path.join(self.apktool_output, "res/xml")
        res_path = os.path.abspath(res_path)
        if not os.path.exists(res_path):
            os.makedirs(res_path)
        print("[*] Adding network file to {}".format(res_path))

        file = "network_security_config.xml"
        with open(file, "r") as network_file:
            with open(os.path.join(res_path, file), "w+") as new_network_file:
                new_network_file.write(network_file.read())

    def _update_manifest(self):
        xml_path = os.path.join(self.apktool_output, "AndroidManifest.xml")
        print("[*] Updating manifest at {}".format(xml_path))

        if os.path.isfile(xml_path):
            ElementTree.register_namespace(
                "android", "http://schemas.android.com/apk/res/android"
            )

            tree = ElementTree.parse(xml_path)
            if tree is not None:
                root = tree.getroot()
                if root is not None:
                    application = root.find("application")
                    application.set(
                        "{http://schemas.android.com/apk/res/android}networkSecurityConfig",
                        "@xml/network_security_config",
                    )
                    application.set("android:debuggable", "true")

                    with open(xml_path, "wb") as xml_file:
                        xml_file.write(
                            '<?xml version="1.0" encoding="utf-8" standalone="no"?>'.encode()
                        )
                        xml_file.write(ElementTree.tostring(root))

    def _repackage_apk(self):
        print("[*] Repackaging to {}".format(self.patched_apk))
        input("Press enter to continue ...")
        self._run_command(
            command=[
                "java",
                "-jar",
                self._apktool_path(),
                "-f",
                "b",
                '"{}"'.format(self.apktool_output),
                "-o",
                self.patched_apk,
            ]
        )

        if not os.path.isfile(self.patched_apk):
            self._repackage_apk_aapt2()

    def _repackage_apk_aapt2(self):
        print("[*] Repackaging using aapt2 to {}".format(self.patched_apk))

        self._run_command(
            command=[
                "java",
                "-jar",
                self._apktool_path(),
                "-f",
                "b",
                "--use-aapt2",
                '"{}"'.format(self.apktool_output),
                "-o",
                self.patched_apk,
            ]
        )

    def _resign_apk(self):
        if os.path.isfile(self.patched_apk):
            print("[*] Re-signing apk {}".format(self.patched_apk))

            self._run_command(
                command=[
                    "java",
                    "-jar",
                    self._apk_signer_path(),
                    "--allowResign",
                    "-a",
                    self.patched_apk,
                ]
            )

    def _delete_existing_resource_table(self):
        os_name = sys_name().lower()
        user_home_directory = Path.home()
        apktool_resource_table_path = "apktool/framework/1.apk"
        try:
            print("[*] Clearing existing resource table")
            if os_name == "darwin":
                os.remove(
                    f"{user_home_directory}/Library/{apktool_resource_table_path}"
                )
            if os.name == "linux":
                os.remove(
                    f"{user_home_directory}/.local/share/{apktool_resource_table_path}"
                )
            if os.name == "windows":
                os.remove(
                    f"{user_home_directory}/AppData/Local/{apktool_resource_table_path}"
                )
        except:
            pass

    def _clean_up(self):
        try:
            print("[*] Cleaning up directory {}".format(self.apktool_output))
            shutil.rmtree(self.apktool_output)
        except OSError as e:
            pass
