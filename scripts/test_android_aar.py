import importlib.util
import io
from pathlib import Path
import struct
import unittest
import zipfile

spec = importlib.util.spec_from_file_location(
    "check_android_aar", Path(__file__).with_name("check-android-aar.py"))
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


def fixture(omit=None, wrong_arch=False, invalid=False):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        for abi, (elf_class, machine) in checker.ARCHITECTURES.items():
            for library in ("libtcx.so", "libconnector.so"):
                name = f"jni/{abi}/{library}"
                if name == omit:
                    continue
                header = bytearray(20)
                header[:6] = b"\x7fELF" + bytes([elf_class, 1])
                struct.pack_into("<HH", header, 16, 3, 0 if wrong_arch else machine)
                archive.writestr(name, b"not a shared library" if invalid else header)
    output.seek(0)
    return output


class AarChecks(unittest.TestCase):
    def test_complete_package(self):
        checker.check_aar(fixture())

    def test_missing_library(self):
        with self.assertRaisesRegex(ValueError, "Missing"):
            checker.check_aar(fixture(omit="jni/x86/libconnector.so"))

    def test_wrong_architecture(self):
        with self.assertRaisesRegex(ValueError, "Invalid ELF"):
            checker.check_aar(fixture(wrong_arch=True))

    def test_placeholder(self):
        with self.assertRaisesRegex(ValueError, "Invalid ELF"):
            checker.check_aar(fixture(invalid=True))


if __name__ == "__main__":
    unittest.main()
