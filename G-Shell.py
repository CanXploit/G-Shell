import argparse
import platform
import sys

def format_shellcode(shellcode_bytes, language, number):
    suffix = "" if number == 1 else str(number)

    if language in ['c', 'cpp']:
        formatted = ', '.join(f'0x{byte:02x}' for byte in shellcode_bytes)
        return (
            f"unsigned char shellcode{suffix}[] = {{\n    "
            + formatted +
            f"\n}};\nunsigned int shellcode{suffix}_len = sizeof(shellcode{suffix});"
        )

    elif language == 'csharp':
        formatted = ', '.join(f'0x{byte:02x}' for byte in shellcode_bytes)
        return f'byte[] shellcode{suffix} = new byte[] {{ {formatted} }};'

    else:
        raise ValueError("Unsupported language. Choose from: c, cpp, csharp.")

def read_shellcode_from_bin(file_path, language, number, output_file=None, arch=None):
    try:
        with open(file_path, "rb") as f:
            shellcode_bytes = f.read()

        # تأكد من تطابق المعمارية
        if arch:
            if arch == "x86" and platform.architecture()[0] != "32bit":
                print("[-] Error: You selected x86 but you're running a 64-bit interpreter.")
                sys.exit(1)
            elif arch == "x64" and platform.architecture()[0] != "64bit":
                print("[-] Error: You selected x64 but you're running a 32-bit interpreter.")
                sys.exit(1)

        formatted_shellcode = format_shellcode(shellcode_bytes, language, number)

        if output_file:
            with open(output_file, "w") as out:
                out.write(formatted_shellcode + "\n")
            print(f"[+] Shellcode written to: {output_file}")
        else:
            print("[+] Shellcode extracted successfully:\n")
            print(formatted_shellcode)

        return shellcode_bytes

    except FileNotFoundError:
        print("[-] File not found.")
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract and format shellcode from a .bin file.")
    parser.add_argument("file", help="Path to the .bin file")
    parser.add_argument("--lang", choices=["c", "cpp", "csharp"], default="c", help="Language to format shellcode for")
    parser.add_argument("--output", help="Optional output file to save the formatted shellcode")
    parser.add_argument("--num", type=int, default=1, help="Shellcode variable number (default: 1)")
    parser.add_argument("--arch", choices=["x86", "x64"], help="Target architecture (x86 or x64)")

    args = parser.parse_args()
    read_shellcode_from_bin(args.file, args.lang, args.num, args.output, args.arch)
