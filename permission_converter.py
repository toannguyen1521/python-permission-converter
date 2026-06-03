#!/usr/bin/env python3
"""
permission_converter.py
Chuyển đổi quyền file Linux: Octal <-> Ký hiệu (Symbol)
Hỗ trợ: rwx thông thường + special bits (setuid, setgid, sticky bit)

Cách dùng:
  python permission_converter.py                  # Chạy chế độ tương tác
  python permission_converter.py 755              # Octal -> Symbol
  python permission_converter.py rwxr-xr-x        # Symbol -> Octal
  python permission_converter.py 7665             # Octal 4 chữ số (có special bits)
"""

import sys

# ──────────────────────────────────────────────
# PHẦN 1: OCTAL → SYMBOL
# ──────────────────────────────────────────────

def octal_to_symbol(octal_str: str) -> str:
    """
    Chuyển chuỗi octal (3 hoặc 4 chữ số) sang ký hiệu quyền.
    Ví dụ: '755'  -> 'rwxr-xr-x'
           '7665' -> 'rwSrwSr-t'
           '4755' -> 'rwsr-xr-x'
    """
    octal_str = octal_str.strip()

    # Kiểm tra hợp lệ
    if not octal_str.isdigit():
        raise ValueError(f"'{octal_str}' không phải chuỗi số octal hợp lệ.")

    if len(octal_str) == 3:
        special = 0
        owner_oct, group_oct, other_oct = (int(c) for c in octal_str)
    elif len(octal_str) == 4:
        special, owner_oct, group_oct, other_oct = (int(c) for c in octal_str)
    else:
        raise ValueError("Octal phải có 3 hoặc 4 chữ số (ví dụ: 755 hoặc 4755).")

    # Kiểm tra từng chữ số trong phạm vi 0-7
    for digit in [special, owner_oct, group_oct, other_oct]:
        if digit > 7:
            raise ValueError(f"Chữ số '{digit}' không hợp lệ trong hệ octal (phải từ 0-7).")

    # Tách special bits
    setuid  = bool(special & 4)   # bit 2
    setgid  = bool(special & 2)   # bit 1
    sticky  = bool(special & 1)   # bit 0

    def bits_to_rwx(val):
        r = 'r' if val & 4 else '-'
        w = 'w' if val & 2 else '-'
        x = 'x' if val & 1 else '-'
        return r, w, x

    or_, ow, ox = bits_to_rwx(owner_oct)
    gr, gw, gx = bits_to_rwx(group_oct)
    rr, rw, rx = bits_to_rwx(other_oct)

    # Áp dụng special bits vào ký tự execute
    if setuid:
        ox = 's' if ox == 'x' else 'S'   # s = có x, S = không có x
    if setgid:
        gx = 's' if gx == 'x' else 'S'
    if sticky:
        rx = 't' if rx == 'x' else 'T'   # t = có x, T = không có x

    return f"{or_}{ow}{ox}{gr}{gw}{gx}{rr}{rw}{rx}"


# ──────────────────────────────────────────────
# PHẦN 2: SYMBOL → OCTAL
# ──────────────────────────────────────────────

def symbol_to_octal(symbol: str) -> str:
    """
    Chuyển chuỗi ký hiệu 9 ký tự sang octal.
    Ví dụ: 'rwxr-xr-x' -> '755'
           'rwSrwSr-t'  -> '7665'
           'rwsr-xr-x'  -> '4755'
    """
    symbol = symbol.strip()

    if len(symbol) != 9:
        raise ValueError(f"Ký hiệu phải có đúng 9 ký tự (ví dụ: rwxr-xr-x), nhận được: '{symbol}'")

    # Ký tự hợp lệ tại từng vị trí
    valid = [
        ('r', '-'),   # 0: owner read
        ('w', '-'),   # 1: owner write
        ('x', '-', 's', 'S'),  # 2: owner execute / setuid
        ('r', '-'),   # 3: group read
        ('w', '-'),   # 4: group write
        ('x', '-', 's', 'S'),  # 5: group execute / setgid
        ('r', '-'),   # 6: other read
        ('w', '-'),   # 7: other write
        ('x', '-', 't', 'T'),  # 8: other execute / sticky
    ]

    for i, ch in enumerate(symbol):
        if ch not in valid[i]:
            raise ValueError(f"Ký tự '{ch}' không hợp lệ tại vị trí {i+1}.")

    special = 0
    owner   = 0
    group   = 0
    other   = 0

    # Owner (vị trí 0-2)
    if symbol[0] == 'r': owner += 4
    if symbol[1] == 'w': owner += 2
    if symbol[2] == 'x':
        owner += 1
    elif symbol[2] == 's':
        owner += 1
        special += 4  # setuid
    elif symbol[2] == 'S':
        special += 4  # setuid, không có execute

    # Group (vị trí 3-5)
    if symbol[3] == 'r': group += 4
    if symbol[4] == 'w': group += 2
    if symbol[5] == 'x':
        group += 1
    elif symbol[5] == 's':
        group += 1
        special += 2  # setgid
    elif symbol[5] == 'S':
        special += 2  # setgid, không có execute

    # Other (vị trí 6-8)
    if symbol[6] == 'r': other += 4
    if symbol[7] == 'w': other += 2
    if symbol[8] == 'x':
        other += 1
    elif symbol[8] == 't':
        other += 1
        special += 1  # sticky
    elif symbol[8] == 'T':
        special += 1  # sticky, không có execute

    if special > 0:
        return f"{special}{owner}{group}{other}"
    else:
        return f"{owner}{group}{other}"


# ──────────────────────────────────────────────
# PHẦN 3: TỰ NHẬN DẠNG INPUT
# ──────────────────────────────────────────────

def detect_and_convert(user_input: str) -> str:
    """
    Tự động nhận dạng input là octal hay symbol rồi chuyển đổi.
    """
    s = user_input.strip()

    if s.isdigit():
        # Là octal
        result = octal_to_symbol(s)
        return f"Octal    : {s}\nKý hiệu  : {result}"
    elif len(s) == 9:
        # Là symbol
        result = symbol_to_octal(s)
        return f"Ký hiệu  : {s}\nOctal    : {result}"
    else:
        raise ValueError(
            f"Không nhận dạng được '{s}'.\n"
            "  - Octal: 3-4 chữ số (vd: 755, 4755)\n"
            "  - Symbol: đúng 9 ký tự (vd: rwxr-xr-x)"
        )


# ──────────────────────────────────────────────
# PHẦN 4: CHẠY CHƯƠNG TRÌNH
# ──────────────────────────────────────────────

BANNER = """
╔══════════════════════════════════════════════╗
║   Linux Permission Converter  (Octal ↔ Ký hiệu)  ║
╚══════════════════════════════════════════════╝
Nhập octal (vd: 755, 7665) hoặc ký hiệu (vd: rwxr-xr-x)
Gõ 'q' hoặc 'quit' để thoát.
"""

def run_interactive():
    """Chế độ tương tác: hỏi liên tục cho đến khi thoát."""
    print(BANNER)
    while True:
        try:
            user_input = input("Nhập quyền > ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nThoát.")
            break

        if user_input.lower() in ('q', 'quit', 'exit', ''):
            print("Thoát.")
            break

        try:
            print(detect_and_convert(user_input))
        except ValueError as e:
            print(f"[Lỗi] {e}")

        print()  # dòng trống cho dễ đọc


def main():
    if len(sys.argv) == 1:
        # Không có argument -> chế độ tương tác
        run_interactive()
    elif len(sys.argv) == 2:
        # Có 1 argument -> chuyển đổi thẳng
        try:
            print(detect_and_convert(sys.argv[1]))
        except ValueError as e:
            print(f"[Lỗi] {e}")
            sys.exit(1)
    else:
        print("Cách dùng:")
        print("  python permission_converter.py              # Chế độ tương tác")
        print("  python permission_converter.py 755          # Octal -> Symbol")
        print("  python permission_converter.py rwxr-xr-x   # Symbol -> Octal")
        sys.exit(1)


if __name__ == "__main__":
    main()
