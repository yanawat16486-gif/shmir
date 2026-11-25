"""โครงงานคณิตศาสตร์: ระบบแบ่งความลับแบบ 3-of-5

ระบบแบ่งความลับตามเอกสารบทที่ 3 รันได้ด้วย Python 3.8 ขึ้นไป
วิธีรัน: python3 Shamir_Phase2_Secure_Fixed.py
ดูตัวอย่างตามเอกสาร: python3 Shamir_Phase2_Secure_Fixed.py --demo
"""

import argparse
import base64
import getpass
import hmac
import json
import os
import tempfile
from pathlib import Path
import secrets
import sys
from contextlib import contextmanager
from itertools import combinations


@contextmanager
def alternate_screen(enabled=True):
    """Use the terminal's alternate screen, restoring the original on exit."""
    active = enabled and sys.stdin.isatty() and sys.stdout.isatty() and (
        os.environ.get("TERM", "dumb") != "dumb"
    )
    if active:
        sys.stdout.write("\033[?1049h")
        sys.stdout.flush()
    try:
        yield
    finally:
        if active:
            sys.stdout.write("\033[?1049l")
            sys.stdout.flush()


# ใช้ค่าตามเอกสาร จะได้เทียบผลกับการคำนวณด้วยมือได้ง่าย
SECRET = 41216
PRIME = 50021
TOTAL_SHARES = 5
MIN_SHARES = 3
A1 = 37
A2 = 82

# ค่าข้างบนใช้ในโหมดตัวอย่างเท่านั้น เมนูแบ่งความลับจะรับค่าและสุ่มใหม่


def create_shares(secret, a1, a2):
    """สร้างส่วนแบ่งทั้ง 5 ส่วนจากพหุนามดีกรี 2"""
    if not all(type(value) is int for value in (secret, a1, a2)):
        raise ValueError("ความลับและสัมประสิทธิ์ต้องเป็นจำนวนเต็ม")
    if not all(0 <= value < PRIME for value in (secret, a1, a2)):
        raise ValueError(f"ค่าทั้งสามต้องอยู่ระหว่าง 0 ถึง {PRIME - 1}")
    if a2 == 0:
        raise ValueError("สัมประสิทธิ์ดีกรีสองต้องไม่เป็นศูนย์")

    shares = []

    # แทน x ตั้งแต่ 1 ถึง 5 เหมือนแจกส่วนแบ่งให้คนละหนึ่งชุด
    for x in range(1, TOTAL_SHARES + 1):
        y = (secret + a1 * x + a2 * x**2) % PRIME
        shares.append((x, y))

    return shares


def split_secret(secret):
    """สุ่มสมการใหม่ แล้วส่งกลับเฉพาะส่วนแบ่งสำหรับแจก"""
    # ใช้ secrets สุ่มค่าในช่วง 0 ถึง p-1 ตามหลักการของ Shamir
    # เก็บสัมประสิทธิ์ไว้เฉพาะตอนสร้างส่วนแบ่ง ไม่ต้องใช้ตอนกู้คืน
    a1 = secrets.randbelow(PRIME)
    a2 = secrets.randbelow(PRIME - 1) + 1  # Keep degree exactly 2
    return create_shares(secret, a1, a2)


def recover_secret(shares):
    """หาค่า f(0) ด้วยสูตรลากร็องจ์ โดยใช้เฉพาะส่วนแบ่งที่ได้รับ"""
    if not MIN_SHARES <= len(shares) <= TOTAL_SHARES:
        raise ValueError("ระบบนี้ต้องใช้ส่วนแบ่ง 3 ถึง 5 ส่วนในการกู้คืน")

    x_values = []
    for x, y in shares:
        if type(x) is not int or type(y) is not int:
            raise ValueError("ค่า x และ y ต้องเป็นจำนวนเต็ม")
        if not 1 <= x <= TOTAL_SHARES or not 0 <= y < PRIME:
            raise ValueError("ส่วนแบ่งมีค่าอยู่นอกช่วงที่ระบบกำหนด")
        x_values.append(x)

    # คนเดิมส่งส่วนแบ่งมาซ้ำ ไม่ได้นับเป็นอีกหนึ่งคน
    if len(set(x_values)) != len(x_values):
        raise ValueError("ค่า x ซ้ำกัน กรุณาใช้ส่วนแบ่งจากคนละคน")

    secret = 0

    # สูตรลากร็องจ์รวมผลจากแต่ละจุด เพื่อหาค่าพหุนามที่ x = 0
    for i, (xi, yi) in enumerate(shares):
        numerator = 1
        denominator = 1

        for j, (xj, _) in enumerate(shares):
            if i != j:
                numerator = (numerator * (0 - xj)) % PRIME
                denominator = (denominator * (xi - xj)) % PRIME

        # ในระบบ mod ใช้การคูณกับอินเวอร์สแทนการหารธรรมดา
        # เช่น อินเวอร์สของ d คือเลขที่คูณกับ d แล้วเหลือเศษ 1
        inverse = pow(denominator, -1, PRIME)
        basis = (numerator * inverse) % PRIME
        secret = (secret + yi * basis) % PRIME

    return secret


def show_experiment(shares):
    """ลองใช้ส่วนแบ่ง 1 ถึง 5 ส่วน แล้วแสดงผลเป็นตาราง"""
    print("\nตารางผลการทดลอง (เลือกผู้ถือคนแรก ๆ ตามจำนวนที่ทดสอบ)")
    print("จำนวนส่วน | ผู้ถือส่วนแบ่ง | ค่าที่กู้คืน | ผลการทดลอง")
    print("-" * 70)

    for count in range(1, TOTAL_SHARES + 1):
        selected = shares[:count]
        holders = ",".join(str(x) for x, _ in selected)

        if count < MIN_SHARES:
            # ส่วนแบ่งยังไม่พอ จึงไม่แสดงเลขที่อาจทำให้เข้าใจว่าเป็นความลับจริง
            print(f"{count:^10}| {holders:<14}| {'-':^12}| ข้อมูลไม่พอระบุความลับเดิม")
        else:
            recovered = recover_secret(selected)
            result = "ตรงกับความลับเดิม" if recovered == SECRET else "ไม่ตรงกับความลับเดิม"
            print(f"{count:^10}| {holders:<14}| {recovered:^12}| {result}")


def check_all_groups(shares):
    """ตรวจทุกกลุ่มที่เลือกได้ เผื่อส่วนแบ่งที่เลือกไม่ได้เรียงติดกัน"""
    print("\nตรวจทุกกลุ่มที่มีส่วนแบ่งพอสำหรับกู้คืน")

    for count in range(MIN_SHARES, TOTAL_SHARES + 1):
        groups = list(combinations(shares, count))
        correct = sum(recover_secret(group) == SECRET for group in groups)
        print(f"ใช้ {count} ส่วน: กู้คืนถูกต้อง {correct}/{len(groups)} กลุ่ม")
        if correct != len(groups):
            raise RuntimeError("พบกลุ่มที่กู้คืนไม่ตรงกับความลับเดิม")


def show_why_two_shares_are_not_enough(shares):
    """ยกตัวอย่างว่าจุด 2 จุดเข้ากับความลับได้มากกว่าหนึ่งค่า"""
    # สร้างอีกสมการจาก g(x) = f(x) + (x - 1)(x - 2)
    # เมื่อ x เป็น 1 หรือ 2 พจน์ที่เพิ่มมาจะเป็นศูนย์ จึงได้ส่วนแบ่งเดิม
    another_secret = (SECRET + 2) % PRIME
    another_a1 = (A1 - 3) % PRIME
    another_a2 = (A2 + 1) % PRIME
    another_shares = create_shares(another_secret, another_a1, another_a2)

    print("\nทำไมมีแค่ 2 ส่วนจึงยังระบุความลับเดิมไม่ได้?")
    print(f"สมการเดิม: f(x) = {SECRET} + {A1}x + {A2}x^2 (mod {PRIME})")
    print(
        f"อีกสมการ: g(x) = {another_secret} + {another_a1}x "
        f"+ {another_a2}x^2 (mod {PRIME})"
    )
    print(f"ส่วนแบ่งคนที่ 1 และ 2 จากสมการเดิม: {shares[:2]}")
    print(f"ส่วนแบ่งคนที่ 1 และ 2 จากอีกสมการ: {another_shares[:2]}")
    print(f"ทั้งสองสมการผ่าน 2 จุดเดียวกัน แต่ความลับต่างกัน: {SECRET} กับ {another_secret}")
    print("จึงต้องมีอย่างน้อย 3 จุด เพื่อหาความลับของพหุนามดีกรีไม่เกิน 2 ได้แน่นอน")


def run_demo():
    print("โครงงานคณิตศาสตร์: Shamir's Secret Sharing แบบ 3-of-5")
    print(f"ความลับตัวอย่าง S = {SECRET}")
    print(f"มอดูลัส p = {PRIME}")
    print(f"พหุนาม f(x) = {SECRET} + {A1}x + {A2}x^2")
    print(f"คำนวณส่วนแบ่งด้วย y = f(x) mod {PRIME}")

    shares = create_shares(SECRET, A1, A2)
    print("\nส่วนแบ่งที่แจกให้ผู้ถือทั้ง 5 คน")
    for x, y in shares:
        print(f"คนที่ {x}: (x, y) = ({x}, {y})")

    show_experiment(shares)
    check_all_groups(shares)
    show_why_two_shares_are_not_enough(shares)

    print("\nหมายเหตุ: ตัวอย่างเปิดค่าต่าง ๆ ไว้สำหรับเรียนรู้และตรวจคำตอบ")
    print("ฟังก์ชันกู้คืนใช้เพียงส่วนแบ่ง ไม่ได้อ่าน SECRET หรือสัมประสิทธิ์มาหาคำตอบ")


def read_integer(prompt, minimum, maximum):
    """ถามซ้ำจนกว่าจะได้จำนวนเต็มที่อยู่ในช่วง"""
    while True:
        try:
            value = int(input(prompt))
            if minimum <= value <= maximum:
                return value
        except ValueError:
            pass
        print(f"กรอกจำนวนเต็มตั้งแต่ {minimum} ถึง {maximum} นะครับ")


def read_shares():
    """รับส่วนแบ่งที่จดไว้ เพื่อกู้คืนโดยไม่ต้องมีความลับต้นฉบับ"""
    count = read_integer("จะใช้กี่ส่วน (3-5): ", MIN_SHARES, TOTAL_SHARES)
    shares = []
    while len(shares) < count:
        text = input(f"ส่วนที่ {len(shares) + 1} กรอก x y เช่น 1 41335: ")
        try:
            # รับได้ทั้ง 1 41335 และ 1,41335
            x, y = map(int, text.replace(",", " ").split())
            if not 1 <= x <= TOTAL_SHARES or not 0 <= y < PRIME:
                raise ValueError("ค่าอยู่นอกช่วง")
            if any(old_x == x for old_x, _ in shares):
                print("คนนี้ส่งส่วนแบ่งแล้ว เลือกคนอื่นอีกคนครับ")
                continue
            shares.append((x, y))
        except ValueError:
            print(f"กรอกเลข 2 ตัว โดย x อยู่ในช่วง 1-5 และ y อยู่ในช่วง 0-{PRIME - 1}")
    return shares


# Encrypted state (Phase 2) — AES-256-GCM + Argon2id.
# Required: pip install cryptography argon2-cffi
# This file deliberately does not bundle third-party cryptographic implementations.

STATE_VERSION = 2
KDF_TIME = 3
KDF_MEMORY_KIB = 65536
KDF_PARALLELISM = 2


def crypto_modules():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.exceptions import InvalidTag
        from argon2.low_level import Type, hash_secret_raw
    except ImportError as exc:
        raise RuntimeError(
            "ต้องติดตั้ง dependencies ก่อน: python3 -m pip install cryptography argon2-cffi"
        ) from exc
    return AESGCM, InvalidTag, Type, hash_secret_raw


def state_dir():
    configured_base = os.environ.get("XDG_STATE_HOME")
    base = Path(configured_base) if configured_base else Path.home() / ".local" / "state"
    return base / "shamir-secret-sharing"


def state_path():
    """ที่เก็บข้อมูลเข้ารหัส (Phase 2)"""
    return state_dir() / "shares.enc"


def legacy_state_path():
    """ชื่อไฟล์เดิมจาก Phase 1: ยังไม่เข้ารหัส"""
    return state_dir() / "shares.json"


def validate_shares(shares):
    if not isinstance(shares, list) or len(shares) != TOTAL_SHARES:
        raise ValueError("ไฟล์บันทึกต้องมีส่วนแบ่งครบ 5 ชุด")
    if any(not isinstance(p, (list, tuple)) or len(p) != 2 for p in shares):
        raise ValueError("ส่วนแบ่งมีรูปแบบไม่ถูกต้อง")
    result = [tuple(p) for p in shares]
    recovered = recover_secret(result[:MIN_SHARES])
    if any(recover_secret(group) != recovered for group in combinations(result, MIN_SHARES)):
        raise ValueError("ส่วนแบ่งไม่สอดคล้องกับพหุนามเดียวกัน")
    if {x for x, _ in result} != set(range(1, TOTAL_SHARES + 1)):
        raise ValueError("หมายเลขผู้ถือส่วนแบ่งต้องเป็น 1 ถึง 5")
    return sorted(result)


def _atomic_write(path, data):
    directory = path.parent
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    if directory.is_symlink() or path.is_symlink():
        raise ValueError("ไม่อนุญาตให้ State path เป็น symbolic link")
    if os.name == "posix":
        os.chmod(directory, 0o700)
    fd, temporary = tempfile.mkstemp(prefix=".shares-", dir=str(directory))
    try:
        if os.name == "posix":
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        if os.name == "posix":
            dir_fd = os.open(str(directory), os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _derive_key(password, salt, *, time_cost=KDF_TIME, memory_cost=KDF_MEMORY_KIB,
                parallelism=KDF_PARALLELISM):
    _, _, Type, hash_secret_raw = crypto_modules()
    if not isinstance(password, str) or not password:
        raise ValueError("ต้องตั้งรหัสผ่านที่ไม่ว่าง")
    return hash_secret_raw(password.encode("utf-8"), salt, time_cost=time_cost,
                           memory_cost=memory_cost, parallelism=parallelism,
                           hash_len=32, type=Type.ID)


def _encode(data):
    return base64.b64encode(data).decode("ascii")


def _decode(data):
    if not isinstance(data, str):
        raise ValueError("ข้อมูลเข้ารหัสไม่ถูกต้อง")
    return base64.b64decode(data, validate=True)


def save_shares(shares, password):
    """บันทึกเฉพาะ Ciphertext ไม่มี Plaintext State บนดิสก์"""
    AESGCM, _, _, _ = crypto_modules()
    normalized = validate_shares(shares)
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    kdf = {"name": "argon2id", "time": KDF_TIME,
           "memory_kib": KDF_MEMORY_KIB, "parallelism": KDF_PARALLELISM}
    envelope = {"version": STATE_VERSION, "cipher": "AES-256-GCM", "kdf": kdf,
                "salt": _encode(salt), "nonce": _encode(nonce)}
    aad = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")
    plaintext = json.dumps({"prime": PRIME, "shares": normalized},
                           separators=(",", ":")).encode("utf-8")
    key = _derive_key(password, salt)
    envelope["ciphertext"] = _encode(AESGCM(key).encrypt(nonce, plaintext, aad))
    _atomic_write(state_path(), json.dumps(envelope, separators=(",", ":")).encode("utf-8"))


def load_shares(password):
    path = state_path()
    if not path.exists():
        return None
    AESGCM, InvalidTag, _, _ = crypto_modules()
    try:
        envelope = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(envelope, dict) or envelope.get("version") != STATE_VERSION or envelope.get("cipher") != "AES-256-GCM":
            raise ValueError("เวอร์ชันหรือรูปแบบไฟล์เข้ารหัสไม่รองรับ")
        kdf = envelope["kdf"]
        if kdf.get("name") != "argon2id":
            raise ValueError("ชนิด KDF ไม่รองรับ")
        time_cost, memory_cost, parallelism = kdf["time"], kdf["memory_kib"], kdf["parallelism"]
        # Avoid malicious files requesting excessive resource use.
        if not all(type(x) is int for x in (time_cost, memory_cost, parallelism)) or not (1 <= time_cost <= 10 and 8192 <= memory_cost <= 262144 and 1 <= parallelism <= 8):
            raise ValueError("พารามิเตอร์ KDF ไม่ถูกต้อง")
        salt, nonce, ciphertext = _decode(envelope["salt"]), _decode(envelope["nonce"]), _decode(envelope["ciphertext"])
        if len(salt) != 16 or len(nonce) != 12 or len(ciphertext) > 8192:
            raise ValueError("ขนาดไฟล์เข้ารหัสผิดปกติ")
        header = {name: envelope[name] for name in ("version", "cipher", "kdf", "salt", "nonce")}
        aad = json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")
        key = _derive_key(password, salt, time_cost=time_cost, memory_cost=memory_cost,
                          parallelism=parallelism)
        plain = AESGCM(key).decrypt(nonce, ciphertext, aad)
        data = json.loads(plain)
        if data.get("prime") != PRIME:
            raise ValueError("มอดูลัสของไฟล์ไม่ตรงกับโปรแกรม")
        return validate_shares(data["shares"])
    except InvalidTag as exc:
        raise ValueError("รหัสผ่านไม่ถูกต้อง หรือไฟล์เข้ารหัสถูกแก้ไข") from exc
    except (KeyError, TypeError, UnicodeDecodeError, json.JSONDecodeError, base64.binascii.Error) as exc:
        raise ValueError("ไฟล์ State เสียหายหรือมีรูปแบบไม่ถูกต้อง") from exc


def load_legacy_shares():
    path = legacy_state_path()
    if not path.exists():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("version") != 1 or data.get("prime") != PRIME:
        raise ValueError("ไฟล์ State เวอร์ชันเดิมไม่ถูกต้อง")
    return validate_shares(data["shares"])


def export_one_share(shares, holder, destination):
    """Export only one share, using an exclusive 0600 file (never overwrite)."""
    normalized = validate_shares(shares)
    if type(holder) is not int or holder not in range(1, TOTAL_SHARES + 1):
        raise ValueError("หมายเลขผู้ถือส่วนแบ่งต้องเป็น 1 ถึง 5")
    path = Path(destination).expanduser()
    if not path.name or not path.parent.is_dir():
        raise ValueError("โฟลเดอร์ปลายทางไม่มีอยู่")
    x, y = normalized[holder - 1]
    data = ("SHAMIR SHARE v1\n"
            f"holder={x}\nvalue={y}\nprime={PRIME}\n"
            f"threshold={MIN_SHARES}\ntotal={TOTAL_SHARES}\n").encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(str(path), flags, 0o600)
    try:
        if os.name == "posix":
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise
    return path


def delete_saved_shares():
    state_path().unlink(missing_ok=True)


def prompt_new_password():
    """Ask until a valid confirmed password is provided or the user cancels.

    A rejected password never exits the application or modifies saved state.
    Ctrl+C / Ctrl+D are handled by the interactive entry point.
    """
    print("กำหนดรหัสผ่านอย่างน้อย 12 ตัวอักษร (อักขระจะไม่แสดงขณะพิมพ์)")
    print("หากต้องการยกเลิก ให้พิมพ์ /cancel ที่ช่องรหัสผ่าน")
    while True:
        password = getpass.getpass("ตั้งรหัสผ่านสำหรับไฟล์ State: ")
        if password == "/cancel":
            print("ยกเลิกการตั้งรหัสผ่าน — ไม่มีข้อมูลถูกเขียนทับ")
            return None
        if len(password) < 12:
            print("[!] รหัสผ่านสั้นเกินไป ต้องยาวอย่างน้อย 12 ตัวอักษร กรุณาลองใหม่")
            continue
        confirmation = getpass.getpass("ยืนยันรหัสผ่านอีกครั้ง: ")
        if confirmation == "/cancel":
            print("ยกเลิกการตั้งรหัสผ่าน — ไม่มีข้อมูลถูกเขียนทับ")
            return None
        if not hmac.compare_digest(password.encode("utf-8"), confirmation.encode("utf-8")):
            print("[!] รหัสผ่านไม่ตรงกัน กรุณากรอกใหม่ทั้งสองครั้ง")
            continue
        return password


def clean_setup():
    """Create a new encrypted state after explicit confirmation, as in C."""
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        print("การตั้งค่าใหม่ต้องใช้เทอร์มินัลแบบโต้ตอบ", file=sys.stderr)
        return 1

    print(f"ตั้งค่า shmir ใหม่\nไฟล์ State: {state_path()}")
    print("การตั้งค่าสำเร็จจะเขียนทับ shares.enc และลบ shares.json เดิม")
    print("Python และ C ใช้ไฟล์ชุดเดียวกัน การเปลี่ยนแปลงนี้ย้อนกลับไม่ได้")
    try:
        if input("พิมพ์ RESET SHMIR เพื่อยืนยัน: ") != "RESET SHMIR":
            print("ยกเลิกการตั้งค่า")
            return 1
        try:
            secret = int(input(f"กรอกเลขความลับใหม่ (0-{PRIME - 1}): "))
            shares = split_secret(secret)
        except ValueError:
            print(f"เลขความลับต้องเป็นจำนวนเต็ม 0-{PRIME - 1}", file=sys.stderr)
            return 1
        password = prompt_new_password()
        if password is None:
            return 1
    except (EOFError, KeyboardInterrupt):
        print("\nยกเลิกการตั้งค่า")
        return 1

    try:
        save_shares(shares, password)
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"บันทึก State ใหม่ไม่สำเร็จ: {exc}", file=sys.stderr)
        return 1

    try:
        if load_shares(password) != shares:
            raise ValueError("ส่วนแบ่งที่อ่านกลับมาไม่ตรงกับส่วนแบ่งที่สร้าง")
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"ตรวจสอบ State ใหม่ไม่สำเร็จ: {exc} — เก็บ shares.json เดิมไว้", file=sys.stderr)
        return 1

    try:
        legacy_state_path().unlink(missing_ok=True)
    except OSError as exc:
        print(f"บันทึก State ใหม่แล้ว แต่ลบ shares.json ไม่สำเร็จ: {exc}", file=sys.stderr)
        return 1
    print("สร้างและตรวจสอบ State เข้ารหัสใหม่เรียบร้อยแล้ว และจัดการไฟล์เดิมแล้ว")
    return 0


def initialize_state():
    """คืน (shares, password); never silently load unencrypted legacy data."""
    if state_path().exists():
        for attempt in range(3):
            password = getpass.getpass("รหัสผ่านเพื่อปลดล็อก State: ")
            try:
                shares = load_shares(password)
                print("ปลดล็อกและโหลดส่วนแบ่งที่เข้ารหัสแล้ว")
                return shares, password
            except (ValueError, RuntimeError, OSError) as exc:
                print(f"ปลดล็อกไม่สำเร็จ ({attempt + 1}/3): {exc}")
        print("ไม่สามารถปลดล็อก State ได้ — ยกเลิกเพื่อป้องกันการเขียนทับข้อมูล")
        return None, None
    if legacy_state_path().exists():
        print("พบ shares.json จาก Phase 1 ซึ่งยังไม่ได้เข้ารหัส")
        answer = input("ย้ายไปเป็นไฟล์เข้ารหัสตอนนี้หรือไม่? (พิมพ์ YES): ").strip()
        if answer != "YES":
            print("ยังไม่เปลี่ยนข้อมูลเดิม — ยกเลิกการเปิดเมนู")
            return None, None
        try:
            shares = load_legacy_shares()
        except (ValueError, TypeError, OSError) as exc:
            print(f"ไม่สามารถย้ายไฟล์เดิม: {exc}")
            return None, None
        password = prompt_new_password()
        if password is None:
            return None, None
        try:
            save_shares(shares, password)
            if load_shares(password) != shares:
                raise ValueError("ตรวจสอบไฟล์ที่ย้ายไม่สำเร็จ")
        except (OSError, ValueError, RuntimeError) as exc:
            print(f"ย้ายไฟล์ไม่สำเร็จ: {exc} — ไฟล์เดิมยังอยู่")
            return None, None
        print(f"ย้ายข้อมูลสำเร็จ: {state_path()}")
        print("เพื่อความปลอดภัย ไฟล์ shares.json เดิมยังคงอยู่ — กรุณาจัดการลบด้วยตนเองหลังสำรองข้อมูล")
        return shares, password
    return None, None

def run_interactive():
    print("ระบบแบ่งความลับแบบ 3-of-5 — Phase 2 Encrypted Storage")
    print(f"รับความลับเป็นจำนวนเต็ม 0-{PRIME - 1}")
    try:
        latest_shares, password = initialize_state()
    except (EOFError, KeyboardInterrupt):
        print("\nยกเลิกการปลดล็อก")
        return
    if (state_path().exists() or legacy_state_path().exists()) and password is None:
        # Without this pause the alternate screen disappears immediately,
        # making a cancellation/error look like a crash on macOS terminals.
        if sys.stdin.isatty() and sys.stdout.isatty():
            try:
                input("กด Enter เพื่อกลับไปยัง Terminal...")
            except (EOFError, KeyboardInterrupt):
                pass
        return
    print("ไฟล์ State ใหม่จะเข้ารหัสด้วย AES-256-GCM และ Argon2id")
    print("อย่าลืมรหัสผ่าน: ไม่มีระบบกู้คืนรหัสผ่านจากไฟล์เข้ารหัส")
    print("หมายเหตุ: นี่เป็นโครงงานสาธิต ไม่ใช่ระบบเก็บความลับที่ผ่านการตรวจสอบความปลอดภัย")

    while True:
        print("\n1. แบ่งความลับใหม่ให้ 5 คน")
        print("2. กรอกส่วนแบ่งเพื่อกู้คืนความลับ")
        print("3. เลือกคนจากส่วนแบ่งที่สร้างหรือโหลดไว้")
        print("4. ดูตัวอย่างและผลทดลองตามเอกสาร")
        print("5. ลบ State เข้ารหัสที่บันทึกไว้")
        print("6. ส่งออกส่วนแบ่งหนึ่งชุดให้ผู้ถือ (ไฟล์ไม่เข้ารหัส)")
        print("0. ออกจากโปรแกรม")
        choice = input("เลือกเมนู: ").strip()
        if choice == "0":
            print("จบการทำงานครับ")
            return
        if choice == "1":
            secret = read_integer("กรอกเลขความลับ: ", 0, PRIME - 1)
            shares = split_secret(secret)
            del secret
            if password is None:
                print("ตั้งรหัสผ่านเพื่อเริ่มบันทึก State เข้ารหัส")
                candidate = prompt_new_password()
                if candidate is None:
                    print("ยกเลิกการสร้าง State")
                    continue
            else:
                candidate = password
            try:
                save_shares(shares, candidate)
            except (OSError, ValueError, RuntimeError) as exc:
                print(f"บันทึกไม่สำเร็จ: {exc} — ข้อมูลเดิมยังคงอยู่")
                continue
            password = candidate
            latest_shares = shares
            print(f"บันทึกส่วนแบ่งแบบเข้ารหัสไว้แล้ว: {state_path()}")
            for x, y in latest_shares:
                print(f"คนที่ {x}: {x} {y}")
            print("ส่วนแบ่งต่างรอบไม่ควรนำมาปนกัน")
        elif choice == "2":
            selected = read_shares()
            print(f"ความลับที่คำนวณได้: {recover_secret(selected)}")
            print("ต้องมั่นใจว่าทุกส่วนถูกต้องและมาจากรอบเดียวกัน")
        elif choice == "3":
            if latest_shares is None:
                print("ยังไม่มีส่วนแบ่ง ลองเลือกเมนู 1 ก่อนครับ")
                continue
            text = input("เลือกหมายเลขคนอย่างน้อย 3 คน เช่น 1 3 5: ")
            try:
                holders = list(map(int, text.replace(",", " ").split()))
                if not MIN_SHARES <= len(holders) <= TOTAL_SHARES or len(set(holders)) != len(holders) or any(x not in range(1, TOTAL_SHARES + 1) for x in holders):
                    raise ValueError("เลือกหมายเลข 1–5 ไม่ซ้ำกัน จำนวน 3–5 คน")
                selected = [latest_shares[x - 1] for x in holders]
                print(f"ความลับที่กู้คืนได้: {recover_secret(selected)}")
            except ValueError as exc:
                print(f"กู้คืนไม่ได้: {exc}")
        elif choice == "4":
            run_demo()
        elif choice == "5":
            if input("ลบไฟล์ State เข้ารหัส? (พิมพ์ YES): ").strip() == "YES":
                try:
                    delete_saved_shares()
                    latest_shares = None
                    password = None
                    print("ลบไฟล์ State เข้ารหัสแล้ว (ไม่ใช่การลบข้อมูลอย่างปลอดภัย)")
                    if legacy_state_path().exists():
                        print("คำเตือน: shares.json เดิมยังอยู่ และไม่ได้เข้ารหัส")
                except OSError as exc:
                    print(f"ลบไม่สำเร็จ: {exc}")
            else:
                print("ยกเลิก")
        elif choice == "6":
            if latest_shares is None:
                print("ยังไม่มีส่วนแบ่ง กรุณาเลือกเมนู 1 หรือปลดล็อก State ก่อน")
                continue
            print("คำเตือน: ส่วนแบ่งที่ส่งออกเป็นข้อความอ่านได้ กรุณาเก็บแต่ละไฟล์แยกกัน")
            print("ห้ามส่งส่วนแบ่งครบ 3 ชุดไปยังผู้รับหรือพื้นที่เก็บเดียวกัน")
            try:
                holder = read_integer("เลือกหมายเลขผู้ถือส่วนแบ่ง (1–5): ", 1, TOTAL_SHARES)
                destination = input("พาธไฟล์ใหม่ เช่น ~/Documents/share-1.txt: ").strip()
                if not destination:
                    print("ยกเลิก: ไม่ได้ระบุพาธ")
                    continue
                if input("ยืนยันส่งออกไฟล์ที่ไม่เข้ารหัส? (พิมพ์ YES): ").strip() != "YES":
                    print("ยกเลิก")
                    continue
                path = export_one_share(latest_shares, holder, destination)
                print(f"ส่งออกส่วนแบ่งหมายเลข {holder} สำเร็จ: {path}")
                print("ไฟล์ต้นทาง shares.enc ยังอยู่ และยังเก็บส่วนแบ่งทั้ง 5 ชุด")
            except (ValueError, OSError) as exc:
                print(f"ส่งออกไม่สำเร็จ: {exc}")
        else:
            print("เลือกเมนู 0 ถึง 6 ครับ")


# ------------------------------------------------------------------
# Self-tests: python3 Shamir_Phase2_Secure.py --test
# ------------------------------------------------------------------
import unittest
import subprocess
from unittest.mock import patch

class ShamirPhase2Tests(unittest.TestCase):
    TEST_PASSWORD = "correct horse battery staple"

    def test_document_example(self):
        self.assertEqual(create_shares(SECRET, A1, A2),
                         [(1, 41335), (2, 41618), (3, 42065), (4, 42676), (5, 43451)])

    def test_every_eligible_combination(self):
        for secret in (0, 1, 41216, PRIME - 1):
            shares = split_secret(secret)
            for count in (3, 4, 5):
                for group in combinations(shares, count):
                    self.assertEqual(recover_secret(group), secret)

    def test_invalid_share_sets(self):
        shares = split_secret(1234)
        with self.assertRaises(ValueError): recover_secret(shares[:2])
        with self.assertRaises(ValueError): recover_secret([shares[0]] * 3)
        with self.assertRaises(ValueError): split_secret(PRIME)
        with self.assertRaises(ValueError): create_shares(1234, 37, 0)

    def test_encrypted_roundtrip_and_delete(self):
        with tempfile.TemporaryDirectory() as d, patch.dict(os.environ, {"XDG_STATE_HOME": d}):
            shares = split_secret(41216)
            self.assertIsNone(load_shares(self.TEST_PASSWORD))
            save_shares(shares, self.TEST_PASSWORD)
            raw = state_path().read_bytes()
            self.assertNotIn(b'"shares"', raw)
            self.assertNotIn(b'41216', raw)
            self.assertEqual(load_shares(self.TEST_PASSWORD), shares)
            self.assertEqual(recover_secret(load_shares(self.TEST_PASSWORD)[::2]), 41216)
            if os.name == "posix":
                self.assertEqual(state_path().stat().st_mode & 0o777, 0o600)
                self.assertEqual(state_dir().stat().st_mode & 0o777, 0o700)
            delete_saved_shares()
            self.assertIsNone(load_shares(self.TEST_PASSWORD))

    def test_wrong_password_rejected(self):
        with tempfile.TemporaryDirectory() as d, patch.dict(os.environ, {"XDG_STATE_HOME": d}):
            save_shares(split_secret(42), self.TEST_PASSWORD)
            with self.assertRaisesRegex(ValueError, "รหัสผ่านไม่ถูกต้อง"):
                load_shares("a different password")

    def test_tampering_detected(self):
        with tempfile.TemporaryDirectory() as d, patch.dict(os.environ, {"XDG_STATE_HOME": d}):
            save_shares(split_secret(42), self.TEST_PASSWORD)
            path = state_path()
            payload = json.loads(path.read_text())
            data = bytearray(_decode(payload["ciphertext"]))
            data[0] ^= 1
            payload["ciphertext"] = _encode(data)
            path.write_text(json.dumps(payload))
            with self.assertRaisesRegex(ValueError, "ไฟล์เข้ารหัสถูกแก้ไข"):
                load_shares(self.TEST_PASSWORD)

    def test_nonces_and_salts_fresh(self):
        with tempfile.TemporaryDirectory() as d, patch.dict(os.environ, {"XDG_STATE_HOME": d}):
            shares = split_secret(42)
            save_shares(shares, self.TEST_PASSWORD)
            first = json.loads(state_path().read_text())
            save_shares(shares, self.TEST_PASSWORD)
            second = json.loads(state_path().read_text())
            self.assertNotEqual(first["salt"], second["salt"])
            self.assertNotEqual(first["nonce"], second["nonce"])
            self.assertNotEqual(first["ciphertext"], second["ciphertext"])

    def test_migrate_legacy_without_deletion(self):
        with tempfile.TemporaryDirectory() as d, patch.dict(os.environ, {"XDG_STATE_HOME": d}):
            shares = split_secret(41216)
            legacy_state_path().parent.mkdir(parents=True)
            legacy_state_path().write_text(json.dumps({"version": 1, "prime": PRIME, "shares": shares}))
            with patch('builtins.input', return_value='YES'), patch('getpass.getpass', side_effect=[self.TEST_PASSWORD, self.TEST_PASSWORD]):
                migrated, password = initialize_state()
            self.assertEqual(migrated, shares)
            self.assertEqual(password, self.TEST_PASSWORD)
            self.assertEqual(load_shares(password), shares)
            self.assertTrue(legacy_state_path().exists())

    def test_restart_state(self):
        with tempfile.TemporaryDirectory() as d, patch.dict(os.environ, {"XDG_STATE_HOME": d}):
            shares = split_secret(41216)
            save_shares(shares, self.TEST_PASSWORD)
            self.assertEqual(recover_secret(load_shares(self.TEST_PASSWORD)[::2]), 41216)
            with patch('getpass.getpass', return_value=self.TEST_PASSWORD):
                recovered, password = initialize_state()
            self.assertEqual(recovered, shares)
            self.assertEqual(password, self.TEST_PASSWORD)

    def test_export_one_share_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            shares = split_secret(41216)
            path = Path(directory) / "holder-2.txt"
            self.assertEqual(export_one_share(shares, 2, path), path)
            exported = path.read_text(encoding="utf-8")
            self.assertIn("SHAMIR SHARE v1", exported)
            self.assertIn(f"holder=2\nvalue={shares[1][1]}", exported)
            self.assertNotIn(f"holder=1\nvalue={shares[0][1]}", exported)
            with self.assertRaises(FileExistsError):
                export_one_share(shares, 2, path)
            with self.assertRaises(ValueError):
                export_one_share(shares, 7, Path(directory) / "bad.txt")
            if os.name == "posix":
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_password_retry_short_then_mismatch_then_success(self):
        with patch('getpass.getpass', side_effect=[
            "short", self.TEST_PASSWORD, "not-the-same-password",
            self.TEST_PASSWORD, self.TEST_PASSWORD
        ]) as mocked:
            self.assertEqual(prompt_new_password(), self.TEST_PASSWORD)
            self.assertEqual(mocked.call_count, 5)

    def test_password_cancel_does_not_write_state(self):
        with tempfile.TemporaryDirectory() as d, patch.dict(os.environ, {"XDG_STATE_HOME": d}):
            with patch('getpass.getpass', side_effect=["too-short", "/cancel"]):
                self.assertIsNone(prompt_new_password())
            self.assertFalse(state_path().exists())

    def test_migrate_retries_bad_password_without_losing_original(self):
        with tempfile.TemporaryDirectory() as d, patch.dict(os.environ, {"XDG_STATE_HOME": d}):
            shares = split_secret(41216)
            legacy_state_path().parent.mkdir(parents=True)
            legacy_state_path().write_text(json.dumps({"version": 1, "prime": PRIME, "shares": shares}))
            with patch('builtins.input', return_value='YES'), patch('getpass.getpass', side_effect=[
                'short', self.TEST_PASSWORD, 'mismatch', self.TEST_PASSWORD, self.TEST_PASSWORD
            ]):
                migrated, password = initialize_state()
            self.assertEqual(migrated, shares)
            self.assertEqual(load_shares(password), shares)
            self.assertTrue(legacy_state_path().exists())

    def test_help_commands(self):
        script = str(Path(__file__).resolve())
        for argument in ('help', '-h', '--help'):
            result = subprocess.run([sys.executable, script, argument], text=True,
                                    capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('--test', result.stdout)
            self.assertIn('--setup', result.stdout)

    def test_setup_rejects_redirected_input(self):
        result = subprocess.run([sys.executable, str(Path(__file__).resolve()), "--setup"],
                                input="RESET SHMIR\n42\n", text=True,
                                capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 1)
        self.assertIn("เทอร์มินัลแบบโต้ตอบ", result.stderr)

    def test_setup_cancel_preserves_both_state_files(self):
        with tempfile.TemporaryDirectory() as d, patch.dict(os.environ, {"XDG_STATE_HOME": d}):
            state_dir().mkdir()
            state_path().write_bytes(b"original encrypted state")
            legacy_state_path().write_bytes(b"original plaintext state")
            for responses, passwords in [
                (["reset shmir"], []),
                (["RESET SHMIR", "50021"], []),
                (["RESET SHMIR", "42"], ["/cancel"]),
            ]:
                with self.subTest(responses=responses), \
                        patch.object(sys.stdin, "isatty", return_value=True), \
                        patch.object(sys.stdout, "isatty", return_value=True), \
                        patch("builtins.input", side_effect=responses), \
                        patch("getpass.getpass", side_effect=passwords):
                    self.assertEqual(clean_setup(), 1)
                    self.assertEqual(state_path().read_bytes(), b"original encrypted state")
                    self.assertEqual(legacy_state_path().read_bytes(), b"original plaintext state")

    def test_setup_replaces_state_and_removes_legacy_after_verification(self):
        with tempfile.TemporaryDirectory() as d, patch.dict(os.environ, {"XDG_STATE_HOME": d}):
            save_shares(split_secret(1234), self.TEST_PASSWORD)
            legacy_state_path().write_bytes(b"original plaintext state")
            password = "รหัสผ่านใหม่ทดสอบ"
            with patch.object(sys.stdin, "isatty", return_value=True), \
                    patch.object(sys.stdout, "isatty", return_value=True), \
                    patch("builtins.input", side_effect=["RESET SHMIR", "42"]), \
                    patch("getpass.getpass", side_effect=[password, password]):
                self.assertEqual(clean_setup(), 0)
            self.assertEqual(recover_secret(load_shares(password)[:MIN_SHARES]), 42)
            self.assertFalse(legacy_state_path().exists())

    def test_setup_preserves_legacy_when_verification_fails(self):
        with tempfile.TemporaryDirectory() as d, patch.dict(os.environ, {"XDG_STATE_HOME": d}):
            state_dir().mkdir()
            legacy_state_path().write_bytes(b"original plaintext state")
            with patch.object(sys.stdin, "isatty", return_value=True), \
                    patch.object(sys.stdout, "isatty", return_value=True), \
                    patch("builtins.input", side_effect=["RESET SHMIR", "42"]), \
                    patch("getpass.getpass", return_value=self.TEST_PASSWORD), \
                    patch(__name__ + ".load_shares", return_value=None):
                self.assertEqual(clean_setup(), 1)
            self.assertEqual(legacy_state_path().read_bytes(), b"original plaintext state")


def main():
    parser = argparse.ArgumentParser(
        description="Shamir Secret Sharing 3-of-5 — Phase 2: Encrypted State (AES-256-GCM + Argon2id)",
        epilog="ตัวอย่าง: python3 Shamir_Phase2_Secure_Fixed.py --setup",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--demo", action="store_true", help="แสดงตัวอย่างตาม PDF (ไม่ใช้ไฟล์ State)")
    parser.add_argument("--setup", action="store_true", help="ตั้งค่า State เข้ารหัสใหม่แทนข้อมูลเดิม (ต้องยืนยัน)")
    parser.add_argument(
        "--no-alt-screen", action="store_true",
        help="แสดงผลบนหน้าจอ Terminal ปกติ (ไม่คืนหน้าจอเดิมเมื่อออก)",
    )
    parser.add_argument("--test", action="store_true", help="รัน Unit Tests ในไฟล์เดียว (รวมทดสอบรหัสผ่าน)")
    # รองรับทั้งคำสั่งแบบมาตรฐาน --help/-h และแบบอ่านง่าย help
    if len(sys.argv) == 2 and sys.argv[1].lower() == "help":
        parser.print_help()
        return 0
    args = parser.parse_args()
    if args.test:
        import unittest
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(ShamirPhase2Tests)
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        return 0 if result.wasSuccessful() else 1
    if args.setup:
        return clean_setup()
    with alternate_screen(enabled=not args.no_alt_screen):
        try:
            if args.demo:
                run_demo()
            else:
                run_interactive()
        except (EOFError, KeyboardInterrupt):
            print("\nจบการทำงานครับ")


if __name__ == "__main__":
    sys.exit(main())
