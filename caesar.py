def caesar_cipher(text, shift, mode):
    shift = shift % 26
    result = ""
    for ch in text:
        if ch.isalpha() and ('A' <= ch <= 'Z' or 'a' <= ch <= 'z'):
            base = ord('A') if ch.isupper() else ord('a')
            if mode == "encrypt":
                result += chr((ord(ch) - base + shift) % 26 + base)
            else:  # decrypt
                result += chr((ord(ch) - base - shift) % 26 + base)
        else:
            result += ch
    return result


def get_mode():
    while True:
        m = input("Do you want to encrypt or decrypt? ").strip().lower()
        if m in ("encrypt", "e"):
            return "encrypt"
        if m in ("decrypt", "d"):
            return "decrypt"
        print("Please type 'encrypt' or 'decrypt' (or e/d).")


def get_shift():
    while True:
        s = input("Enter shift number (e.g., 3): ").strip()
        try:
            return int(s)
        except ValueError:
            print("Invalid number — try again.")


def main():
    mode = get_mode()
    message = input("Enter the message: ")
    shift = get_shift()
    result = caesar_cipher(message, shift, mode)
    print("\nResult:")
    print(result)


if __name__ == "_main_":
    main()