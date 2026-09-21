import os
import math
import hashlib
import mimetypes
from collections import Counter


def calculate_entropy(data):
    """
    Calculate Shannon entropy of the file bytes.
    Higher entropy can indicate compressed or encrypted content.
    """

    if not data:
        return 0.0

    counter = Counter(data)
    length = len(data)

    entropy = 0.0

    for count in counter.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def analyze_file(filepath):
    """
    Extract basic static features from ANY uploaded file.
    """

    filename = os.path.basename(filepath)

    # Read file as bytes
    with open(filepath, "rb") as f:
        data = f.read()

    size = len(data)

    # Hashes
    sha256 = hashlib.sha256(data).hexdigest()
    md5 = hashlib.md5(data).hexdigest()

    # Entropy
    entropy = calculate_entropy(data)

    # Printable characters
    printable = sum(
        32 <= byte <= 126
        for byte in data
    )

    printable_ratio = (
        printable / size
        if size > 0
        else 0
    )

    # Null bytes
    null_ratio = (
        data.count(0) / size
        if size > 0
        else 0
    )

    # File extension
    extension = os.path.splitext(filename)[1].lower()

    # MIME type
    mime_type, _ = mimetypes.guess_type(filename)

    # File signatures
    is_pe = data[:2] == b"MZ"

    is_pdf = data[:4] == b"%PDF"

    is_zip = data[:4] == b"PK\x03\x04"

    is_elf = data[:4] == b"\x7fELF"

    # Suspicious strings
    suspicious_terms = [
        b"ransom",
        b"encrypt",
        b"encrypted",
        b"decrypt",
        b"bitcoin",
        b"payment",
        b"powershell",
        b"cmd.exe",
        b"vssadmin",
        b"shadowcopy",
        b"delete",
        b"lockbit",
        b"wannacry"
    ]

    lower_data = data.lower()

    suspicious_strings = 0

    for term in suspicious_terms:
        if term in lower_data:
            suspicious_strings += 1

    # Return all statistics
    return {
        "filename": filename,
        "extension": extension,
        "mime_type": mime_type or "unknown",

        "size_bytes": size,

        "md5": md5,
        "sha256": sha256,

        "entropy": round(entropy, 4),

        "printable_ratio": round(
            printable_ratio, 4
        ),

        "null_ratio": round(
            null_ratio, 4
        ),

        "is_pe": int(is_pe),
        "is_pdf": int(is_pdf),
        "is_zip": int(is_zip),
        "is_elf": int(is_elf),

        "suspicious_strings": suspicious_strings
    }