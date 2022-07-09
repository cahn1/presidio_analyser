import re
from Crypto.Hash import keccak
from hashlib import sha256
from typing import List, Optional
from presidio_analyzer import Pattern, PatternRecognizer

# Referred to:
# https://gist.github.com/MBrassey/623f7b8d02766fa2d826bf9eca3fe005
# https://github.com/vgaicuks/ethereum-address/blob/master/ethereum_address
# /utils.py


class CryptoEthereumRecognizer(PatternRecognizer):
    """Recognize common crypto account numbers using regex + checksum.

    :param patterns: List of patterns to be used by this recognizer
    :param context: List of context words to increase confidence in detection
    :param supported_language: Language this recognizer supports
    :param supported_entity: The entity this recognizer can detect
    """

    PATTERNS = [
        Pattern("Crypto (Medium)", r"^0x[a-fA-F0-9]{40}$", 0.5),
    ]

    CONTEXT = ["wallet", "eth", "ethereum"]

    def __init__(
        self,
        patterns: Optional[List[Pattern]] = None,
        context: Optional[List[str]] = None,
        supported_language: str = "en",
        supported_entity: str = "ETH_WALLET",
    ):
        patterns = patterns if patterns else self.PATTERNS
        context = context if context else self.CONTEXT
        super().__init__(
            supported_entity=supported_entity,
            patterns=patterns,
            context=context,
            supported_language=supported_language,
        )

    def validate_result(self, pattern_text: str) -> bool:  # noqa D102
        if re.match(r'^(0x)?[0-9a-fA-F]{40}$', pattern_text,
                        flags=re.IGNORECASE):
            return True
        return self.__is_checksum_address(pattern_text)

    @staticmethod
    def __is_checksum_address(pattern_text: str) -> bool:
        address = pattern_text.replace('0x', '')
        address_hash = keccak.new(digest_bits=256)
        address_hash = \
            address_hash.update(address.lower().encode('utf-8')).hexdigest()

        for i in range(0, 40):
            # The nth letter should be uppercase if the nth digit of casemap is 1
            if ((int(address_hash[i], 16) > 7 and address[i].upper() != address[i]) or
                    (int(address_hash[i], 16) <= 7 and address[i].lower() != address[i])):
                return False
        return True
