from collections import defaultdict
from typing import List, Optional

from presidio_analyzer import Pattern, PatternRecognizer


class KrSsnRecognizer(PatternRecognizer):
    """Recognize Korean Residential Identification Number using regex.
    https://regexlib.com/REDetails.aspx?regexp_id=3076&AspxAutoDetectCookieSupport=1

    :param patterns: List of patterns to be used by this recognizer
    :param context: List of context words to increase confidence in detection
    :param supported_language: Language this recognizer supports
    :param supported_entity: The entity this recognizer can detect
    """

    PATTERNS = [
        Pattern("SSN1 (very weak)", r"\b(\d{6})[- ](\d{7})\b", 0.05),
        Pattern("SSN2 (very weak)", r"\b\d{13}\b", 0.05),
        Pattern("SSN3 (medium)", r"\b(?:\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[1,"
                                 r"2]\d|3[0,1]))[- ][1-4]\d{6}\b", 0.5),
    ]

    CONTEXT = [
        "resident registration number",
        "resident registration#",
        "national identification number",
        "national identification#",
        "주민등록번호",
    ]

    def __init__(
        self,
        patterns: Optional[List[Pattern]] = None,
        context: Optional[List[str]] = None,
        supported_language: str = "en",
        supported_entity: str = "KR_SSN",
    ):
        patterns = patterns if patterns else self.PATTERNS
        context = context if context else self.CONTEXT
        super().__init__(
            supported_entity=supported_entity,
            patterns=patterns,
            context=context,
            supported_language=supported_language,
        )

    def invalidate_result(self, pattern_text: str) -> bool:
        """
        Check if the pattern text cannot be validated as a KR_SSN entity.

        :param pattern_text: Text detected as pattern by regex
        :return: True if invalidated
        """
        # if there are delimiters, make sure both delimiters are the same
        delimiter_counts = defaultdict(int)
        for c in pattern_text:
            if c in (".", "-", " "):
                delimiter_counts[c] += 1
        if len(delimiter_counts.keys()) > 1:
            # mismatched delimiters
            return True

        only_digits = "".join(c for c in pattern_text if c.isdigit())
        if all(only_digits[0] == c for c in only_digits):
            # cannot be all same digit
            return True

        if only_digits[0:3] == "0000" or only_digits[6:8] == "000":
            # groups cannot be all zeros
            return True

        for sample_ssn in ("121356789", "120056789", "0780515200982",
                           "0780510200982"):
            if only_digits.startswith(sample_ssn):
                return True

        return False
