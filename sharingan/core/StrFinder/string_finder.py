# String Finder - Detection and Mapping Only
from cgitb import reset
import idautils
import re
from math import log2

from .ignore_store import apply_ignore_store
from .result_filter import ResultFilter
from .string_extractor import FLOSSStringExtractor

MIN_LENGTH = 4

class StringFinder:
    """
    Finds encrypted strings and maps where they're used.
    NO DECRYPTION - just detection and location mapping.
    """

    def __init__(self, min_length: int = MIN_LENGTH):
        # Handle the filtering of results
        self.result_filter = ResultFilter()
        self.ignore_store = apply_ignore_store(self.result_filter)
        self.filter_results = self.result_filter.filter_results

        # FLOSS-inspired comprehensive string extractor
        self.extractor = FLOSSStringExtractor(min_length=min_length)

    def find_all_encrypted_strings(self):
        """Find all potentially encrypted strings"""
        print("[Sharingan] Scanning for potentially encrypted strings...")

        # Method 0: FLOSS-inspired extraction (static, stack, tight strings)
        # Static strings (raw segment scan)
        static_strings = list(self.extractor.extract_static_strings())
        print(f"[Sharingan]  Found {len(static_strings)} static strings")
        if static_strings:
            print(f"\t\t{[x['value'] for x in static_strings]}")
        
        # Stack strings (constructed on stack)
        stack_strings = list(self.extractor.extract_stack_strings())
        print(f"[Sharingan]   Found {len(stack_strings)} stack strings")
        if stack_strings:
            print(f"\t\t{[(x['value'], hex(x['address'])) for x in stack_strings]}")
        
        # Tight strings (push immediate sequences)
        tight_strings = list(self.extractor.extract_tight_strings())
        print(f"[Sharingan]   Found {len(tight_strings)} tight strings")
        if tight_strings:
            print(f"\t\t{[(x['value'], hex(x['address'])) for x in tight_strings]}")

        # Merge and deduplicate
        all_strings = self.merge_results(static_strings)
        print(f"[Sharingan]   Found {len(all_strings)} strings after merging")

        # Filter the results
        all_strings = self.filter_results(all_strings)
        print(f"[Sharingan]   Found {len(all_strings)} strings after filtering")
        
        # Add stack strings and tight strings to results
        print(f"[Sharingan]   Adding stack strings and tight strings to results")
        all_strings = self.merge_results(all_strings, stack_strings, tight_strings)

        # Method 1: Base64-like strings
        base64_strings = self.find_base64_strings(all_strings)
        print(f"[Sharingan - Extra]   Found {len(base64_strings)} base64-like strings \n\t\t{base64_strings}")

        # Method 2: High-entropy strings
        entropy_strings = self.find_high_entropy_strings(all_strings)
        print(f"[Sharingan - Extra]   Found {len(entropy_strings)} high-entropy strings \n\t\t{entropy_strings}")

        # Method 3: Pseudo-gibberish syllabic strings (obfuscated word-like sequences)
        gibberish_strings = self.find_pseudo_gibberish_strings(all_strings)
        print(f"[Sharingan - Extra]   Found {len(gibberish_strings)} pseudo-gibberish strings \n\t\t{gibberish_strings}")

        return all_strings
    
    # ------------------------------------------------------------------
    # Find base64-like strings
    # ------------------------------------------------------------------
    def find_base64_strings(self, strings):
        """Find base64-like strings"""
        ret = []

        for s in strings:
            value = str(s['value'])
            # Check if looks like base64
            if not self._looks_like_base64(value):
                continue
            ret.append(value)

        return ret

    def _looks_like_base64(self, s):
        """Check if string looks like base64 with stricter validation."""
        if len(s) < 4 or len(s) % 4 != 0:  # Base64 strings are typically divisible by 4
            return False

        # Count valid base64 characters
        valid_chars = sum(1 for c in s if c.isalnum() or c in '+/=')
        ratio = valid_chars / len(s)

        # Must be mostly alphanumeric + base64 chars
        if ratio < 0.95:  # Stricter ratio
            return False

        # Must have character diversity (not all same character)
        unique_chars = len(set(s))
        if unique_chars < 6:  # Increased diversity threshold
            return False

        return True

    # ------------------------------------------------------------------
    # Find high-entropy strings
    # ------------------------------------------------------------------
    def find_high_entropy_strings(self, strings):
        """Find strings with high entropy (likely encrypted) with additional checks."""
        ret = []

        for s in strings:
            value = str(s['value'])

            # Skip if too short
            if len(value) < 10:
                continue

            # Calculate entropy
            entropy = self._calculate_entropy(value)

            # Additional check: Ensure string is not plain text
            if entropy >= 4.5 and not self._is_plain_text(value):
                ret.append(value)

        return ret

    def _calculate_entropy(self, s):
        """Calculate Shannon entropy of string"""
        if not s:
            return 0.0

        # Count character frequencies
        char_counts = {}
        for c in s:
            char_counts[c] = char_counts.get(c, 0) + 1

        # Calculate entropy
        entropy = 0.0
        length = len(s)

        for count in char_counts.values():
            probability = count / length
            entropy -= probability * log2(probability)

        return entropy

    def _is_plain_text(self, s):
        """Check if string is likely plain text (e.g., readable words)."""
        # Character class coverage
        plain_text_chars = sum(1 for c in s if c.isalnum() or c in ' _-.,')
        ratio = plain_text_chars / len(s)
        if ratio < 0.7:  # Too many non word-like chars => not plain
            return False

        # Tokenize on whitespace/punctuation
        tokens = [t for t in re.split(r'[^A-Za-z]+', s) if t]
        if not tokens:
            return False
        # Small common English lexicon (kept minimal to avoid false negatives on obfuscated text)
        lexicon = {
            'the','and','for','with','this','that','from','have','will','info','name','file','data','value','init','error','open','close','read','write','key','user','system','thread','module','load','start','stop','length','time','date','mount','point','volume','lib'
        }
        english_hits = sum(1 for t in tokens if t.lower() in lexicon)
        english_ratio = english_hits / len(tokens)
        # If few real words detected, treat as NOT plain (likely obfuscated syllables)
        if english_ratio < 0.2 and len(s) >= 12:
            return False
        return ratio > 0.85 and english_ratio >= 0.2
    
    # ------------------------------------------------------------------
    # Pseudo-gibberish detection
    # ------------------------------------------------------------------
    def find_pseudo_gibberish_strings(self, strings):
        """
            Detect obfuscated pseudo-lexical strings composed of syllable-like tokens.
            Expanded to catch single-token randomized syllabic strings shorter than 12 chars
            (e.g. "Vibigezof", "hezahixejo") that were previously missed.
            
            Core heuristics (multi-token or long single-token >=12):
            - Total length >= 12
            - Low English dictionary token ratio (< 0.2)
            - High vowel/consonant alternation density (avg >= 0.5)
            - Diversity: >= 6 unique characters
            
            Short single-token mode (length 8..11):
            - Length between 8 and 11 inclusive
            - Alternation score >= 0.65
            - Vowel proportion between 0.35 and 0.65
            - Unique bigram count >= max(5, len(bigrams)//2)
            - Dictionary token ratio == 0
            
            Excludes: all-uppercase (likely module names), digit-heavy (digit ratio > 0.1),
            low-diversity (<6 unique chars).
        """
        ret = []
        vowels = set('aeiou')
        english_small = {
            'the','and','for','with','this','that','from','have','will','info','name','file','data','value','init','error','open','close','read','write','key','user','system','thread','module','load','start','stop','length','time','date','mount','point','volume','lib'
        }
        seen_addrs = set()

        syllable_run_re = re.compile(r'(?:[bcdfghjklmnpqrstvwxyz]{1,2}[aeiou]{1,2}){5,}', re.IGNORECASE)
        debug = False
        try:
            import os
            debug = os.getenv('DEBUG_ESF_GIBBERISH', '0') == '1'
        except Exception:
            pass

        for s in strings:
            value = str(s['value'])
            # Allow shorter single-token strings down to length 8
            if len(value) < 8:
                continue
            if value.isupper():  # skip pure uppercase (module names / constants)
                continue
            if any(c.isdigit() for c in value):  # skip if numeric heavy
                digit_ratio = sum(1 for c in value if c.isdigit()) / len(value)
                if digit_ratio > 0.1:
                    continue
            tokens = [t for t in re.split(r'[^a-zA-Z]+', value) if t]
            if not tokens:
                continue
            english_hits = sum(1 for t in tokens if t.lower() in english_small)
            english_ratio = english_hits / len(tokens)
            # For short single-token candidate we require zero dictionary hits
            # For longer/multi-token allow small ratio (<0.2)
            # Character diversity
            unique_chars = len(set(value))
            if unique_chars < 6:
                continue
            # Alternation score: proportion of adjacency changes vowel<->consonant per token aggregated
            def alternation_score(tok: str) -> float:
                pairs = sum(1 for i in range(len(tok)-1) if (tok[i].lower() in vowels) != (tok[i+1].lower() in vowels))
                return pairs / max(1, len(tok)-1)
            alt_scores = [alternation_score(t) for t in tokens if len(t) >= 4]
            # Single-token vs multi-token handling
            accepted = False
            reason = ''
            if len(tokens) == 1:
                tok = tokens[0]
                alt = alternation_score(tok)
                vprop = sum(1 for c in tok.lower() if c in vowels) / len(tok)
                bigrams = [tok[i:i+2].lower() for i in range(len(tok)-1)]
                uniq_bi = len(set(bigrams))
                if len(tok) >= 12:
                    # Long single-token: original heuristic (slightly tightened)
                    if english_ratio >= 0.2:
                        reason = 'long-single english_ratio'
                    elif alt < 0.55 or not (0.28 <= vprop <= 0.72) or uniq_bi < max(5, len(bigrams)//6):
                        # Fallback: syllable-run regex rescue
                        if syllable_run_re.search(tok):
                            accepted = True
                            reason = 'long-single syllable-run fallback'
                        else:
                            reason = 'long-single thresholds'
                    else:
                        accepted = True
                else:
                    # Short single-token 8..11
                    if english_ratio > 0:  # require zero dictionary hits
                        reason = 'short-single english'
                    elif alt < 0.65:
                        reason = 'short-single alt'
                    elif not (0.35 <= vprop <= 0.65):
                        reason = 'short-single vprop'
                    elif uniq_bi < max(5, len(bigrams)//2):
                        # Fallback for repeated-syllable short tokens
                        if syllable_run_re.search(tok):
                            accepted = True
                            reason = 'short-single syllable-run fallback'
                        else:
                            reason = 'short-single bigram'
                    else:
                        accepted = True
            else:
                if not alt_scores:
                    reason = 'multi no alt_scores'
                else:
                    avg_alt = sum(alt_scores) / len(alt_scores)
                    if english_ratio >= 0.2 or avg_alt < 0.5:
                        # Multi-token fallback: check concatenated syllable sequence
                        concat = ''.join(tokens)
                        if english_ratio < 0.25 and syllable_run_re.search(concat):
                            accepted = True
                            reason = 'multi syllable-run fallback'
                        else:
                            reason = 'multi thresholds'
                    else:
                        accepted = True
            # Avoid duplicates already included by other methods
            if s.get('address') in seen_addrs:
                continue
            seen_addrs.add(s.get('address'))
            if accepted:
                ret.append(value)
            elif debug:
                print(f"[Sharingan Gibberish DEBUG] Rejected '{value}' : {reason}")
        return ret

    # ------------------------------------------------------------------
    # Merge results
    # ------------------------------------------------------------------
    def merge_results(self, *result_lists):
        """Merge and deduplicate results by string value"""
        merged = {}

        for result in result_lists:
            for item in result:
                value = item['value']
                if not value:
                    continue

                if value in merged:
                    # Already exists, merge xrefs and addresses
                    existing_xrefs = set(merged[value]['xrefs'])
                    new_xrefs = set(item.get('xrefs', []))
                    merged[value]['xrefs'] = list(existing_xrefs | new_xrefs)
                    merged[value]['xref_count'] = len(merged[value]['xrefs'])
                    
                    # Track all addresses where this string appears
                    if 'addresses' not in merged[value]:
                        merged[value]['addresses'] = [merged[value]['address']]
                    if item.get('address') and item['address'] not in merged[value]['addresses']:
                        merged[value]['addresses'].append(item['address'])
                else:
                    merged[value] = item.copy()
                    merged[value]['addresses'] = [item.get('address', 0)]

        # Sort by xref count (most used first)
        ret = list(merged.values())
        ret.sort(key=lambda x: x.get('xref_count', 0), reverse=True)
        return ret
