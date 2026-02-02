import json
import os
import locale
import logging

logger = logging.getLogger(__name__)

class Translator:
    def __init__(self, lang_dir, default_lang="de"):
        self.lang_dir = lang_dir
        self.default_lang = default_lang
        self.current_lang = default_lang
        self.translations = {}
        self.load_translations()

    def load_translations(self):
        try:
            # Detect system language if not set (optional, here we stick to default or config)
            # sys_lang = locale.getdefaultlocale()[0]
            # if sys_lang and "en" in sys_lang.lower(): self.current_lang = "en"
            
            lang_file = os.path.join(self.lang_dir, f"lang_{self.current_lang}.json")
            if not os.path.exists(lang_file):
                # Fallback to English if German not found, or vice versa
                fallback = "en" if self.current_lang == "de" else "de"
                lang_file = os.path.join(self.lang_dir, f"lang_{fallback}.json")

            if os.path.exists(lang_file):
                with open(lang_file, "r", encoding="utf-8") as f:
                    self.translations = json.load(f)
            else:
                logger.warning(f"Keine Sprachdatei gefunden: {lang_file}")
                self.translations = {}
        except Exception as e:
            logger.error(f"Fehler beim Laden der Übersetzungen: {e}")
            self.translations = {}

    def set_language(self, lang):
        self.current_lang = lang
        self.load_translations()

    def tr(self, key, default_text, **kwargs):
        val = self.translations.get(key, default_text)
        if kwargs:
            try:
                return val.format(**kwargs)
            except:
                return val
        return val

# Global instance
_translator = None

def init_translator(base_dir):
    global _translator
    lang_dir = os.path.join(base_dir, "i18n")
    _translator = Translator(lang_dir)

def tr(key, default_text, **kwargs):
    if _translator:
        return _translator.tr(key, default_text, **kwargs)
    return default_text.format(**kwargs) if kwargs else default_text

def set_lang(lang):
    if _translator:
        _translator.set_language(lang)

def get_translation_dict(lang):
    """
    Returns the raw translation dictionary for the given language code.
    Used by the frontend to load translations dynamically.
    """
    if not _translator:
        return {}
    
    # Construct path manually to avoid changing global state
    lang_file = os.path.join(_translator.lang_dir, f"lang_{lang}.json")
    if not os.path.exists(lang_file):
         # Fallback
         fallback = "en" if lang == "de" else "de"
         lang_file = os.path.join(_translator.lang_dir, f"lang_{fallback}.json")
    
    if os.path.exists(lang_file):
        try:
            with open(lang_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error loading dict for {lang}: {e}")
            return {}
    return {}
