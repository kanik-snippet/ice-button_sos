from modeltranslation.translator import register, TranslationOptions
from .models import StaticContent

@register(StaticContent)
class StaticContentTranslationOptions(TranslationOptions):
    fields = ('title', 'body', 'meta_title', 'meta_description')
