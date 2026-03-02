import re

from django import template

register = template.Library()

HEX_COLOR_RE = re.compile(r"^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$")


@register.filter(name="safe_brand_color")
def safe_brand_color(value: str) -> str | None:
    """Return the color if it is a strict hex color, otherwise ``None``.

    Only ``#RGB`` and ``#RRGGBB`` patterns are accepted so that the
    value is safe to inject into a ``<style>`` block without risk of
    CSS injection.
    """
    if not isinstance(value, str):
        return None
    value = value.strip()
    if HEX_COLOR_RE.match(value):
        return value.lower()
    return None
