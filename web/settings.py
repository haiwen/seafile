
DEBUG = False

DEFAULT_HELP_WEB = "http://seafile.com/help/"
DEFAULT_HELP_WEB_EN = "http://seafile.com/en/help/"

SHOW_SYSTEM = False
SHOW_INTERNAL = False

try:
    import local_settings
except ImportError:
    pass
else:
  # Import any symbols that begin with A-Z. Append to lists any symbols that
  # begin with "EXTRA_".
    import re
    for attr in dir(local_settings):
        match = re.search('^EXTRA_(\w+)', attr)
        if match:
            name = match.group(1)
            value = getattr(local_settings, attr)
            try:
                globals()[name] += value
            except KeyError:
                globals()[name] = value
        elif re.search('^[A-Z]', attr):
            globals()[attr] = getattr(local_settings, attr)
