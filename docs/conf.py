# -*- coding: utf-8 -*-

# Project info
project = 'SSPI Library'
copyright = '2022, Evan McBroom'
author = 'Evan McBroom'

# General config
needs_sphinx = '4.5'
extensions = [
    'breathe',
    'sphinx_sitemap'
]
exclude_patterns = [
    'builds/*'
]
primary_domain = 'cpp'
highlight_language = 'cpp'

# Breath config
# The breathe_projects config will be overridden by CMake
breathe_projects = {
    'SspiLibrary': ''
}
breathe_default_project = 'SspiLibrary'
breathe_default_members = ('members', 'undoc-members')

# HTLM output config
html_theme = 'sphinx_rtd_theme'
pygments_style = 'sphinx'

# Site map config
html_baseurl = 'https://evanmcbroom.github.io/lsa-whisperer/'