# -*- mode: python ; coding: utf-8 -*-
import os
from pathlib import Path

# Create output directories if they don't exist
Path('dist/deploy-gen').mkdir(parents=True, exist_ok=True)

block_cipher = None

# Add data files that should be included in the binary
added_files = [
    ('README.md', '.'),
    ('deploy-sample.yml', '.'),
    # Add any other files that need to be included
]

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=added_files,
    hiddenimports=[
        'typer',
        'requests',
        'cryptography',
        'yaml',
        'json',
        'pathlib',
        'base64',
        'enum',
        'io',
        'contextlib',
        're',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(
    a.pure, 
    a.zipped_data,
    cipher=block_cipher
)

# Create a directory-based distribution (all files separate)
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='deploy-gen',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='deploy-gen',
)

# Create a single-file executable (everything bundled into one file)
exe_onefile = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='deploy-gen-onefile',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
) 