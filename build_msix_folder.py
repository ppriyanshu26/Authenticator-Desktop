import os
import subprocess
import shutil

def run_command(cmd):
    print(f"Running: {' '.join(cmd)}")
    subprocess.run(cmd, check=True)

# 1. Run PyInstaller
run_command(["pyinstaller", "--noconfirm", "CipherAuth.spec"])

# 2. Ensure Assets exist
run_command(["python", "generate_assets.py", "Assets"])

# 3. Prepare MSIX folder
msix_folder = r"i:\Projects\Authenticator\dist\auth_folder\CipherAuth"
if os.path.exists(msix_folder):
    shutil.rmtree(msix_folder)
os.makedirs(msix_folder)

# Copy build artifacts from dist/CipherAuth to dist/auth_folder/CipherAuth
build_output = r"i:\Projects\Authenticator\dist\CipherAuth"
for item in os.listdir(build_output):
    s = os.path.join(build_output, item)
    d = os.path.join(msix_folder, item)
    if os.path.isdir(s):
        shutil.copytree(s, d)
    else:
        shutil.copy2(s, d)

# Copy Assets and Manifest
shutil.copytree(r"i:\Projects\Authenticator\Assets", os.path.join(msix_folder, "Assets"))
shutil.copy2(r"i:\Projects\Authenticator\AppxManifest.xml", os.path.join(msix_folder, "AppxManifest.xml"))

print("\nBuild complete! MSIX folder is ready at:")
print(msix_folder)
