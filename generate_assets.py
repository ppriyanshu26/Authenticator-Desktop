from PIL import Image
import os

def generate_store_assets(ico_path, output_folder):
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)
    
    try:
        img = Image.open(ico_path)
        # Ensure we have the highest quality version from the ico
        img = img.convert("RGBA")
        
        assets = {
            "Square150x150Logo.png": (150, 150),
            "Square44x44Logo.png": (44, 44),
            "StoreLogo.png": (50, 50),
            "Wide310x150Logo.png": (310, 150),
            "LargeTile.png": (310, 310)
        }
        
        for name, size in assets.items():
            # For Wide logo, we might want to pad instead of stretch, 
            # but for a simple icon, centering on a transparent background is usually best.
            new_img = Image.new("RGBA", size, (0, 0, 0, 0))
            
            # Resize original to fit the smaller dimension
            scale = min(size) / max(img.size)
            resized_size = (int(img.size[0] * scale), int(img.size[1] * scale))
            resized_icon = img.resize(resized_size, Image.Resampling.LANCZOS)
            
            # Paste in center
            offset = ((size[0] - resized_size[0]) // 2, (size[1] - resized_size[1]) // 2)
            new_img.paste(resized_icon, offset)
            
            new_img.save(os.path.join(output_folder, name))
            print(f"Created {name}")
            
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    # Using the path to your icon
    generate_store_assets("Python/icon.ico", "dist/auth_folder/Authenticator/Assets")
