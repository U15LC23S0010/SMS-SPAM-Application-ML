import cv2
import os

source_image = r'C:\Users\Lenovo\.gemini\antigravity\brain\39d7fc86-b19c-433f-9bc7-1f7f0e07baa8\message_guardian_logo_1776783986374.png'
dest_dir = 'static'

if os.path.exists(source_image):
    img = cv2.imread(source_image, cv2.IMREAD_UNCHANGED)
    if img is not None:
        # Resize to 512x512
        icon_512 = cv2.resize(img, (512, 512), interpolation=cv2.INTER_AREA)
        cv2.imwrite(os.path.join(dest_dir, 'icon-512x512.png'), icon_512)
        
        # Resize to 192x192
        icon_192 = cv2.resize(img, (192, 192), interpolation=cv2.INTER_AREA)
        cv2.imwrite(os.path.join(dest_dir, 'icon-192x192.png'), icon_192)
        
        print("Icons updated successfully with the new premium logo.")
    else:
        print("Error: Could not read source image.")
else:
    print(f"Error: Source image not found at {source_image}")
