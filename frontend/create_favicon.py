#!/usr/bin/env python3
"""
Create favicon.ico from MalwareSnipper logo
"""
try:
    from PIL import Image, ImageDraw
    import io
    
    # Create favicon image with dark blue gradient background
    size = 256
    img = Image.new('RGBA', (size, size), (0, 31, 63, 255))  # Dark blue background
    draw = ImageDraw.Draw(img)
    
    # Define colors matching our logo
    blue1 = (59, 130, 246, 255)    # #3b82f6
    blue2 = (30, 64, 175, 255)     # #1e40af
    blue3 = (12, 74, 110, 255)     # #0c4a6e
    
    # Draw shield
    shield_left = 80
    shield_top = 60
    shield_right = 176
    shield_bottom = 200
    
    # Outer shield
    points = [
        (128, 40),      # top point
        (80, 70),       # left top
        (80, 120),      # left middle
        (128, 160),     # bottom
        (176, 120),     # right middle
        (176, 70),      # right top
    ]
    draw.polygon(points, fill=None, outline=blue1, width=4)
    
    # Inner shield (offset)
    points_inner = [
        (128, 55),
        (95, 80),
        (95, 120),
        (128, 150),
        (161, 120),
        (161, 80),
    ]
    draw.polygon(points_inner, fill=None, outline=blue2, width=3)
    
    # Lock rectangle
    lock_x = 105
    lock_y = 110
    lock_w = 46
    lock_h = 40
    draw.rectangle([lock_x, lock_y, lock_x + lock_w, lock_y + lock_h], 
                   outline=blue1, width=3)
    
    # Lock shackle
    draw.arc([lock_x + 5, lock_y - 20, lock_x + lock_w - 5, lock_y + 10], 
             0, 180, fill=blue1, width=3)
    
    # Lock dot
    draw.ellipse([128 - 3, 130 - 3, 128 + 3, 130 + 3], fill=blue1)
    
    # Add small circuit pattern in corner
    circuit_points = [(200, 220), (210, 220), (210, 230), (220, 230)]
    for i in range(len(circuit_points) - 1):
        draw.line([circuit_points[i], circuit_points[i+1]], fill=blue2, width=2)
    
    # Convert to RGB for ICO format
    rgb_img = Image.new('RGB', (256, 256), (0, 31, 63))
    rgb_img.paste(img, (0, 0), img)
    
    # Save as favicon.ico with multiple sizes
    favicon_sizes = [(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
    ico_images = []
    
    for size in favicon_sizes:
        resized = rgb_img.resize(size, Image.Resampling.LANCZOS)
        ico_images.append(resized)
    
    # Save favicon.ico
    ico_images[0].save(
        'public/favicon.ico',
        format='ICO',
        sizes=favicon_sizes
    )
    
    print("✅ favicon.ico created successfully!")
    print(f"   Sizes: {favicon_sizes}")
    print("   Location: public/favicon.ico")
    
except ImportError:
    print("Installing Pillow...")
    import subprocess
    import sys
    subprocess.check_call([sys.executable, "-m", "pip", "install", "Pillow"])
    print("Pillow installed. Please run this script again.")
except Exception as e:
    print(f"❌ Error creating favicon: {e}")
    print("\nFalling back to simple color-based favicon...")
    
    # Fallback: Create a simple solid-color ICO
    try:
        from PIL import Image
        
        # Create simple blue square favicon
        img = Image.new('RGB', (256, 256), (59, 130, 246))  # #3b82f6
        
        favicon_sizes = [(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
        ico_images = []
        
        for size in favicon_sizes:
            resized = img.resize(size, Image.Resampling.LANCZOS)
            ico_images.append(resized)
        
        ico_images[0].save('public/favicon.ico', format='ICO', sizes=favicon_sizes)
        print("✅ Simple favicon.ico created as fallback")
    except Exception as e2:
        print(f"❌ Fallback also failed: {e2}")
