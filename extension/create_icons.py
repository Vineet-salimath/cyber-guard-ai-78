from PIL import Image, ImageDraw, ImageFont
import os

# Create icons directory if it doesn't exist
icons_dir = os.path.join(os.path.dirname(__file__), 'icons')
os.makedirs(icons_dir, exist_ok=True)

def create_icon(size):
    # Create image with gradient background
    img = Image.new('RGB', (size, size), color='white')
    draw = ImageDraw.Draw(img)
    
    # Draw gradient-like background (purple gradient)
    for y in range(size):
        r = int(102 + (118 - 102) * y / size)  # 667eea to 764ba2
        g = int(126 + (75 - 126) * y / size)
        b = int(234 + (162 - 234) * y / size)
        draw.line([(0, y), (size, y)], fill=(r, g, b))
    
    # Draw shield shape
    center_x = size // 2
    center_y = size // 2
    shield_width = int(size * 0.6)
    shield_height = int(size * 0.7)
    
    shield_points = [
        (center_x, center_y - shield_height//2),
        (center_x + shield_width//2, center_y - shield_height//4),
        (center_x + shield_width//2, center_y + shield_height//4),
        (center_x, center_y + shield_height//2),
        (center_x - shield_width//2, center_y + shield_height//4),
        (center_x - shield_width//2, center_y - shield_height//4),
    ]
    
    draw.polygon(shield_points, fill='white', outline='white')
    
    # Add checkmark or text
    if size >= 48:
        # Draw "MS" text
        try:
            font_size = size // 4
            font = ImageFont.truetype("arial.ttf", font_size)
        except:
            font = ImageFont.load_default()
        
        text = "MS"
        bbox = draw.textbbox((0, 0), text, font=font)
        text_width = bbox[2] - bbox[0]
        text_height = bbox[3] - bbox[1]
        text_x = center_x - text_width // 2
        text_y = center_y - text_height // 2
        draw.text((text_x, text_y), text, fill=(102, 126, 234), font=font)
    else:
        # Draw checkmark for 16x16
        check_color = (102, 126, 234)
        draw.line([(center_x - 2, center_y), (center_x, center_y + 2)], fill=check_color, width=2)
        draw.line([(center_x, center_y + 2), (center_x + 3, center_y - 3)], fill=check_color, width=2)
    
    # Save the icon
    icon_path = os.path.join(icons_dir, f'icon{size}.png')
    img.save(icon_path, 'PNG')
    print(f"✓ Created {icon_path}")

# Generate all three icon sizes
print("🔥 MALWARE SNIPPER - Icon Generator")
print("=" * 50)
create_icon(16)
create_icon(48)
create_icon(128)
print("=" * 50)
print("✓ All icons generated successfully!")
print(f"Icons saved in: {icons_dir}")
