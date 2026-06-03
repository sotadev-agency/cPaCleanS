"""Genera el icono de la aplicación (icon.ico) usando Pillow."""
from PIL import Image, ImageDraw, ImageFont
from pathlib import Path

SIZE = 256
OUTPUT = Path(__file__).parent / "assets" / "icon.ico"


def create_icon():
    img = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Fondo circular con gradiente simulado
    for i in range(128, 0, -1):
        r = int(10 + (26 - 10) * (i / 128))
        g = int(10 + (33 - 10) * (i / 128))
        b = int(30 + (62 - 30) * (i / 128))
        offset = 128 - i
        draw.ellipse([offset, offset, SIZE - offset, SIZE - offset], fill=(r, g, b, 255))

    # Escudo
    shield_points = [
        (128, 30),
        (210, 65),
        (210, 140),
        (128, 220),
        (46, 140),
        (46, 65),
    ]
    draw.polygon(shield_points, fill=(0, 212, 255, 200), outline=(0, 180, 220, 255))

    # Check mark
    check_points = [
        (85, 130),
        (115, 165),
        (175, 90),
    ]
    draw.line(check_points, fill=(255, 255, 255, 255), width=12, joint="curve")

    sizes = [(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
    imgs = [img.resize(s, Image.LANCZOS) for s in sizes]

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    imgs[0].save(str(OUTPUT), format="ICO", sizes=sizes, append_images=imgs[1:])
    print(f"Icono creado: {OUTPUT}")


if __name__ == "__main__":
    create_icon()
