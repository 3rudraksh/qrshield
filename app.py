from flask import Flask, render_template, request
from analyzer import analyze_url
import cv2
import os
import uuid


app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
MAX_UPLOAD_SIZE = 5 * 1024 * 1024
ALLOWED_EXTENSIONS = {".png", ".jpg", ".jpeg"}

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def decode_qr_with_preprocessing(image):
    """
    Try QR decoding on the original image and a few
    useful preprocessing/rotation variants.
    """

    detector = cv2.QRCodeDetector()
    images = [
        image,
        cv2.cvtColor(image, cv2.COLOR_BGR2GRAY),
        cv2.rotate(image, cv2.ROTATE_90_CLOCKWISE),
        cv2.rotate(image, cv2.ROTATE_90_COUNTERCLOCKWISE)
    ]

    decoded_codes = []

    for candidate in images:

        multi_found, decoded_info, points, _ = (
            detector.detectAndDecodeMulti(candidate)
        )

        if multi_found and decoded_info:

            for text in decoded_info:

                if text and text.strip():
                    cleaned = text.strip()

                    if cleaned not in decoded_codes:
                        decoded_codes.append(cleaned)

        else:

            decoded_text, points, _ = (
                detector.detectAndDecode(candidate)
            )

            if decoded_text and decoded_text.strip():

                cleaned = decoded_text.strip()

                if cleaned not in decoded_codes:
                    decoded_codes.append(cleaned)

    return decoded_codes

def analyze_image_quality(image):
    """
    Analyze basic image properties that can affect QR decoding.
    """

    if image is None:
        return {
            "valid": False,
            "width": 0,
            "height": 0,
            "brightness": None,
            "contrast": None,
            "quality": "INVALID"
        }

    height, width = image.shape[:2]

    gray = cv2.cvtColor(
        image,
        cv2.COLOR_BGR2GRAY
    )

    brightness = float(gray.mean())
    contrast = float(gray.std())

    if width < 200 or height < 200:
        quality = "LOW"

    elif brightness < 40 or brightness > 215:
        quality = "LOW"

    elif contrast < 25:
        quality = "LOW"

    else:
        quality = "GOOD"

    return {
        "valid": True,
        "width": width,
        "height": height,
        "brightness": round(brightness, 2),
        "contrast": round(contrast, 2),
        "quality": quality
    }



@app.route("/", methods=["GET", "POST"])
def index():

    result = None
    error = None

    if request.method == "POST":

        # ----------------------------------------------
        # URL input
        # ----------------------------------------------

        url = request.form.get("url", "").strip()

        if url:
            result = analyze_url(url)

        # ----------------------------------------------
        # QR image input
        # ----------------------------------------------

    qr_file = request.files.get("qr_image")

    if qr_file and qr_file.filename:
        original_filename = qr_file.filename
        extension = os.path.splitext(original_filename)[1].lower()

        if extension not in ALLOWED_EXTENSIONS:
            error = "Invalid image type. Please upload a PNG, JPG, or JPEG image."

        else:
            qr_file.seek(0, os.SEEK_END)
            file_size = qr_file.tell()
            qr_file.seek(0)

            if file_size > MAX_UPLOAD_SIZE:
                error = "Image is too large. Maximum allowed size is 5 MB."

            elif file_size == 0:
                error = "The uploaded image is empty."

            else:
                filename = str(uuid.uuid4()) + extension
                filepath = os.path.join(UPLOAD_FOLDER, filename)

                qr_file.save(filepath)

                image = cv2.imread(filepath)

                if image is None:

                    error = (
                        "The uploaded file is not a valid "
                        "readable image."
                    )

                    os.remove(filepath)

                else:

                    image_quality = analyze_image_quality(image)

                    try:

                        decoded_codes = decode_qr_with_preprocessing(image)

                        if len(decoded_codes) > 1:

                            error = (
                                f"Multiple QR codes detected ({len(decoded_codes)}). "
                                "Please upload an image containing one QR code at a time."
                            )

                        elif len(decoded_codes) == 1:

                            result = analyze_url(
                                decoded_codes[0]
                            )

                        else:

                            if image_quality["quality"] == "LOW":

                                error = (
                                    "No readable QR code was detected. "
                                    "Image quality may be affecting QR decoding."
                                )

                            else:

                                error = (
                                    "No readable QR code was detected "
                                    "in the uploaded image."
                                )
                    except cv2.error:

                        error = (
                            "QR decoding failed because the image "
                            "could not be processed."
                        )

                    except Exception:

                        error = (
                            "An unexpected error occurred while "
                            "processing the QR code."
                        )

                    finally:

                        if os.path.exists(filepath):
                            os.remove(filepath)

    return render_template(
        "index.html",
        result=result,
        error=error
    )


if __name__ == "__main__":
    app.run(debug=True)