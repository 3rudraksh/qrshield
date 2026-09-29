from flask import Flask, render_template, request, send_file

from analyzer import analyze_url, export_security_report

import cv2
import os
import uuid
import json
from datetime import datetime


app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
MAX_UPLOAD_SIZE = 5 * 1024 * 1024
ALLOWED_EXTENSIONS = {".png", ".jpg", ".jpeg"}

HISTORY_FILE = "scan_history.json"
MAX_HISTORY = 20

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


def save_scan_history(result):
    """
    Save a successful scan's essential metadata.
    QR image files are not stored.
    """

    if not isinstance(result, dict):
        return

    history = []

    if os.path.exists(HISTORY_FILE):

        try:

            with open(
                HISTORY_FILE,
                "r",
                encoding="utf-8"
            ) as file:

                history = json.load(file)

                if not isinstance(history, list):
                    history = []

        except (json.JSONDecodeError, OSError):

            history = []

    history.insert(
        0,
        {
            "timestamp": datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            "content": result.get("url"),
            "content_type": result.get("content_type"),
            "risk": result.get("risk"),
            "score": result.get("score")
        }
    )

    history = history[:MAX_HISTORY]

    with open(
        HISTORY_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            history,
            file,
            indent=4,
            ensure_ascii=False
        )

@app.route("/dashboard", methods=["GET"])
def dashboard():

    history = []

    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, "r", encoding="utf-8") as file:
                history = json.load(file)

            if not isinstance(history, list):
                history = []

        except (json.JSONDecodeError, OSError):
            history = []

    total_scans = len(history)

    low_risk = sum(
        1 for scan in history
        if scan.get("risk") == "LOW RISK"
    )

    caution = sum(
        1 for scan in history
        if scan.get("risk") == "CAUTION"
    )

    high_risk = sum(
        1 for scan in history
        if scan.get("risk") == "HIGH RISK"
    )

    scores = [
        scan.get("score")
        for scan in history
        if isinstance(scan.get("score"), (int, float))
    ]

    average_score = (
        round(sum(scores) / len(scores), 2)
        if scores
        else 0
    )
    today = datetime.now().date()

    scans_today = 0
    scans_last_7_days = 0

    for scan in history:

        try:
            scan_date = datetime.strptime(
                scan.get("timestamp", ""),
                "%Y-%m-%d %H:%M:%S"
            ).date()

            days_old = (today - scan_date).days

            if days_old == 0:
                scans_today += 1

            if 0 <= days_old < 7:
                scans_last_7_days += 1

        except (TypeError, ValueError):
            continue

    content_types = {}

    for scan in history:

        content_type = scan.get(
            "content_type",
            "UNKNOWN"
        )

        content_types[content_type] = (
            content_types.get(content_type, 0) + 1
        )

    most_common_content_type = (
        max(
            content_types,
            key=content_types.get
        )
        if content_types
        else "N/A"
    )

    highest_score = max(
        scores
    ) if scores else 0

    return render_template(
        "dashboard.html",
        history=history,
        total_scans=total_scans,
        low_risk=low_risk,
        caution=caution,
        high_risk=high_risk,
        average_score=average_score,
        scans_today=scans_today,
        scans_last_7_days=scans_last_7_days,
        most_common_content_type=most_common_content_type,
        highest_score=highest_score
    )


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

            save_scan_history(result)


        # ----------------------------------------------
        # QR image input
        # ----------------------------------------------

        qr_file = request.files.get("qr_image")

        if qr_file and qr_file.filename:

            original_filename = qr_file.filename

            extension = os.path.splitext(
                original_filename
            )[1].lower()

            if extension not in ALLOWED_EXTENSIONS:

                error = (
                    "Invalid image type. Please upload "
                    "a PNG, JPG, or JPEG image."
                )

            else:

                qr_file.seek(0, os.SEEK_END)

                file_size = qr_file.tell()

                qr_file.seek(0)

                if file_size > MAX_UPLOAD_SIZE:

                    error = (
                        "Image is too large. "
                        "Maximum allowed size is 5 MB."
                    )

                elif file_size == 0:

                    error = (
                        "The uploaded image is empty."
                    )

                else:

                    filename = (
                        str(uuid.uuid4()) + extension
                    )

                    filepath = os.path.join(
                        UPLOAD_FOLDER,
                        filename
                    )

                    qr_file.save(filepath)

                    image = cv2.imread(filepath)

                    if image is None:

                        error = (
                            "The uploaded file is not a valid "
                            "readable image."
                        )

                        os.remove(filepath)

                    else:

                        image_quality = (
                            analyze_image_quality(image)
                        )

                        try:

                            decoded_codes = (
                                decode_qr_with_preprocessing(
                                    image
                                )
                            )

                            if len(decoded_codes) > 1:

                                error = (
                                    f"Multiple QR codes detected "
                                    f"({len(decoded_codes)}). "
                                    "Please upload an image "
                                    "containing one QR code "
                                    "at a time."
                                )

                            elif len(decoded_codes) == 1:

                                result = analyze_url(
                                    decoded_codes[0]
                                )

                                save_scan_history(result)

                            else:

                                if (
                                    image_quality["quality"]
                                    == "LOW"
                                ):

                                    error = (
                                        "No readable QR code "
                                        "was detected. Image "
                                        "quality may be affecting "
                                        "QR decoding."
                                    )

                                else:

                                    error = (
                                        "No readable QR code "
                                        "was detected in the "
                                        "uploaded image."
                                    )

                        except cv2.error:

                            error = (
                                "QR decoding failed because "
                                "the image could not be processed."
                            )

                        except Exception:

                            error = (
                                "An unexpected error occurred "
                                "while processing the QR code."
                            )

                        finally:

                            if os.path.exists(filepath):

                                os.remove(filepath)

    # ----------------------------------------------
    # Load scan history
    # ----------------------------------------------

    history = []

    if os.path.exists(HISTORY_FILE):

        try:

            with open(
                HISTORY_FILE,
                "r",
                encoding="utf-8"
            ) as file:

                history = json.load(file)

                if not isinstance(history, list):
                    history = []

        except (json.JSONDecodeError, OSError):

            history = []

    return render_template(
        "index.html",
        result=result,
        error=error,
        history=history
    )

@app.route("/export-report", methods=["POST"])
def export_report():

    content = request.form.get("content", "").strip()

    if not content:
        return "No analysis result available.", 400

    result = analyze_url(content)

    filepath = "qrshield_security_report.json"

    export_security_report(
        result,
        filepath
    )

    return send_file(
        filepath,
        as_attachment=True,
        download_name="qrshield_security_report.json",
        mimetype="application/json"
    )

if __name__ == "__main__":
    app.run(debug=False)