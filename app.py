from flask import Flask, render_template, request
from analyzer import analyze_url
import cv2
import os
import uuid


app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


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

            filename = str(uuid.uuid4()) + ".png"
            filepath = os.path.join(UPLOAD_FOLDER, filename)

            qr_file.save(filepath)

            image = cv2.imread(filepath)

            detector = cv2.QRCodeDetector()

            decoded_text, points, _ = detector.detectAndDecode(image)

            os.remove(filepath)

            if decoded_text:
                result = analyze_url(decoded_text)
            else:
                error = "QR code could not be decoded."

    return render_template(
        "index.html",
        result=result,
        error=error
    )


if __name__ == "__main__":
    app.run(debug=True)