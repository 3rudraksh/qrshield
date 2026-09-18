import qrcode

safe_url = "https://example.com/campus-registration"

phishing_demo_url = (
    "http://kmclu-account-verify.example/"
    "urgent/login/password"
)

campus_demo_url = (
    "http://kmclu-scholarship-verify.example/"
    "urgent/account/verification"
)

campus_qr = qrcode.make(campus_demo_url)
campus_qr.save("demo_qr/campus_phishing_demo.png")

qrcode.make(safe_url).save(
    "demo_qr/campus_safe.png"
)

qrcode.make(phishing_demo_url).save(
    "demo_qr/campus_phishing_demo.png"
)

print("Campus demonstration QR codes created.")