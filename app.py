from flask import Flask, render_template, request, redirect, url_for, flash
from flask_wtf import FlaskForm
from wtforms.validators import ValidationError, DataRequired
from wtforms import TextAreaField, SubmitField
from cryptography.fernet import Fernet
import rsa
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from base64 import b64decode, b64encode

app = Flask(__name__)
app.config["SECRET_KEY"] = 'secret'

class EncryptionForm(FlaskForm):
    issue = TextAreaField("Issue", render_kw={"rows": 10, "cols": 50}, validators=[DataRequired()], default="Team Name : \nFile Name : \nBug Description : \nSolution : ")

@app.route('/', methods=['GET', 'POST'])
def index():
    form = EncryptionForm()
    if form.is_submitted():
        result = request.form
        print("Form is submitted\n", result['issue'])

        message = result['issue']
        key = Fernet.generate_key()
        fernet = Fernet(key)

        encMessage = fernet.encrypt(message.encode())

        message = key

        public_key = "AAAAB3NzaC1yc2EAAAADAQABAAACAQDNQW+F00fbUlZEBGKUd3q7r08yJ/uf2d4ygD4MDlBNxxzfJChuoZUKlNTydTO314dMBYrgemSs8pnhILwMN41tLEidkrc8+TfSTQnkSO9Q9IkDNPUZBblQTS4b7HU1Q1gEQYy1HXsYRUwqFPQ/XQ4PCLWhmNN0932Lh/5QzPqnGAN0Nw490RRTXd4Dv26pJuLceXHSjG+PfiTPpv2DcC+R6MJDZsTig+kZMXB4yHqn1EIjlIqaeZ7xfRmDb0EakMZXp86zxbxwivHVCiO3zdKV1ze6urhsyjU0HB0hFF+bWDIp+TVyB8yArEUhyL2fmLKgss8zoHQZGOSa+8QMoxDasyaob1Cf2qgKUoSCR3c0HoXFDartRZE9Wc9pgCQlfAGL1Fm51DMDwxi0utwjXtt/+86vnEOMGgSAKVKiBoj03O00InsngazO3bi4XmZlc6WLfvtzMFaYHe4Md7x/7O9yfB+x0l39KtKdx56rpj5zWaES9ApJ4/m9omBoyiHib3PSgDNZZma98z+W5e8Pv1h34c3n7sjoAWjNIH11m4kRFrrjg8oMmMOP6pUAidW7zKiL0sitq+/falh5ftkFkE/raxVkLBcCVfSh3pEZyKoje7Ut6L3I9wiCwDhDO85VuAcHfXVJ4YKocRLuqzPJldtZw6rNSauY8maCZeDpw8Obtw=="
        public_key = b64decode(public_key)
        public_key = RSA.import_key(public_key)
        cipher = PKCS1_OAEP.new(public_key)
        encrypted_key = cipher.encrypt(message)
        print("\n\n")
        print(encrypted_key)
        print("\n\n")
        print(encMessage)

        output = [encrypted_key, encMessage]
        return render_template('result.html', output=output)
    return render_template('index.html', form=form)

if __name__ == "__main__":
    app.run(debug=True)
