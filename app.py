from flask import Flask, render_template, request
from flask_wtf import FlaskForm
from wtforms.validators import ValidationError, DataRequired
from wtforms import TextAreaField, StringField, SelectField
from cryptography.fernet import Fernet
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from base64 import b64decode
import json

app = Flask(__name__)
app.config["SECRET_KEY"] = 'secret'

questions = []

for i in range(1, 16):
    tmp = f"c/c++ {i}"
    tmp = tuple((tmp, tmp))
    questions.append(tmp)

for i in range(1, 13):
    tmp = f"python {i}"
    tmp = tuple((tmp, tmp))
    questions.append(tmp)


class EncryptionForm(FlaskForm):
    team_name = StringField(
        validators=[DataRequired()],
        label="Team name",
        render_kw={"placeholder": "Team Name"},
    )
    file_name = SelectField(
        choices=questions,
        label="File Name",
        render_kw={"placeholder": "File Name"},
    )
    line_number = StringField(
        label="Line Number",
        validators=[DataRequired()],
        render_kw={"placeholder": "Line Number"},
    )
    bug_description = TextAreaField(
        label="Bug Description",
        validators=[DataRequired()],
        render_kw={"placeholder": "Bug Description"},
    )
    solution = TextAreaField(
        label="Solution",
        render_kw={"placeholder": "Solution"},
    )

    def validate_line_number(form, field):
        if not field.data:
            return
        field.data = field.data.strip("' ")
        values = map(str.strip, field.data.split(','))
        for value in values:
            if '-' in value:
                start, end = value.split('-')
                if not start.isdigit() or not end.isdigit():
                    raise ValidationError("Invalid line numbers. Valid-Format: '3' or '2-5' or '1,7-9,14'")
                if int(start) >= int(end):
                    raise ValidationError("Start value must be less than end value")
            else:
                if not value.isdigit():
                    raise ValidationError("Invalid line numbers. Valid-Format: '3' or '2-5' or '1,7-9,14'")

    class Meta:
        csrf = False


def generate_range(string):
    string = string.strip("' ")
    values = map(str.strip, string.split(','))
    result = set()
    for value in values:
        if '-' in value:
            start, end = value.split('-')
            result.update(range(int(start), int(end)+1))
        else:
            result.add(int(value))
    return list(result)


@app.route('/', methods=['GET', 'POST'])
def index():
    form = EncryptionForm()
    if request.method == 'GET':
        return render_template('index.html', form=form)
    if form.validate_on_submit():
        result = request.form.to_dict()
        result['line_number'] = generate_range(result['line_number'])
        print("Form is submitted\n", result)

        message = json.dumps(result)
        key = Fernet.generate_key()
        fernet = Fernet(key)

        encMessage = fernet.encrypt(message.encode())

        message = key

        public_key = "MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgHxNtDIfEwU/LbyQDqMUwBSPki6dp2XqwodefXxi0twOirtiZw6oB7W2caRyjBOd9KTHlTUPkb1LymprgP7kauGrXDYNP5KthWiSWfMt1mlvsWfR2Bpy9remlwuumBU7CuF7iK6X3v8FKpQuYaOLMpe4UzmUvRn7xmQ6vRMcMKyPAgMBAAE="
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
