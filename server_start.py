from flask import Flask, request, render_template
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

app = Flask(__name__, static_url_path='/static')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze_rsa', methods=['GET', 'POST'])
def analyze_rsa():
    key_details = None
    if request.method == 'POST':
        file = request.files['file']
        if file:
            private_key = serialization.load_pem_private_key(
                file.read(),
                password=None,
                backend=default_backend()
            )
            key_details = analyze_rsa_key(private_key)
    return render_template('analyze_rsa.html', key_details=key_details)

@app.route('/frequency_analysis', methods=['GET', 'POST'])
def frequency_analysis():
    frequency_analysis_result = None
    if request.method == 'POST':
        file = request.files['file']
        if file:
            text_content = file.read().decode('utf-8')
            frequency_analysis_result = perform_frequency_analysis(text_content)
    return render_template('frequency_analysis.html', frequency_analysis=frequency_analysis_result)

@app.route('/caesar_brute_force', methods=['GET', 'POST'])
def caesar_brute_force():
    brute_forced_results = None
    if request.method == 'POST':
        text = request.form['text']
        results = brute_force_caesar(text)
        brute_forced_results = list(enumerate(results))
    return render_template('caesar_brute_force.html', brute_forced_results=brute_forced_results)


def analyze_rsa_key(key):
    key_size = key.key_size
    public_key = key.public_key()
    public_numbers = public_key.public_numbers()
    public_exponent = public_numbers.e
    modulus = public_numbers.n
    return f'''<h2>Key Information:</h2>
               <p>Key Size: {key_size}</p>
               <p>Public Exponent: {public_exponent}</p>
               <p>Modulus: {modulus}</p>'''

def perform_frequency_analysis(text):
    frequency = {}
    for letter in text:
        if letter.isalpha():
            letter = letter.lower()
            if letter in frequency:
                frequency[letter] += 1
            else:
                frequency[letter] = 1

    return {k: v for k, v in sorted(frequency.items(), key=lambda item: item[1], reverse=True)}

def brute_force_caesar(cipher_text):
    results = []
    for shift in range(26):
        plain_text = ''
        for char in cipher_text:
            if char.isalpha():
                shifted = ord(char) - shift
                if char.islower():
                    if shifted < ord('a'):
                        shifted += 26
                elif char.isupper():
                    if shifted < ord('A'):
                        shifted += 26
                plain_text += chr(shifted)
            else:
                plain_text += char
        results.append(plain_text)
    return results

if __name__ == '__main__':
    app.run(debug=True)
