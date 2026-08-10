from flask import Flask
app = Flask(__name__)
DEBUG = False
if __name__ == "__main__":
    app.run(debug=False)
