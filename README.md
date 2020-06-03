programming:

python3 -m venv env
source env/bin/activate

You should now see you (env) to the left of the prompt in the terminal, indicating that you are now working in a virtual environment.

To add deps: python3 -m pip install pyjks==20.0.0

To free requirements to requirements.txt

python3 -m pip freeze > requirements.txt


to load all deps from requirements.txt
pip3 install -r requirements.txt


to run:
python3 app.py  --keystore test/resources/certs/server.jks --keystorePassphrase password --keystoreAlias server --keyPass password --hostAndPort encrypted.google.com:443



to build with pyinstaller
env/bin/pyinstaller --onefile --paths env/lib/python3.6/site-packages --paths env/lib64/python3.6/site-packages  app.py